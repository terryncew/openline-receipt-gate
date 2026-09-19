"""RECEIVER-ROLLBACK-002: ancestry-closure restart monotonicity.

Frozen test matrix from ~/workspace/receiver-rollback-002/PREREGISTRATION.md.

Durability is opt-in (as in 001). Every test here uses the durable
configuration: a DurableOpLog-backed ReceiverAncestryClosureView paired
with a durable ClosureAwareStandingView. The legacy in-memory default is
unchanged by the repair (guarded by test_legacy_default_still_forgets).

Determinism: fixed Ed25519 seeds, explicit now= timestamps.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate._durable_heads import (
    DurableHeadStore,
    DurableHeadStoreError,
    DurableOpLog,
    DurableOpLogError,
)
from olp_gate.ancestry import (
    ANCESTRY_CLOSURE_VIEW_IDENTITY,
    AncestryClosureError,
    ClosureAwareStandingView,
    ReceiverAncestryClosureView,
    closure_aware_standing_requirement_source,
)
from olp_gate.crypto import public_key_hex, sign_olp_body
from olp_gate.standing import (
    STANDING_PROJECTION_SCHEMA,
    ReceiverStandingView,
    StandingProjectionError,
    support_receipt_hash,
)
from olp_gate.tool_adapter import ToolCallContext

REPO_ROOT = Path(__file__).resolve().parent.parent

ISSUER_ID = "test-issuer"
ISSUED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
EXPIRES_AT = datetime(2030, 1, 1, tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _issuer(seed: int):
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    return key, public_key_hex(key)


def _projection(key, support_hash, action_hash, standing, event_type,
                sequence, predecessor_hash):
    return sign_olp_body(
        {
            "schema": STANDING_PROJECTION_SCHEMA,
            "projection_id": f"{event_type.lower()}:{sequence}",
            "issuer_id": ISSUER_ID,
            "support_hash": support_hash,
            "action_hash": action_hash,
            "standing": standing,
            "event_type": event_type,
            "sequence": sequence,
            "predecessor_hash": predecessor_hash,
            "issued_at": _iso(ISSUED_AT),
            "expires_at": _iso(EXPIRES_AT),
        },
        key,
    )


def _support(label: str):
    return {"artifact": "approval-record", "label": label}


def _identity(trusted):
    return {
        "view": ANCESTRY_CLOSURE_VIEW_IDENTITY,
        "trusted_issuers": dict(trusted),
    }


class Harness:
    """Durable coupled receiver: heads file + ancestry log + views."""

    def __init__(self, tmp_path: Path, seed: int = 0x11):
        self.key, pub = _issuer(seed)
        self.trusted = {ISSUER_ID: pub}
        self.heads_path = str(tmp_path / "heads.json")
        self.log_path = str(tmp_path / "ancestry.json")
        DurableHeadStore.create(
            self.heads_path,
            {"view": "standing/v1", "trusted_issuers": dict(self.trusted)},
        )
        self.ident = _identity(self.trusted)
        self.reopen()

    def reopen(self):
        """Simulate process restart: fresh objects, durable files only."""
        closure = ReceiverAncestryClosureView(
            durable_path=self.log_path if Path(self.log_path).exists()
            else self._ensure_log(),
            identity=self.ident,
        )
        self.closure = closure
        self.view = ClosureAwareStandingView(
            self.trusted,
            closure_view=closure,
            durable_path=self.heads_path,
        )
        return self

    def _ensure_log(self):
        ReceiverAncestryClosureView.create_durable_log(
            self.log_path, self.ident
        )
        return self.log_path

    def lineage(self, ancestor_label, descendant_label, decision_id,
                ancestor_action="aa", descendant_action="dd"):
        s_a = _support(ancestor_label)
        s_d = _support(descendant_label)
        h_a = support_receipt_hash(s_a)
        h_d = support_receipt_hash(s_d)
        act_a, act_d = ancestor_action * 32, descendant_action * 32
        p_a1 = _projection(self.key, h_a, act_a, "ACTIVE", "ADMIT", 1, None)
        p_a2 = _projection(
            self.key, h_a, act_a, "INACTIVE", "REVOKE", 2,
            p_a1["payload_hash"],
        )
        p_d1 = _projection(self.key, h_d, act_d, "ACTIVE", "ADMIT", 1, None)
        return {
            "s_a": s_a, "s_d": s_d, "h_a": h_a, "h_d": h_d,
            "act_a": act_a, "act_d": act_d,
            "p_a1": p_a1, "p_a2": p_a2, "p_d1": p_d1,
            "decision_id": decision_id,
        }

    def admit_active_lineage(self, lin):
        self.view.admit(lin["p_a1"], now=NOW)
        edge = self.closure.record_commit(
            decision_id=lin["decision_id"],
            derived_receipt=lin["s_d"],
            accepted_supports=[lin["s_a"]],
        )
        assert edge["created"] is True
        self.view.admit(lin["p_d1"], now=NOW)
        return lin

    def revoke_ancestor(self, lin):
        admitted = self.view.admit(lin["p_a2"], now=NOW)
        assert admitted["standing"] == "INACTIVE"
        assert "closure" in admitted
        return admitted


@contextmanager
def _raises(exc_type):
    """Context-manager equivalent of raises(); stdlib only for unittest collection."""
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def _make_harness(seed: int = 0x11) -> Harness:
    return Harness(Path(tempfile.mkdtemp(prefix="rollback002-")), seed=seed)


# ---------------------------------------------------------------------------
# T1: original ancestry rollback
# ---------------------------------------------------------------------------

def test_t1_descendant_stays_refused_after_restart():
    h = _make_harness()
    lin = h.lineage("ancestor", "descendant", "t1/d1")
    h.admit_active_lineage(lin)
    h.revoke_ancestor(lin)
    assert h.closure.is_affected(lin["h_d"])

    h.reopen()  # process restart

    assert h.closure.is_affected(lin["h_d"])
    affected = h.closure.affected(lin["h_d"])
    assert affected["state"] == "AFFECTED_UPSTREAM_STANDING_LOSS"
    assert affected["upstream_support_hash"] == lin["h_a"]
    # Ancestor head still revoked (001 holds).
    assert h.view.head_hash(lin["h_a"], lin["act_a"]) == \
        lin["p_a2"]["payload_hash"]


# ---------------------------------------------------------------------------
# T2: transitive grandchild
# ---------------------------------------------------------------------------

def test_t2_grandchild_stays_refused_after_restart():
    h = _make_harness()
    s_a, s_b, s_c = _support("a"), _support("b"), _support("c")
    h_a, h_b, h_c = (support_receipt_hash(s) for s in (s_a, s_b, s_c))
    p_a1 = _projection(h.key, h_a, "aa" * 32, "ACTIVE", "ADMIT", 1, None)
    p_a2 = _projection(h.key, h_a, "aa" * 32, "INACTIVE", "REVOKE", 2,
                       p_a1["payload_hash"])
    h.view.admit(p_a1, now=NOW)
    assert h.closure.record_commit(
        decision_id="t2/ab", derived_receipt=s_b,
        accepted_supports=[s_a])["created"] is True
    assert h.closure.record_commit(
        decision_id="t2/bc", derived_receipt=s_c,
        accepted_supports=[s_b])["created"] is True
    h.view.admit(p_a2, now=NOW)
    assert h.closure.is_affected(h_b)
    assert h.closure.is_affected(h_c)

    h.reopen()

    assert h.closure.is_affected(h_b)
    assert h.closure.is_affected(h_c)


# ---------------------------------------------------------------------------
# T3: selective sibling — unrelated lineage stays clean
# ---------------------------------------------------------------------------

def test_t3_unrelated_lineage_not_invented():
    h = _make_harness()
    lin = h.lineage("a", "b", "t3/ab")
    other = h.lineage("x", "d", "t3/xd", ancestor_action="ee",
                      descendant_action="ff")
    h.admit_active_lineage(lin)
    h.admit_active_lineage(other)
    h.revoke_ancestor(lin)

    h.reopen()

    assert h.closure.is_affected(lin["h_d"])
    assert not h.closure.is_affected(other["h_d"])
    assert not h.closure.is_affected(other["h_a"])
    # Persistence invented no cross-lineage relationship.
    assert h.closure.affected(other["h_d"]) is None


# ---------------------------------------------------------------------------
# T4: fresh successor lineage is not permanently denied
# ---------------------------------------------------------------------------

def test_t4_fresh_successor_admitted_after_restart():
    h = _make_harness()
    lin = h.lineage("ancestor", "descendant", "t4/d1")
    h.admit_active_lineage(lin)
    h.revoke_ancestor(lin)
    assert h.closure.is_affected(lin["h_d"])

    h.reopen()

    assert h.closure.is_affected(lin["h_d"])  # old lineage still refused
    fresh = h.lineage("ancestor2", "descendant2", "t4/d2",
                      ancestor_action="11", descendant_action="22")
    h.admit_active_lineage(fresh)  # must not raise: no permanent denial
    assert not h.closure.is_affected(fresh["h_d"])
    assert not h.closure.is_affected(fresh["h_a"])


# ---------------------------------------------------------------------------
# T5: stale ancestor re-admission refused after restart (001 composition)
# ---------------------------------------------------------------------------

def test_t5_stale_ancestor_readmission_refused_after_restart():
    h = _make_harness()
    lin = h.lineage("ancestor", "descendant", "t5/d1")
    h.admit_active_lineage(lin)
    h.revoke_ancestor(lin)

    h.reopen()

    with _raises(StandingProjectionError):
        h.view.admit(lin["p_a1"], now=NOW)  # stale ACTIVE seq 1
    assert h.closure.is_affected(lin["h_d"])


# ---------------------------------------------------------------------------
# T6: transformed derived descendant keeps its durable ancestry link
# ---------------------------------------------------------------------------

def test_t6_transformed_descendant_keeps_link_across_restart():
    h = _make_harness()
    # The current code has no distinct "transform" primitive: a transformed
    # artifact is simply a different derived receipt. The edge mechanism
    # covers it, and must survive restart.
    lin = h.lineage("ancestor", "descendant", "t6/d1")
    transformed = {"artifact": "transformed-output",
                   "from_label": "descendant", "nonce": "t6"}
    h.view.admit(lin["p_a1"], now=NOW)
    assert h.closure.record_commit(
        decision_id="t6/d1t", derived_receipt=transformed,
        accepted_supports=[lin["s_a"]])["created"] is True
    h.revoke_ancestor(lin)
    h_t = support_receipt_hash(transformed)
    assert h.closure.is_affected(h_t)

    h.reopen()

    assert h.closure.is_affected(h_t)
    assert h.closure.affected(h_t)["upstream_support_hash"] == lin["h_a"]


# ---------------------------------------------------------------------------
# T7/T8/T9/T10: fail-closed open
# ---------------------------------------------------------------------------

def test_t7_missing_durable_state_fails_closed():
    tmp_path = Path(tempfile.mkdtemp(prefix="rollback002-"))
    key, pub = _issuer(0x11)
    ident = {"view": ANCESTRY_CLOSURE_VIEW_IDENTITY,
             "trusted_issuers": {ISSUER_ID: pub}}
    with _raises(DurableOpLogError):
        ReceiverAncestryClosureView(
            durable_path=str(tmp_path / "nope.json"), identity=ident)


def test_t8_corrupt_durable_state_fails_closed():
    tmp_path = Path(tempfile.mkdtemp(prefix="rollback002-"))
    key, pub = _issuer(0x11)
    ident = {"view": ANCESTRY_CLOSURE_VIEW_IDENTITY,
             "trusted_issuers": {ISSUER_ID: pub}}
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"\x00\x01not json{{")
    with _raises(DurableOpLogError):
        ReceiverAncestryClosureView(
            durable_path=str(bad), identity=ident)
    bad2 = tmp_path / "bad2.json"
    bad2.write_text(json.dumps({"schema": "durable_ancestry_log/v1",
                                "identity": ident,
                                "ops": [{"op": "bogus"}]}))
    with _raises(DurableOpLogError):
        ReceiverAncestryClosureView(
            durable_path=str(bad2), identity=ident)


def test_t9_identity_mismatch_fails_closed():
    tmp_path = Path(tempfile.mkdtemp(prefix="rollback002-"))
    key, pub = _issuer(0x11)
    ident_a = {"view": ANCESTRY_CLOSURE_VIEW_IDENTITY,
               "trusted_issuers": {ISSUER_ID: pub}}
    _, pub_b = _issuer(0x22)
    ident_b = {"view": ANCESTRY_CLOSURE_VIEW_IDENTITY,
               "trusted_issuers": {ISSUER_ID: pub_b}}
    path = str(tmp_path / "anc.json")
    ReceiverAncestryClosureView.create_durable_log(path, ident_a)
    with _raises(DurableOpLogError):
        ReceiverAncestryClosureView(durable_path=path, identity=ident_b)
    # And the rightful owner still opens.
    ReceiverAncestryClosureView(durable_path=path, identity=ident_a)


def test_t10_trust_root_mismatch_fails_closed():
    tmp_path = Path(tempfile.mkdtemp(prefix="rollback002-"))
    # Same mechanism as T9, exercised through the trust-issuer binding:
    # a log created under one trust root must not initialize a receiver
    # under another.
    key, pub = _issuer(0x11)
    ident = {"view": ANCESTRY_CLOSURE_VIEW_IDENTITY,
             "trusted_issuers": {ISSUER_ID: pub}}
    path = str(tmp_path / "anc.json")
    ReceiverAncestryClosureView.create_durable_log(path, ident)
    tampered = json.loads(Path(path).read_text())
    _, pub_evil = _issuer(0x99)
    tampered["identity"]["trusted_issuers"][ISSUER_ID] = pub_evil
    Path(path).write_text(json.dumps(tampered))
    with _raises(DurableOpLogError):
        ReceiverAncestryClosureView(durable_path=path, identity=ident)


# ---------------------------------------------------------------------------
# T11: write failure -> no acknowledgement
# ---------------------------------------------------------------------------

def test_t11_record_commit_write_failure_not_acknowledged():
    h = _make_harness()
    lin = h.lineage("ancestor", "descendant", "t11/d1")
    with mock.patch.object(h.closure._op_log, "append",
                           side_effect=DurableOpLogError("injected")):
        with _raises(DurableOpLogError):
            h.closure.record_commit(
                decision_id=lin["decision_id"],
                derived_receipt=lin["s_d"],
                accepted_supports=[lin["s_a"]],
            )
    # No in-memory change, nothing durably recorded.
    assert not h.closure._edges
    h.reopen()
    assert not h.closure._edges


def test_t11_apply_loss_write_failure_not_acknowledged():
    h = _make_harness()
    lin = h.lineage("ancestor", "descendant", "t11/d2")
    h.admit_active_lineage(lin)
    with mock.patch.object(h.closure._op_log, "append",
                           side_effect=DurableOpLogError("injected")):
        with _raises(DurableOpLogError):
            h.closure.apply_standing_loss(
                support_hash=lin["h_a"],
                standing_event_id="t11:evt",
                standing_event_sequence=1,
            )
    assert not h.closure.is_affected(lin["h_d"])
    assert not h.closure._processed_standing_events


def test_t11_coupled_admit_ancestry_failure_refuses_but_stays_safe():
    h = _make_harness()
    # The 001 head commits; the ancestry loss op fails. The admission must
    # raise (not acknowledged), the live process must still refuse the
    # descendant, and the head must be durably revoked.
    lin = h.lineage("ancestor", "descendant", "t11/d3")
    h.admit_active_lineage(lin)
    with mock.patch.object(h.closure._op_log, "append",
                           side_effect=DurableOpLogError("injected")):
        with _raises(DurableOpLogError):
            h.view.admit(lin["p_a2"], now=NOW)
    # Live window did not widen: the loss is installed in memory.
    assert h.closure.is_affected(lin["h_d"])
    # The head is durably revoked.
    plain = ReceiverStandingView(h.trusted, durable_path=h.heads_path)
    assert plain.head_hash(lin["h_a"], lin["act_a"]) == \
        lin["p_a2"]["payload_hash"]
    # Restart reconciles the log: still refused, log converged.
    h.reopen()
    assert h.closure.is_affected(lin["h_d"])
    ops = DurableOpLog(h.log_path, h.ident).load_ops()
    assert any(o["op"] == "loss" and
               o["standing_event_id"] == lin["p_a2"]["payload_hash"]
               for o in ops)


# ---------------------------------------------------------------------------
# T12: clean first boot
# ---------------------------------------------------------------------------

def test_t12_clean_first_boot():
    tmp_path = Path(tempfile.mkdtemp(prefix="rollback002-"))
    key, pub = _issuer(0x11)
    ident = {"view": ANCESTRY_CLOSURE_VIEW_IDENTITY,
             "trusted_issuers": {ISSUER_ID: pub}}
    path = str(tmp_path / "anc.json")
    view = ReceiverAncestryClosureView.create_durable_log(path, ident)
    assert view.durable
    assert view.snapshot()["edges"] == []
    # Refuses to clobber.
    with _raises(DurableOpLogError):
        ReceiverAncestryClosureView.create_durable_log(path, ident)
    # Reopens empty.
    reopened = ReceiverAncestryClosureView(
        durable_path=path, identity=ident)
    assert reopened.snapshot()["edges"] == []


# ---------------------------------------------------------------------------
# T13: duplicate / replayed lineage is idempotent and non-widening
# ---------------------------------------------------------------------------

def test_t13_duplicate_edge_and_replayed_loss_idempotent():
    h = _make_harness()
    lin = h.lineage("ancestor", "descendant", "t13/d1")
    h.view.admit(lin["p_a1"], now=NOW)
    first = h.closure.record_commit(
        decision_id=lin["decision_id"], derived_receipt=lin["s_d"],
        accepted_supports=[lin["s_a"]])
    second = h.closure.record_commit(
        decision_id=lin["decision_id"], derived_receipt=lin["s_d"],
        accepted_supports=[lin["s_a"]])
    assert first["created"] is True and second["created"] is False
    assert second["edge"]["edge_id"] == first["edge"]["edge_id"]
    h.view.admit(lin["p_a2"], now=NOW)
    replay = h.closure.apply_standing_loss(
        support_hash=lin["h_a"],
        standing_event_id=lin["p_a2"]["payload_hash"],
        standing_event_sequence=2,
    )
    assert replay["replayed"] is True
    ops = DurableOpLog(h.log_path, h.ident).load_ops()
    assert sum(1 for o in ops if o["op"] == "edge") == 1
    assert sum(1 for o in ops if o["op"] == "loss") == 1

    h.reopen()
    assert h.closure.is_affected(lin["h_d"])


# ---------------------------------------------------------------------------
# T14: descendant first evaluated only after restart
# ---------------------------------------------------------------------------

def test_t14_first_evaluation_after_restart_still_refused():
    h = _make_harness()
    lin = h.lineage("ancestor", "descendant", "t14/d1")
    h.admit_active_lineage(lin)
    h.revoke_ancestor(lin)
    # Deliberately NO pre-restart evaluation of the descendant via
    # affected()/is_affected(): the verdict must come from durable
    # edges + loss events, not from a cached pre-crash evaluation.

    h.reopen()

    assert h.closure.is_affected(lin["h_d"])
    # And the assertion-level source still refuses it, as in the falsifier.
    provide = closure_aware_standing_requirement_source(
        h.view,
        closure_view=h.closure,
        support_source=lambda call: lin["s_d"],
        projection_source=lambda call: lin["p_d1"],
        action_hash_source=lambda call: lin["act_d"],
        evidence_issuer_id="t14",
        now_source=lambda: NOW,
    )
    assertion = provide(ToolCallContext(
        tool="payments", target="refund://process",
        arguments={"order": "42"}, proposal_id="t14/p",
        producer_id="worker-x", producer_model="model-x",
        objective="issue refund",
    ))
    assert assertion is not None
    assert assertion.revoked is True


# ---------------------------------------------------------------------------
# Regression guard: legacy in-memory default is unchanged (defect excluded
# there by the claim ceiling, as in 001).
# ---------------------------------------------------------------------------

def test_legacy_default_still_forgets():
    closure = ReceiverAncestryClosureView()
    assert not closure.durable
    s_a, s_d = _support("a"), _support("d")
    h_a = support_receipt_hash(s_a)
    closure.record_commit(decision_id="leg/d", derived_receipt=s_d,
                          accepted_supports=[s_a])
    closure.apply_standing_loss(support_hash=h_a, standing_event_id="e1",
                                standing_event_sequence=1)
    assert closure.is_affected(support_receipt_hash(s_d))
    fresh = ReceiverAncestryClosureView()
    assert not fresh.is_affected(support_receipt_hash(s_d))


# ---------------------------------------------------------------------------
# Subprocess boundary test: two real processes, durable files only.
# ---------------------------------------------------------------------------

_PROC_SCRIPT = r'''
import json, sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

REPO = r"{repo}"
WORK = r"{work}"
MODE = r"{mode}"
sys.path.insert(0, REPO)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from olp_gate._durable_heads import DurableHeadStore
from olp_gate.ancestry import (
    ANCESTRY_CLOSURE_VIEW_IDENTITY,
    ClosureAwareStandingView,
    ReceiverAncestryClosureView,
)
from olp_gate.crypto import public_key_hex, sign_olp_body
from olp_gate.standing import STANDING_PROJECTION_SCHEMA, support_receipt_hash

ISSUED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
EXPIRES_AT = datetime(2030, 1, 1, tzinfo=timezone.utc)

def iso(v): return v.isoformat().replace("+00:00", "Z")

key = Ed25519PrivateKey.from_private_bytes(bytes([0x31]) * 32)
pub = public_key_hex(key)
trusted = {"proc-issuer": pub}

def proj(support_hash, action_hash, standing, event_type, sequence, pred):
    return sign_olp_body(
        {"schema": STANDING_PROJECTION_SCHEMA,
         "projection_id": f"{event_type.lower()}:{sequence}",
         "issuer_id": "proc-issuer", "support_hash": support_hash,
         "action_hash": action_hash, "standing": standing,
         "event_type": event_type, "sequence": sequence,
         "predecessor_hash": pred, "issued_at": iso(ISSUED_AT),
         "expires_at": iso(EXPIRES_AT)}, key)

s_a = {"artifact": "approval-record", "label": "ancestor"}
s_d = {"artifact": "approval-record", "label": "descendant"}
h_a, h_d = support_receipt_hash(s_a), support_receipt_hash(s_d)
act_a, act_d = "aa" * 32, "dd" * 32
heads_path = str(Path(WORK) / "heads.json")
log_path = str(Path(WORK) / "ancestry.json")
ident = {"view": ANCESTRY_CLOSURE_VIEW_IDENTITY,
         "trusted_issuers": dict(trusted)}

if MODE == "a":
    DurableHeadStore.create(
        heads_path, {"view": "standing/v1",
                     "trusted_issuers": dict(trusted)})
    ReceiverAncestryClosureView.create_durable_log(log_path, ident)
    closure = ReceiverAncestryClosureView(
        durable_path=log_path, identity=ident)
    view = ClosureAwareStandingView(trusted, closure_view=closure,
                                    durable_path=heads_path)
    p_a1 = proj(h_a, act_a, "ACTIVE", "ADMIT", 1, None)
    p_a2 = proj(h_a, act_a, "INACTIVE", "REVOKE", 2, p_a1["payload_hash"])
    p_d1 = proj(h_d, act_d, "ACTIVE", "ADMIT", 1, None)
    view.admit(p_a1, now=NOW)
    assert closure.record_commit(
        decision_id="proc/d1", derived_receipt=s_d,
        accepted_supports=[s_a])["created"] is True
    view.admit(p_d1, now=NOW)
    view.admit(p_a2, now=NOW)
    assert closure.is_affected(h_d)
    Path(WORK, "phase_a.json").write_text(json.dumps({"affected": True}))
else:
    closure = ReceiverAncestryClosureView(
        durable_path=log_path, identity=ident)
    view = ClosureAwareStandingView(trusted, closure_view=closure,
                                    durable_path=heads_path)
    refused = closure.is_affected(h_d)
    Path(WORK, "phase_b.json").write_text(
        json.dumps({"refused_after_restart": refused}))
    sys.exit(0 if refused else 3)
'''


def test_subprocess_two_real_processes():
    tmp_path = Path(tempfile.mkdtemp(prefix="rollback002-"))
    work = tmp_path / "proc"
    work.mkdir()
    for mode in ("a", "b"):
        script = work / f"phase_{mode}.py"
        script.write_text(
            _PROC_SCRIPT.replace("{repo}", str(REPO_ROOT))
            .replace("{work}", str(work))
            .replace("{mode}", mode)
        )
        proc = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
    assert json.loads((work / "phase_a.json").read_text()) == {"affected": True}
    assert json.loads((work / "phase_b.json").read_text()) == \
        {"refused_after_restart": True}


# ---------------------------------------------------------------------------
# Concurrency / race check: concurrent writers, one shared log.
# ---------------------------------------------------------------------------

def test_concurrent_writers_no_lost_state():
    h = _make_harness()
    errors = []

    def worker(i: int):
        try:
            s_a = _support(f"c-ancestor-{i}")
            s_d = _support(f"c-descendant-{i}")
            h_a = support_receipt_hash(s_a)
            act = f"{i:02x}" * 32
            p1 = _projection(h.key, h_a, act, "ACTIVE", "ADMIT", 1, None)
            p2 = _projection(h.key, h_a, act, "INACTIVE", "REVOKE", 2,
                             p1["payload_hash"])
            h.view.admit(p1, now=NOW)
            h.closure.record_commit(
                decision_id=f"conc/d{i}", derived_receipt=s_d,
                accepted_supports=[s_a])
            h.view.admit(p2, now=NOW)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    before = h.closure.snapshot()
    # Every revoked ancestor's descendant is affected: no lost loss events.
    for i in range(6):
        h_d = support_receipt_hash(_support(f"c-descendant-{i}"))
        assert h.closure.is_affected(h_d), i

    h.reopen()
    after = h.closure.snapshot()
    # Log-order replay reproduces the live in-memory state exactly.
    assert after == before


# ---------------------------------------------------------------------------
# Crash points
# ---------------------------------------------------------------------------

def test_crash_head_durable_loss_missing_reconcile_heals():
    h = _make_harness()
    # Simulate the crash between the 001 head commit and the ancestry loss
    # append: revoke the head with a plain standing view (no closure), then
    # record the edge on the durable closure directly.
    lin = h.lineage("ancestor", "descendant", "crash/d1")
    plain = ReceiverStandingView(h.trusted, durable_path=h.heads_path)
    plain.admit(lin["p_a1"], now=NOW)
    direct = ReceiverAncestryClosureView(
        durable_path=h.log_path, identity=h.ident)
    direct.record_commit(decision_id=lin["decision_id"],
                         derived_receipt=lin["s_d"],
                         accepted_supports=[lin["s_a"]])
    plain.admit(lin["p_a2"], now=NOW)  # "crash" here: no loss op logged

    # Next construction of the coupled view must heal via reconcile.
    healed_closure = ReceiverAncestryClosureView(
        durable_path=h.log_path, identity=h.ident)
    healed = ClosureAwareStandingView(
        h.trusted, closure_view=healed_closure,
        durable_path=h.heads_path)
    assert healed.closure_view.is_affected(lin["h_d"])
    # The log converged: the synthesized loss is now durable.
    ops = DurableOpLog(h.log_path, h.ident).load_ops()
    assert any(o["op"] == "loss" and
               o["standing_event_id"] == lin["p_a2"]["payload_hash"]
               for o in ops)
    # And a further restart stays refused.
    h.reopen()
    assert h.closure.is_affected(lin["h_d"])
