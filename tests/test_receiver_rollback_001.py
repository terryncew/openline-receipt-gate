"""RECEIVER-ROLLBACK-001: restart-monotonic receiver heads.

Frozen test suite. See ~/workspace/receiver-rollback-001/PREREGISTRATION.md.
T1-T10 are the mandatory defect/regression tests; M1-M6 the restart matrix;
one subprocess test crosses a real process boundary; the ADV set probes the
threat-model edge.

Threat-model classification for the adversarial set:
  IN-SCOPE (unprivileged): replay of superseded records, forked sequences,
  cross-instance races on one head file, wrong-issuer records. All must be
  defeated: the head frontier never moves backward or sideways.
  OUTSIDE (privileged local attacker): tampering with or restoring a stale
  copy of the head file itself. Documented, not defended: the same exposure
  exists for the already-durable VerifiedCommitLedger, SessionLedger, and
  capability_store. The defense boundary is the file's integrity, which is
  the operator's, not the receiver's.

Determinism: fixed Ed25519 seeds, explicit now= timestamps everywhere the
API allows. T4's challenge nonce and ADV3's thread scheduling are the only
nondeterminism, and no assertion depends on either.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate._durable_heads import DurableHeadStore, DurableHeadStoreError
from olp_gate.adapters import FAIL
from olp_gate.capability_lifecycle import BudgetRefused, reserve
from olp_gate.capability_receipt import RECEIPT_VERSION, SCOPE_PROFILE, HOLDER_METHOD
from olp_gate.capability_receipt import verify_capability_receipt
from olp_gate.capability_store import (
    open_store,
    register_capability,
    revoke_capability,
)
from olp_gate.crypto import public_key_hex, sign_olp_body
from olp_gate import issuance as issuance_mod
from olp_gate.mandate_owner import (
    MandateAuthorityError,
    MandateOwnerView,
    issue_mandate_authorization,
)
from olp_gate.session import SessionLedger
from olp_gate.standing import (
    STANDING_PROJECTION_SCHEMA,
    ReceiverStandingView,
    StandingProjectionError,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

ISSUED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
EXPIRES_AT = datetime(2030, 1, 1, tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _issuer(seed: int):
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    return "test-issuer", key, public_key_hex(key)


def _standing_projection(key, issuer_id, support_hash, action_hash,
                         standing, event_type, sequence, predecessor_hash):
    return sign_olp_body(
        {
            "schema": STANDING_PROJECTION_SCHEMA,
            "projection_id": f"{event_type.lower()}:{sequence}",
            "issuer_id": issuer_id,
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


def _standing_pair():
    """Admit-pair P1 (ACTIVE) then P2 (REVOKE) plus the trust config."""
    issuer_id, key, pub = _issuer(0x11)
    trusted = {issuer_id: pub}
    support, action = "aa" * 32, "bb" * 32
    p1 = _standing_projection(key, issuer_id, support, action,
                             "ACTIVE", "ADMIT", 1, None)
    p2 = _standing_projection(key, issuer_id, support, action,
                             "INACTIVE", "REVOKE", 2, p1["payload_hash"])
    return trusted, support, action, p1, p2


def _mandate_dict():
    return {
        "profile": "principal_mandate/v1",
        "mandate_id": "refund-mandate",
        "principal_id": "alice",
        "agent_id": "refund-agent",
        "purpose": "customer refunds",
        "allowed_action_types": ["authorize_payment"],
        "allowed_targets": ["refund://process"],
        "allowed_disclosure_classes": [],
        "forbidden_disclosure_classes": [],
        "max_settlement_cents": 0,
        "max_payment_cents": 100,
        "delegation_allowed": False,
        "expires_at": _iso(EXPIRES_AT),
        "version": "1",
    }


def _slot_config(seed: int = 0x22):
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    slots = {"slot-1": {"owner_id": "alice", "public_key": public_key_hex(key)}}
    return slots, key


def _mandate_auth(key, state, sequence, predecessor_hash):
    return issue_mandate_authorization(
        slot_id="slot-1",
        owner_id="alice",
        mandate=_mandate_dict(),
        state=state,
        sequence=sequence,
        predecessor_hash=predecessor_hash,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        key=key,
    )


def _create_standing_store(path: str, trusted) -> None:
    DurableHeadStore.create(
        path, {"view": "standing/v1", "trusted_issuers": dict(trusted)}
    )


def _create_mandate_store(path: str, slots) -> None:
    DurableHeadStore.create(
        path, {"view": "mandate_owner/v1", "slots": {k: dict(v) for k, v in slots.items()}}
    )


def _raises(exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type as exc:
        return exc
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


# ---------------------------------------------------------------------------
# T1-T3: the defect, repaired
# ---------------------------------------------------------------------------

def test_t1_standing_rollback_refused_after_restart(tmp_path):
    """T1: revoked standing cannot be resurrected by restarting the receiver."""
    trusted, support, action, p1, p2 = _standing_pair()
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted)

    view_a = ReceiverStandingView(trusted, durable_path=path)
    view_a.admit(p1, now=NOW)
    view_a.admit(p2, now=NOW)

    # Restart: fresh view, same trust config, same head file.
    view_b = ReceiverStandingView(trusted, durable_path=path)
    assert view_b.head_hash(support, action) == p2["payload_hash"]

    exc = _raises(StandingProjectionError, view_b.admit, p1, now=NOW)
    assert "standing_successor_sequence_invalid" in str(exc)

    assessed = view_b.assess(p1, support_hash=support, action_hash=action, now=NOW)
    assert assessed["verified"] is False
    assert "standing_head_mismatch" in assessed["reason_codes"]


def test_t2_fresh_successor_admitted_after_restart(tmp_path):
    """T2: restart must not freeze the frontier; a valid successor still admits."""
    trusted, support, action, p1, p2 = _standing_pair()
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted)

    view_a = ReceiverStandingView(trusted, durable_path=path)
    view_a.admit(p1, now=NOW)
    view_a.admit(p2, now=NOW)

    view_b = ReceiverStandingView(trusted, durable_path=path)
    _, key, _ = _issuer(0x11)
    p3 = _standing_projection(key, "test-issuer", support, action,
                             "INACTIVE", "SUPERSEDE", 3, p2["payload_hash"])
    result = view_b.admit(p3, now=NOW)
    assert result["admitted"] is True
    assert result["sequence"] == 3
    assert view_b.head_hash(support, action) == p3["payload_hash"]


def test_t3_mandate_stale_head_refused_after_restart(tmp_path):
    """T3: a revoked mandate slot cannot be reactivated by restarting."""
    slots, key = _slot_config()
    path = str(tmp_path / "heads.json")
    _create_mandate_store(path, slots)
    mandate = _mandate_dict()

    a1 = _mandate_auth(key, "ACTIVE", 1, None)
    a2 = _mandate_auth(key, "REVOKED", 2, a1["payload_hash"])

    view_a = MandateOwnerView(slots, durable_path=path)
    view_a.admit(a1, mandate, now=NOW)
    view_a.admit(a2, mandate, now=NOW)
    assert view_a.status("slot-1", now=NOW) == "REVOKED"

    view_b = MandateOwnerView(slots, durable_path=path)
    assert view_b.status("slot-1", now=NOW) == "REVOKED"
    exc = _raises(MandateAuthorityError, view_b.admit, a1, mandate, now=NOW)
    assert "mandate_authorization_successor_sequence_invalid" in str(exc)
    assert view_b.status("slot-1", now=NOW) == "REVOKED"


# ---------------------------------------------------------------------------
# T4-T5: already-durable components stay durable (regression)
# ---------------------------------------------------------------------------

def test_t4_session_challenge_replay_refused_after_restart(tmp_path):
    """T4: a consumed challenge stays consumed across a ledger restart."""
    path = str(tmp_path / "session.json")
    ledger_a = SessionLedger(path)
    source_hash = "cc" * 32
    binding = ledger_a.issue_challenge(
        run_id="run-1", session_id="sess-1", expected_source_hash=source_hash
    )
    ledger_a.consume(binding, source_hash=source_hash, decision_hash="dd" * 32)

    ledger_b = SessionLedger(path)
    result = ledger_b.check(binding, source_hash=source_hash)
    assert result.status == FAIL
    assert "challenge_replay" in result.reason_codes


def _capability_owner(seed: int = 0x33):
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    return key, public_key_hex(key)


def test_t5_revoked_capability_stays_revoked_after_reopen(tmp_path):
    """T5: revocation in the capability store survives closing the connection."""
    db = str(tmp_path / "caps.db")
    owner_key, owner_pub = _capability_owner()
    now = datetime.now(timezone.utc)
    now_unix = int(now.timestamp())

    receipt = sign_olp_body(
        {
            "@version": RECEIPT_VERSION,
            "capability_id": "cap-001",
            "issuer_owner_id": "principal-p",
            "issuer_public_key": owner_pub,
            "subject": "principal-p",
            "budget": {"amount": 100, "unit": "cents", "scale": 0},
            "scope": {"profile": SCOPE_PROFILE},
            "holder": {"method": HOLDER_METHOD},
            "expires_at": (now + timedelta(days=1)).isoformat(),
            "parent": None,
            "revocation_mode": "direct",
            "threshold": {"m": 1, "n": 1},
        },
        owner_key,
    )
    conn = open_store(db)
    try:
        parsed = verify_capability_receipt(receipt, "principal-p", owner_pub)
        auth = issuance_mod.make_issuance_auth(
            "cap-001", parsed["receipt_digest"], "principal-p", owner_key, now
        )
        auth_digest = issuance_mod.verify_issuance_auth(
            auth, capability_id="cap-001", receipt_digest=parsed["receipt_digest"],
            pinned_owner_id="principal-p", pinned_pubkey_hex=owner_pub,
        )
        row = register_capability(conn, parsed, auth_digest, now_unix)
        revoke_capability(conn, "cap-001", now_unix)
    finally:
        conn.close()

    # Reopen: a fresh connection against the same file.
    conn2 = open_store(db)
    try:
        cap = {"capability_id": "cap-001"}
        exc = _raises(
            BudgetRefused, reserve, conn2, cap, "op-1", 10,
            "ee" * 32, "ff" * 32, now_unix,
        )
        assert "capability_revoked" in str(exc)
    finally:
        conn2.close()
    _ = row  # keep linters quiet about the registration result


# ---------------------------------------------------------------------------
# T6: write failure is fail-closed
# ---------------------------------------------------------------------------

def test_t6_write_failure_keeps_old_head(tmp_path):
    """T6: if the atomic write fails, admit raises and the old head stands.

    Fault injection via RLIMIT_FSIZE: the read path and the transition still
    work, but the temp-file write exceeds the limit and fails with EFBIG.
    Works as root, where permission-based fault injection does not.
    """
    import resource
    import signal

    trusted, support, action, p1, p2 = _standing_pair()
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted)
    view = ReceiverStandingView(trusted, durable_path=path)
    view.admit(p1, now=NOW)
    before = Path(path).read_bytes()

    old_handler = signal.getsignal(signal.SIGXFSZ)
    old_limits = resource.getrlimit(resource.RLIMIT_FSIZE)
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    # The committed JSON is ~1.5KB; 100 bytes guarantees the write fails.
    # Lower only the soft limit: this container cannot raise a hard limit.
    resource.setrlimit(resource.RLIMIT_FSIZE, (100, old_limits[1]))
    try:
        _raises(OSError, view.admit, p2, now=NOW)
    finally:
        resource.setrlimit(resource.RLIMIT_FSIZE, old_limits)
        signal.signal(signal.SIGXFSZ, old_handler)

    # In-memory state did not move; the file still holds only P1.
    assert view.head_hash(support, action) == p1["payload_hash"]
    assert Path(path).read_bytes() == before
    assert len(json.loads(before)["heads"]) == 1


# ---------------------------------------------------------------------------
# T7-T9: fail-closed open, identity binding, root binding
# ---------------------------------------------------------------------------

def test_t7_missing_and_corrupt_files_fail_closed(tmp_path):
    """T7: no head file, no admission. Corrupt file, no admission."""
    trusted, _, _, _, _ = _standing_pair()
    slots, _ = _slot_config()

    missing = str(tmp_path / "nope.json")
    _raises(DurableHeadStoreError,
            ReceiverStandingView, trusted, durable_path=missing)
    _raises(DurableHeadStoreError,
            MandateOwnerView, slots, durable_path=missing)

    corrupt = str(tmp_path / "corrupt.json")
    Path(corrupt).write_bytes(b"\x00\x01not json{{")
    _raises(DurableHeadStoreError,
            ReceiverStandingView, trusted, durable_path=corrupt)
    _raises(DurableHeadStoreError,
            MandateOwnerView, slots, durable_path=corrupt)


def test_t8_identity_binding_rejects_foreign_trust(tmp_path):
    """T8: a head file created under one trust config will not open under another."""
    trusted_a, _, _, _, _ = _standing_pair()
    _, _, pub_b = _issuer(0x44)
    trusted_b = {"test-issuer": pub_b}
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted_a)

    ok_view = ReceiverStandingView(trusted_a, durable_path=path)
    assert ok_view.head_hash("aa" * 32, "bb" * 32) is None
    _raises(DurableHeadStoreError,
            ReceiverStandingView, trusted_b, durable_path=path)

    slots_a, _ = _slot_config(0x22)
    _, other_pub = _capability_owner(0x55)
    slots_b = {"slot-1": {"owner_id": "alice", "public_key": other_pub}}
    mpath = str(tmp_path / "mheads.json")
    _create_mandate_store(mpath, slots_a)
    MandateOwnerView(slots_a, durable_path=mpath)
    _raises(DurableHeadStoreError, MandateOwnerView, slots_b, durable_path=mpath)


def test_t9_tampered_identity_rejected_at_open(tmp_path):
    """T9: the trust root is pinned; rewriting the file's identity fails closed."""
    trusted, support, action, p1, p2 = _standing_pair()
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted)
    view = ReceiverStandingView(trusted, durable_path=path)
    view.admit(p1, now=NOW)
    view.admit(p2, now=NOW)

    payload = json.loads(Path(path).read_text())
    _, _, other_pub = _issuer(0x66)
    payload["identity"] = {"view": "standing/v1",
                           "trusted_issuers": {"test-issuer": other_pub}}
    Path(path).write_text(json.dumps(payload))

    # The receiver's own config no longer matches the file's claimed root.
    _raises(DurableHeadStoreError, ReceiverStandingView, trusted, durable_path=path)


def test_t10_clean_first_boot(tmp_path):
    """T10: create() then open is the documented first boot; empty frontier."""
    trusted, support, action, p1, _ = _standing_pair()
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted)

    view = ReceiverStandingView(trusted, durable_path=path)
    assert view.head_hash(support, action) is None
    result = view.admit(p1, now=NOW)
    assert result["admitted"] is True

    restarted = ReceiverStandingView(trusted, durable_path=path)
    assert restarted.head_hash(support, action) == p1["payload_hash"]


# ---------------------------------------------------------------------------
# M1-M6: restart matrix
# ---------------------------------------------------------------------------

def test_m1_revoke_restart_readmit_superseded_refused(tmp_path):
    trusted, support, action, p1, p2 = _standing_pair()
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted)
    a = ReceiverStandingView(trusted, durable_path=path)
    a.admit(p1, now=NOW)
    a.admit(p2, now=NOW)
    b = ReceiverStandingView(trusted, durable_path=path)
    _raises(StandingProjectionError, b.admit, p1, now=NOW)
    assert b.head_hash(support, action) == p2["payload_hash"]


def test_m2_revoke_restart_fresh_successor_admitted(tmp_path):
    trusted, support, action, p1, p2 = _standing_pair()
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted)
    a = ReceiverStandingView(trusted, durable_path=path)
    a.admit(p1, now=NOW)
    a.admit(p2, now=NOW)
    b = ReceiverStandingView(trusted, durable_path=path)
    _, key, _ = _issuer(0x11)
    p3 = _standing_projection(key, "test-issuer", support, action,
                             "ACTIVE", "CORRECT", 3, p2["payload_hash"])
    assert b.admit(p3, now=NOW)["admitted"] is True


def test_m3_chain_continues_across_restart(tmp_path):
    trusted, support, action, p1, p2 = _standing_pair()
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted)
    a = ReceiverStandingView(trusted, durable_path=path)
    a.admit(p1, now=NOW)
    # Crash between admits: only P1 reached the file.
    b = ReceiverStandingView(trusted, durable_path=path)
    assert b.admit(p2, now=NOW)["admitted"] is True
    assert b.head_hash(support, action) == p2["payload_hash"]


def test_m4_mandate_revoke_restart_stale_active_refused(tmp_path):
    slots, key = _slot_config()
    path = str(tmp_path / "heads.json")
    _create_mandate_store(path, slots)
    mandate = _mandate_dict()
    a1 = _mandate_auth(key, "ACTIVE", 1, None)
    a2 = _mandate_auth(key, "REVOKED", 2, a1["payload_hash"])
    a = MandateOwnerView(slots, durable_path=path)
    a.admit(a1, mandate, now=NOW)
    a.admit(a2, mandate, now=NOW)
    b = MandateOwnerView(slots, durable_path=path)
    _raises(MandateAuthorityError, b.admit, a1, mandate, now=NOW)
    assert b.status("slot-1", now=NOW) == "REVOKED"


def test_m5_mandate_revoke_restart_new_active_successor_admitted(tmp_path):
    slots, key = _slot_config()
    path = str(tmp_path / "heads.json")
    _create_mandate_store(path, slots)
    mandate = _mandate_dict()
    a1 = _mandate_auth(key, "ACTIVE", 1, None)
    a2 = _mandate_auth(key, "REVOKED", 2, a1["payload_hash"])
    a = MandateOwnerView(slots, durable_path=path)
    a.admit(a1, mandate, now=NOW)
    a.admit(a2, mandate, now=NOW)
    b = MandateOwnerView(slots, durable_path=path)
    a3 = _mandate_auth(key, "ACTIVE", 3, a2["payload_hash"])
    assert b.admit(a3, mandate, now=NOW)["admitted"] is True
    assert b.status("slot-1", now=NOW) == "ACTIVE"


def test_m6_cross_instance_monotonicity_via_file(tmp_path):
    """M6: two live views, one file. The file is the arbiter, not memory."""
    trusted, support, action, p1, p2 = _standing_pair()
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted)
    a = ReceiverStandingView(trusted, durable_path=path)
    b = ReceiverStandingView(trusted, durable_path=path)
    a.admit(p1, now=NOW)
    assert b.admit(p2, now=NOW)["admitted"] is True
    # View A still holds P1 in memory, but the file says P2. A fork off P1 loses.
    _, key, _ = _issuer(0x11)
    p2_fork = _standing_projection(key, "test-issuer", support, action,
                                  "ACTIVE", "CORRECT", 2, p1["payload_hash"])
    _raises(StandingProjectionError, a.admit, p2_fork, now=NOW)
    assert a.head_hash(support, action) == p2["payload_hash"]


# ---------------------------------------------------------------------------
# Subprocess test: a real process boundary, not just a new instance
# ---------------------------------------------------------------------------

_CHILD = """\
import sys
sys.path.insert(0, {repo_root!r})
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from olp_gate._durable_heads import DurableHeadStore
from olp_gate.crypto import public_key_hex, sign_olp_body
from olp_gate.standing import ReceiverStandingView

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
ISSUED = datetime(2026, 1, 1, tzinfo=timezone.utc)
EXPIRES = datetime(2030, 1, 1, tzinfo=timezone.utc)

def iso(v):
    return v.isoformat().replace("+00:00", "Z")

key = Ed25519PrivateKey.from_private_bytes(bytes([0x11]) * 32)
trusted = {{"test-issuer": public_key_hex(key)}}

def proj(standing, event, seq, pred):
    return sign_olp_body({{
        "schema": "openline.standing_projection.v1",
        "projection_id": f"{{event.lower()}}:{{seq}}",
        "issuer_id": "test-issuer",
        "support_hash": "aa" * 32,
        "action_hash": "bb" * 32,
        "standing": standing,
        "event_type": event,
        "sequence": seq,
        "predecessor_hash": pred,
        "issued_at": iso(ISSUED),
        "expires_at": iso(EXPIRES),
    }}, key)

path = {path!r}
DurableHeadStore.create(path, {{"view": "standing/v1", "trusted_issuers": trusted}})
view = ReceiverStandingView(trusted, durable_path=path)
p1 = proj("ACTIVE", "ADMIT", 1, None)
p2 = proj("INACTIVE", "REVOKE", 2, p1["payload_hash"])
view.admit(p1, now=NOW)
view.admit(p2, now=NOW)
print(view.head_hash("aa" * 32, "bb" * 32))
"""


def test_subprocess_restart_preserves_head(tmp_path):
    """The head survives a genuine process exit, read back by the parent."""
    path = str(tmp_path / "heads.json")
    child_file = tmp_path / "child_admit.py"
    child_file.write_text(
        _CHILD.format(repo_root=str(REPO_ROOT), path=path)
    )
    proc = subprocess.run(
        [sys.executable, str(child_file)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    child_head = proc.stdout.strip()
    assert len(child_head) == 64

    trusted = {"test-issuer": public_key_hex(
        Ed25519PrivateKey.from_private_bytes(bytes([0x11]) * 32))}
    parent_view = ReceiverStandingView(trusted, durable_path=path)
    assert parent_view.head_hash("aa" * 32, "bb" * 32) == child_head


# ---------------------------------------------------------------------------
# Adversarial set
# ---------------------------------------------------------------------------

def test_adv1_replay_of_superseded_bytes_refused(tmp_path):
    """ADV1 (in-scope): exact replay of superseded signed bytes after restart."""
    trusted, support, action, p1, p2 = _standing_pair()
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted)
    a = ReceiverStandingView(trusted, durable_path=path)
    a.admit(p1, now=NOW)
    a.admit(p2, now=NOW)
    b = ReceiverStandingView(trusted, durable_path=path)
    replay = json.loads(json.dumps(p1))  # byte-identical logical replay
    _raises(StandingProjectionError, b.admit, replay, now=NOW)
    assessed = b.assess(replay, support_hash=support, action_hash=action, now=NOW)
    assert assessed["verified"] is False


def test_adv2_forked_sibling_sequence_refused(tmp_path):
    """ADV2 (in-scope): a validly-signed sibling fork off an old head loses."""
    trusted, support, action, p1, p2 = _standing_pair()
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted)
    a = ReceiverStandingView(trusted, durable_path=path)
    a.admit(p1, now=NOW)
    a.admit(p2, now=NOW)
    b = ReceiverStandingView(trusted, durable_path=path)
    _, key, _ = _issuer(0x11)
    fork = _standing_projection(key, "test-issuer", support, action,
                               "ACTIVE", "CORRECT", 2, p1["payload_hash"])
    exc = _raises(StandingProjectionError, b.admit, fork, now=NOW)
    assert "standing_successor_sequence_invalid" in str(exc)


def test_adv3_concurrent_admits_exactly_one_wins(tmp_path):
    """ADV3 (in-scope): two threads race to advance one head; one wins."""
    trusted, support, action, p1, _ = _standing_pair()
    path = str(tmp_path / "heads.json")
    _create_standing_store(path, trusted)
    base = ReceiverStandingView(trusted, durable_path=path)
    base.admit(p1, now=NOW)
    _, key, _ = _issuer(0x11)
    cand_a = _standing_projection(key, "test-issuer", support, action,
                                 "ACTIVE", "CORRECT", 2, p1["payload_hash"])
    # Distinct payload, same sequence and predecessor: a genuine fork race.
    # Re-sign with a different projection_id so both candidates are valid.
    cand_b_body = {k: v for k, v in cand_a.items()
                   if k not in ("payload_hash", "signature")}
    cand_b_body["projection_id"] = "correct:2-alt"
    cand_b = sign_olp_body(cand_b_body, key)

    barrier = threading.Barrier(2)
    outcomes = []

    def attempt(view, cand):
        barrier.wait()
        try:
            view.admit(cand, now=NOW)
            outcomes.append("admitted")
        except StandingProjectionError:
            outcomes.append("refused")

    v1 = ReceiverStandingView(trusted, durable_path=path)
    v2 = ReceiverStandingView(trusted, durable_path=path)
    t1 = threading.Thread(target=attempt, args=(v1, cand_a))
    t2 = threading.Thread(target=attempt, args=(v2, cand_b))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert sorted(outcomes) == ["admitted", "refused"]
    final = ReceiverStandingView(trusted, durable_path=path)
    assert final.head_hash(support, action) in (
        cand_a["payload_hash"], cand_b["payload_hash"])
    # The frontier advanced exactly one step, never sideways.
    heads = json.loads(Path(path).read_text())["heads"]
    assert len(heads) == 1


def test_adv4_stale_file_restore_outside_threat_model(tmp_path):
    """ADV4 (OUTSIDE threat model): a privileged file restore rolls the frontier back.

    This documents the boundary, not a defect: anyone who can rewrite the
    head file can already rewrite the VerifiedCommitLedger, the SessionLedger,
    and the capability database. The file's integrity is the operator's
    responsibility. The test pins the behavior so the boundary stays explicit.
    """
    trusted, support, action, p1, p2 = _standing_pair()
    path = str(tmp_path / "heads.json")
    backup = str(tmp_path / "heads.stale.json")
    _create_standing_store(path, trusted)

    view = ReceiverStandingView(trusted, durable_path=path)
    view.admit(p1, now=NOW)
    shutil.copy(path, backup)  # privileged attacker snapshots pre-revocation state
    view.admit(p2, now=NOW)
    assert view.head_hash(support, action) == p2["payload_hash"]

    shutil.copy(backup, path)  # privileged attacker restores the stale file
    restarted = ReceiverStandingView(trusted, durable_path=path)
    # Outside the threat model: the stale head is accepted, revocation lost.
    assert restarted.head_hash(support, action) == p1["payload_hash"]
    assessed = restarted.assess(p1, support_hash=support, action_hash=action, now=NOW)
    assert assessed["verified"] is True
    assert assessed["standing"] == "ACTIVE"
