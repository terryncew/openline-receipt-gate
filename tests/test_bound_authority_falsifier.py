"""Executable production falsifier for BOUND-AUTHORITY-TEST-001.

Frozen spec: ``~/workspace/bound-authority-test-001/PRODUCTION_FALSIFIER.md``
(T1-T12 plus the six-mode falsifier). Every test below binds a frozen
assertion to the implementation's real entry points, through the real
Receipt Gate admission path. This file must FAIL on b00b2ef (the layer
does not exist) and PASS on the implementation.

Notation: P = principal-p (100-unit capability), O2 = principal-o2
(own 100-unit capability). Amounts are value_cents against "cents"
capabilities (the v1 profile's explicit unit convention).
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate import capability_gate as gate
from olp_gate import capability_lifecycle as lifecycle
from olp_gate import capability_receipt as receipts
from olp_gate import capability_store as store
from olp_gate import issuance as issuance_mod
from olp_gate.crypto import public_key_hex, sign_olp_body
from olp_gate.mandate import (
    MandateSpec,
    compile_verified_commit_settings,
    validate_effect,
)
from olp_gate.mandate_gate import mandate_preflight

REPO_ROOT = Path(__file__).resolve().parent.parent
CHILD = REPO_ROOT / "tests" / "falsifier_crash_child.py"


@contextmanager
def _raises(expected):
    """Stdlib equivalent of pytest.raises for the release-check's
    pytest-free unittest environment."""
    try:
        yield
    except expected:
        return
    raise AssertionError(f"expected {expected.__name__} to be raised")


def _now():
    return datetime.now(timezone.utc)


def _unix():
    return int(_now().timestamp())


class Owner:
    def __init__(self, owner_id: str):
        self.owner_id = owner_id
        self.key = Ed25519PrivateKey.generate()
        self.pubkey = public_key_hex(self.key)


def _receipt(capability_id: str, owner: Owner, amount: int = 100):
    body = {
        "@version": receipts.RECEIPT_VERSION,
        "capability_id": capability_id,
        "issuer_owner_id": owner.owner_id,
        "issuer_public_key": owner.pubkey,
        "subject": owner.owner_id,
        "budget": {"amount": amount, "unit": "cents", "scale": 0},
        "scope": {"profile": receipts.SCOPE_PROFILE},
        "holder": {"method": receipts.HOLDER_METHOD},
        "expires_at": (_now() + timedelta(days=1)).isoformat(),
        "parent": None,
        "revocation_mode": "direct",
        "threshold": {"m": 1, "n": 1},
    }
    return sign_olp_body(body, owner.key)


def _register(db_path: str, capability_id: str, owner: Owner, amount: int = 100):
    conn = store.open_store(db_path)
    try:
        receipt = _receipt(capability_id, owner, amount)
        parsed = receipts.verify_capability_receipt(receipt, owner.owner_id, owner.pubkey)
        auth = issuance_mod.make_issuance_auth(
            capability_id, parsed["receipt_digest"], owner.owner_id, owner.key, _now()
        )
        auth_digest = issuance_mod.verify_issuance_auth(
            auth, capability_id=capability_id,
            receipt_digest=parsed["receipt_digest"],
            pinned_owner_id=owner.owner_id, pinned_pubkey_hex=owner.pubkey,
        )
        store.register_capability(conn, parsed, auth_digest, _unix())
        return parsed
    finally:
        conn.close()


def _mandate_mapping(mandate_id: str, principal_id: str, max_payment_cents: int = 60):
    return {
        "profile": "principal_mandate/v1",
        "mandate_id": mandate_id,
        "principal_id": principal_id,
        "agent_id": "agent-1",
        "purpose": "falsifier",
        "allowed_action_types": ["authorize_payment"],
        "allowed_targets": ["vendor"],
        "allowed_disclosure_classes": ["amount"],
        "forbidden_disclosure_classes": [],
        "max_settlement_cents": 0,
        "max_payment_cents": max_payment_cents,
        "delegation_allowed": False,
        "expires_at": (_now() + timedelta(days=1)).isoformat(),
        "version": "1",
    }


def _effect_mapping(
    effect_id: str, mandate_id: str, principal_id: str,
    value_cents: int = 60, action_type: str = "authorize_payment",
):
    return {
        "profile": "principal_effect/v1",
        "effect_id": effect_id,
        "mandate_id": mandate_id,
        "principal_id": principal_id,
        "agent_id": "agent-1",
        "purpose": "falsifier",
        "action_type": action_type,
        "target": "vendor",
        "disclosures": ["amount"],
        "value_cents": value_cents,
        "delegatee": None,
        "producer_model": "falsifier",
    }


def _preflight(mandate_id: str, effect_id: str, principal_id: str, **kw):
    now = _now()
    effect_kw = {k: kw.pop(k) for k in ("value_cents", "action_type") if k in kw}
    mandate = MandateSpec.from_mapping(_mandate_mapping(mandate_id, principal_id, **kw))
    effect = validate_effect(_effect_mapping(effect_id, mandate_id, principal_id, **effect_kw))
    settings = compile_verified_commit_settings(mandate, effect, now=now)
    return mandate_preflight(mandate, settings, now=now), effect


# --------------------------------------------------------------------------
# Registration / verification (profile enforcement)


def test_receipt_verification_fails_closed(tmp_path):
    owner, other = Owner("principal-p"), Owner("principal-evil")
    receipt = _receipt("cap-x", owner)
    with _raises(receipts.CapabilityReceiptError):  # wrong pinned key
        receipts.verify_capability_receipt(receipt, owner.owner_id, other.pubkey)
    tampered = json.loads(json.dumps(receipt))
    tampered["budget"]["amount"] = 999  # signature no longer binds
    with _raises(receipts.CapabilityReceiptError):
        receipts.verify_capability_receipt(tampered, owner.owner_id, owner.pubkey)
    delegated = json.loads(json.dumps(receipt))
    delegated["parent"] = "cap-parent"  # delegation excluded from the profile
    with _raises(receipts.CapabilityReceiptError):
        receipts.verify_capability_receipt(delegated, owner.owner_id, owner.pubkey)


def test_registration_idempotent_and_single_active(tmp_path):
    db = str(tmp_path / "reg.db")
    owner = Owner("principal-p")
    parsed = _register(db, "cap-p-001", owner)
    conn = store.open_store(db)
    # identical re-registration is idempotent
    auth = issuance_mod.make_issuance_auth(
        "cap-p-001", parsed["receipt_digest"], owner.owner_id, owner.key, _now()
    )
    auth_digest = issuance_mod.verify_issuance_auth(
        auth, capability_id="cap-p-001", receipt_digest=parsed["receipt_digest"],
        pinned_owner_id=owner.owner_id, pinned_pubkey_hex=owner.pubkey,
    )
    row = store.register_capability(conn, parsed, auth_digest, _unix())
    assert row["capability_id"] == "cap-p-001"
    # a second active capability for the same principal is refused
    parsed2_receipt = _receipt("cap-p-002", owner)
    parsed2 = receipts.verify_capability_receipt(
        parsed2_receipt, owner.owner_id, owner.pubkey
    )
    auth2 = issuance_mod.make_issuance_auth(
        "cap-p-002", parsed2["receipt_digest"], owner.owner_id, owner.key, _now()
    )
    auth2_digest = issuance_mod.verify_issuance_auth(
        auth2, capability_id="cap-p-002", receipt_digest=parsed2["receipt_digest"],
        pinned_owner_id=owner.owner_id, pinned_pubkey_hex=owner.pubkey,
    )
    with _raises(store.StoreError):
        store.register_capability(conn, parsed2, auth2_digest, _unix())
    conn.close()


# --------------------------------------------------------------------------
# T1-T3: reserve, concurrent attempt, refusal


def test_t1_t3_reserve_and_concurrent_refusal(tmp_path):
    db = str(tmp_path / "t1.db")
    owner = Owner("principal-p")
    _register(db, "cap-p-001", owner)
    conn = store.open_store(db)
    pre_a, eff_a = _preflight("mandate-a-001", "effect-a-001", owner.owner_id)
    res_a = gate.reserve_for_effect(conn, pre_a, eff_a, op_id="op-a", now_unix=_unix())
    assert res_a["allowed"] is True and res_a["reservation"]["token"]
    assert lifecycle.available(conn, "cap-p-001")["available"] == 40  # T1

    outcome: dict = {}

    def attempt_b():  # T2: independent executor thread, separate connection
        conn_b = store.open_store(db)
        try:
            pre_b, eff_b = _preflight("mandate-b-001", "effect-b-001", owner.owner_id)
            outcome["b"] = gate.reserve_for_effect(
                conn_b, pre_b, eff_b, op_id="op-b", now_unix=_unix()
            )
        finally:
            conn_b.close()

    worker = threading.Thread(target=attempt_b)
    worker.start()
    worker.join(timeout=30)
    assert not worker.is_alive(), "B's attempt deadlocked"
    res_b = outcome["b"]
    assert res_b["allowed"] is False  # T3
    assert any("capability_budget_exceeded" in r for r in res_b["reason_codes"])
    posture = lifecycle.available(conn, "cap-p-001")
    assert posture["available"] == 40 and posture["encumbered"] == 60
    conn.close()

# --------------------------------------------------------------------------
# T4-T8: crash at the worst point, restart, encumbrance survives, evidence


def _read_marker(child: subprocess.Popen, timeout: int = 30) -> str:
    box: dict = {}

    def _read():
        box["line"] = child.stdout.readline()

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    reader.join(timeout=timeout)
    assert not reader.is_alive(), "child never reached the effect boundary"
    return box["line"].strip()


def test_t4_t8_crash_restart_encumbrance_and_evidence(tmp_path):
    db = str(tmp_path / "crash.db")
    owner = Owner("principal-p")
    parsed = _register(db, "cap-p-001", owner)
    args = {
        "db_path": db,
        "capability_id": "cap-p-001",
        "mandate": _mandate_mapping("mandate-a-001", owner.owner_id),
        "effect": _effect_mapping("effect-a-001", "mandate-a-001", owner.owner_id),
        "op_id": "op-a",
        "entry_ttl": 3600,
        "now_unix": _unix(),
    }
    args_file = tmp_path / "args.json"
    args_file.write_text(json.dumps(args))
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    child = subprocess.Popen(
        [sys.executable, str(CHILD), str(args_file)],
        cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env,
    )
    try:
        assert _read_marker(child) == "BOUNDARY_MARKED"  # T4 setup
    finally:
        os.kill(child.pid, signal.SIGKILL)  # T4: worst point, real SIGKILL
        child.wait(timeout=30)

    conn = store.open_store(db)  # T5: restart from durable storage
    moved = lifecycle.reconcile(
        conn, _unix(), evidence_provider=lambda op: ("unknown", None)
    )
    assert any(m["op_id"] == "op-a" and m["to"] == "indeterminate" for m in moved)
    op = lifecycle.get_operation(conn, "cap-p-001", parsed["receipt_digest"], "op-a")
    assert op["state"] == "indeterminate"
    posture = lifecycle.available(conn, "cap-p-001")
    assert posture["available"] == 40 and posture["encumbered"] == 60  # T6

    pre_b, eff_b = _preflight("mandate-b-001", "effect-b-001", owner.owner_id)
    res_b = gate.reserve_for_effect(conn, pre_b, eff_b, op_id="op-b", now_unix=_unix())
    assert res_b["allowed"] is False  # T7

    with _raises(lifecycle.OperationError):  # T8a: bad token, nothing changes
        lifecycle.commit(
            conn, "cap-p-001", parsed["receipt_digest"], "op-a",
            token="00" * 16, outcome="executed",
            evidence_digest="ab" * 32, now_unix=_unix(),
        )
    assert lifecycle.available(conn, "cap-p-001")["available"] == 40
    with _raises(lifecycle.OperationError):  # T8a: malformed evidence
        lifecycle.resolve_indeterminate(
            conn, "cap-p-001", parsed["receipt_digest"], "op-a", "executed",
            evidence_digest="not-hex", resolver_id="op-1", note="x", now_unix=_unix(),
        )

    resolved = lifecycle.resolve_indeterminate(  # T8b: authenticated evidence
        conn, "cap-p-001", parsed["receipt_digest"], "op-a", "executed",
        evidence_digest="ab" * 32, resolver_id="test-operator",
        note="adapter log shows effect ref e-1 committed", now_unix=_unix(),
    )
    assert resolved["state"] == "executed"
    posture = lifecycle.available(conn, "cap-p-001")
    assert posture["committed"] == 60  # encumbered 60 -> committed 60
    assert posture["available"] == 40 and posture["encumbered"] == 0
    conn.close()


def test_reconcile_evidence_paths(tmp_path):
    db = str(tmp_path / "rec.db")
    owner = Owner("principal-p")
    parsed = _register(db, "cap-p-001", owner)
    conn = store.open_store(db)
    pre, eff = _preflight("mandate-r-001", "effect-r-001", owner.owner_id)
    res = gate.reserve_for_effect(conn, pre, eff, op_id="op-1", now_unix=_unix())
    gate.note_entry_for(conn, res["reservation"], "cap-p-001",
                        res["reservation"]["token"], _unix())
    moved = lifecycle.reconcile(
        conn, _unix(), evidence_provider=lambda op: ("executed", "aa" * 32)
    )
    assert any(m["op_id"] == "op-1" and m["to"] == "executed" for m in moved)
    assert lifecycle.available(conn, "cap-p-001")["committed"] == 60

    pre2, eff2 = _preflight("mandate-r-002", "effect-r-002", owner.owner_id,
                           value_cents=30)
    res2 = gate.reserve_for_effect(conn, pre2, eff2, op_id="op-2", now_unix=_unix())
    assert res2["allowed"] is True
    gate.note_entry_for(conn, res2["reservation"], "cap-p-001",
                        res2["reservation"]["token"], _unix())
    moved = lifecycle.reconcile(
        conn, _unix(), evidence_provider=lambda op: ("not_entered", "bb" * 32)
    )
    assert any(m["op_id"] == "op-2" and m["to"] == "not_entered" for m in moved)
    assert lifecycle.available(conn, "cap-p-001")["available"] == 40
    conn.close()


# --------------------------------------------------------------------------
# T9: authenticated non-entry proof releases the reservation


def test_t9_non_entry_proof_releases(tmp_path):
    db = str(tmp_path / "t9.db")
    owner = Owner("principal-p3")
    _register(db, "cap-p3-001", owner)
    conn = store.open_store(db)
    pre, eff = _preflight("mandate-x-001", "effect-x-001", owner.owner_id)
    res = gate.reserve_for_effect(conn, pre, eff, op_id="op-x", now_unix=_unix())
    assert res["allowed"] is True
    assert lifecycle.available(conn, "cap-p3-001")["available"] == 40
    settled = gate.settle_for(
        conn, res["reservation"], "cap-p3-001", res["reservation"]["token"],
        "not_entered", proven=True, now_unix=_unix(),
    )
    assert settled["state"] == "not_entered"
    assert lifecycle.available(conn, "cap-p3-001")["available"] == 100

    # deadline path: reserved past entry deadline, no entry -> released
    pre2, eff2 = _preflight("mandate-y-001", "effect-y-001", owner.owner_id)
    res2 = gate.reserve_for_effect(
        conn, pre2, eff2, op_id="op-y", now_unix=_unix(), entry_ttl=1
    )
    assert res2["allowed"] is True
    time.sleep(2)
    moved = lifecycle.reconcile(conn, _unix())
    assert any(m["op_id"] == "op-y" and m["to"] == "not_entered" for m in moved)
    assert lifecycle.available(conn, "cap-p3-001")["available"] == 100
    conn.close()


# --------------------------------------------------------------------------
# T10: principal independence


def test_t10_principal_independence(tmp_path):
    db = str(tmp_path / "t10.db")
    p, o2 = Owner("principal-p"), Owner("principal-o2")
    _register(db, "cap-p-001", p)
    _register(db, "cap-o2-001", o2)
    conn = store.open_store(db)
    pre_a, eff_a = _preflight("mandate-a-001", "effect-a-001", p.owner_id)
    res_a = gate.reserve_for_effect(conn, pre_a, eff_a, op_id="op-a", now_unix=_unix())
    gate.note_entry_for(conn, res_a["reservation"], "cap-p-001",
                        res_a["reservation"]["token"], _unix())
    pre_o, eff_o = _preflight(
        "mandate-o-001", "effect-o-001", o2.owner_id,
        value_cents=100, max_payment_cents=100,
    )
    res_o = gate.reserve_for_effect(conn, pre_o, eff_o, op_id="op-o", now_unix=_unix())
    assert res_o["allowed"] is True  # O2 unaffected by P's encumbrance
    assert lifecycle.available(conn, "cap-p-001")["available"] == 40
    assert lifecycle.available(conn, "cap-o2-001")["available"] == 0
    pre_b, eff_b = _preflight("mandate-b-001", "effect-b-001", p.owner_id)
    assert gate.reserve_for_effect(conn, pre_b, eff_b, op_id="op-b",
                                   now_unix=_unix())["allowed"] is False
    gate.note_entry_for(conn, res_o["reservation"], "cap-o2-001",
                        res_o["reservation"]["token"], _unix())
    gate.settle_for(conn, res_o["reservation"], "cap-o2-001",
                    res_o["reservation"]["token"], "executed",
                    evidence_digest="cd" * 32, now_unix=_unix())
    assert lifecycle.available(conn, "cap-o2-001")["committed"] == 100
    assert lifecycle.available(conn, "cap-p-001")["encumbered"] == 60
    conn.close()


# --------------------------------------------------------------------------
# T11: replay / idempotent retry cannot double-consume


def test_t11_replay_cannot_double_consume(tmp_path):
    db = str(tmp_path / "t11.db")
    owner = Owner("principal-p")
    parsed = _register(db, "cap-p-001", owner)
    conn = store.open_store(db)
    pre, eff = _preflight("mandate-r-001", "effect-r-001", owner.owner_id)
    res = gate.reserve_for_effect(conn, pre, eff, op_id="op-r", now_unix=_unix())
    token = res["reservation"]["token"]
    res2 = gate.reserve_for_effect(conn, pre, eff, op_id="op-r", now_unix=_unix())
    assert res2["allowed"] is True
    assert res2["reservation"]["duplicate"] is True
    assert res2["reservation"]["token"] is None  # token issued exactly once
    assert lifecycle.available(conn, "cap-p-001")["available"] == 40
    with _raises(lifecycle.OperationError):  # op key reuse, different terms
        lifecycle.reserve(conn, parsed, "op-r", 50, "different", "different", _unix())
    gate.note_entry_for(conn, res["reservation"], "cap-p-001", token, _unix())
    gate.settle_for(conn, res["reservation"], "cap-p-001", token, "executed",
                    evidence_digest="ef" * 32, now_unix=_unix())
    with _raises(lifecycle.OperationError):  # duplicate commit rejected
        gate.settle_for(conn, res["reservation"], "cap-p-001", token, "executed",
                        evidence_digest="ef" * 32, now_unix=_unix())
    posture = lifecycle.available(conn, "cap-p-001")
    assert posture["committed"] == 60 and posture["available"] == 40
    conn.close()


# --------------------------------------------------------------------------
# T12: mandate DENY still wins


def test_t12_mandate_deny_still_wins(tmp_path):
    db = str(tmp_path / "t12.db")
    owner = Owner("principal-p")
    _register(db, "cap-p-001", owner)
    conn = store.open_store(db)
    # the existing path raises on denial before the capability layer runs
    with _raises(PermissionError):
        _preflight("mandate-d-001", "effect-d-001", owner.owner_id,
                   action_type="send")  # not in allowed_action_types
    # and the gate itself never widens a deny into an allowed action
    eff = _effect_mapping("effect-d-001", "mandate-d-001", owner.owner_id,
                         action_type="send")
    denied = {"allowed": False, "reason_codes": ["action_not_allowed"],
              "evidence": {"principal_id": owner.owner_id}}
    res = gate.reserve_for_effect(conn, denied, eff, op_id="op-d", now_unix=_unix())
    assert res["allowed"] is False
    cur = conn.execute("SELECT COUNT(*) FROM operations")
    assert cur.fetchone()[0] == 0  # no reservation created for a denied effect
    assert lifecycle.available(conn, "cap-p-001")["available"] == 100
    conn.close()
