"""Unit tests for the TRUST-ROOT-SUCCESSION-001 primitive.

In-process, deterministic. Covers issue/validate roundtrip, signer,
sequence, predecessor, no-op, replay, durable restart, and the
historical-verification distinction in assess().
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import pytest
except ImportError:  # CI release-check runs without pytest installed
    pytest = None
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate._durable_heads import DurableHeadStore
from olp_gate.crypto import public_key_hex
from olp_gate.mandate_owner import (
    TRUST_ROOT_SUCCESSION_SCHEMA,
    MandateAuthorityError,
    MandateOwnerView,
    create_trust_root_store,
    issue_mandate_authorization,
    issue_owner_trust_root_succession,
    validate_owner_trust_root_succession,
)

SLOT = "owner/default"
OWNER_ID = "owner"
NOW = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)
LONG = timedelta(days=3650)


def _keys():
    priv = [Ed25519PrivateKey.generate() for _ in range(3)]
    return priv, [public_key_hex(k) for k in priv]


def _succession(signer_key, successor_pub, seq, pred, issued=NOW):
    return issue_owner_trust_root_succession(
        slot_id=SLOT,
        owner_id=OWNER_ID,
        successor_owner_id=OWNER_ID,
        successor_public_key=successor_pub,
        succession_sequence=seq,
        predecessor_succession_hash=pred,
        issued_at=issued - timedelta(seconds=10),
        expires_at=issued + LONG,
        key=signer_key,
    )


def _mandate():
    return {
        "profile": "principal_mandate/v1",
        "mandate_id": "trs-test-mandate",
        "principal_id": OWNER_ID,
        "agent_id": "trs-test-agent",
        "purpose": "unit test",
        "allowed_action_types": ["authorize_payment"],
        "allowed_targets": ["payments://ledger"],
        "allowed_disclosure_classes": [],
        "forbidden_disclosure_classes": [],
        "max_settlement_cents": 0,
        "max_payment_cents": 100,
        "delegation_allowed": False,
        "expires_at": "2030-01-01T00:00:00Z",
        "version": "v1",
    }


def _auth(signer_key, state, sequence, predecessor, issued=NOW):
    return issue_mandate_authorization(
        slot_id=SLOT,
        owner_id=OWNER_ID,
        mandate=_mandate(),
        state=state,
        sequence=sequence,
        predecessor_hash=predecessor,
        issued_at=issued - timedelta(seconds=10),
        expires_at=issued + LONG,
        key=signer_key,
    )


def _view(tmp_path, pub_a, durable=True):
    slots = {SLOT: {"owner_id": OWNER_ID, "public_key": pub_a}}
    kw = {}
    if durable:
        tr = str(tmp_path / "trust_roots.json")
        hd = str(tmp_path / "heads.json")
        create_trust_root_store(tr, slots)
        DurableHeadStore.create(
            hd, {"view": "mandate_owner/v1", "slots": slots}
        )
        kw = {"durable_path": hd, "trust_root_path": tr}
    return MandateOwnerView(slots, **kw)


def test_issue_validate_roundtrip():
    priv, pubs = _keys()
    ev = _succession(priv[0], pubs[1], 1, None)
    assert ev["schema"] == TRUST_ROOT_SUCCESSION_SCHEMA
    checked = validate_owner_trust_root_succession(
        ev, expected_slot_id=SLOT, expected_owner_id=OWNER_ID,
        expected_public_key=pubs[0], now=NOW,
    )
    assert checked["successor_public_key"] == pubs[1]


def test_wrong_signer_rejected():
    priv, pubs = _keys()
    ev = _succession(priv[1], pubs[2], 1, None)  # signed by B, not current A
    with pytest.raises(MandateAuthorityError) as e:
        validate_owner_trust_root_succession(
            ev, expected_slot_id=SLOT, expected_owner_id=OWNER_ID,
            expected_public_key=pubs[0], now=NOW,
        )
    assert "trust_root_succession_signer_not_current_owner" in str(e.value)


def test_self_declared_successor_rejected_on_admit(tmp_path):
    priv, pubs = _keys()
    view = _view(tmp_path, pubs[0], durable=False)
    ev = _succession(priv[2], pubs[2], 1, None)  # C signs itself in
    with pytest.raises(MandateAuthorityError) as e:
        view.admit_trust_root_succession(ev, now=NOW)
    assert "trust_root_succession_signer_not_current_owner" in str(e.value)
    assert view.current_owner(SLOT)["public_key"] == pubs[0]


def test_admit_advances_single_current_owner(tmp_path):
    priv, pubs = _keys()
    view = _view(tmp_path, pubs[0], durable=False)
    ev = _succession(priv[0], pubs[1], 1, None)
    adm = view.admit_trust_root_succession(ev, now=NOW)
    assert adm["admitted"] is True
    assert adm["previous_public_key"] == pubs[0]
    assert view.current_owner(SLOT)["public_key"] == pubs[1]
    assert view.succession_sequence(SLOT) == 1
    assert len(view.key_schedule(SLOT)) == 2


def test_duplicate_sequence_refused(tmp_path):
    priv, pubs = _keys()
    view = _view(tmp_path, pubs[0], durable=False)
    ev = _succession(priv[0], pubs[1], 1, None)
    adm = view.admit_trust_root_succession(ev, now=NOW)
    dup = _succession(priv[1], pubs[2], 1, None)
    with pytest.raises(MandateAuthorityError) as e:
        view.admit_trust_root_succession(dup, now=NOW)
    assert "trust_root_succession_sequence_invalid" in str(e.value)
    assert view.succession_sequence(SLOT) == 1


def test_wrong_predecessor_refused(tmp_path):
    priv, pubs = _keys()
    view = _view(tmp_path, pubs[0], durable=False)
    ev = _succession(priv[0], pubs[1], 1, None)
    view.admit_trust_root_succession(ev, now=NOW)
    bad = _succession(priv[1], pubs[2], 2, "00" * 32)
    with pytest.raises(MandateAuthorityError) as e:
        view.admit_trust_root_succession(bad, now=NOW)
    assert "trust_root_succession_predecessor_mismatch" in str(e.value)


def test_old_owner_cannot_forge_succession(tmp_path):
    priv, pubs = _keys()
    view = _view(tmp_path, pubs[0], durable=False)
    ev = _succession(priv[0], pubs[1], 1, None)
    adm = view.admit_trust_root_succession(ev, now=NOW)
    forge = _succession(priv[0], pubs[2], 2, adm["event_hash"])
    with pytest.raises(MandateAuthorityError) as e:
        view.admit_trust_root_succession(forge, now=NOW)
    assert "trust_root_succession_signer_not_current_owner" in str(e.value)


def test_noop_key_change_rejected():
    priv, pubs = _keys()
    # issue-time has no current-key context, so the validate path enforces it
    ev = issue_owner_trust_root_succession(
        slot_id=SLOT, owner_id=OWNER_ID, successor_owner_id=OWNER_ID,
        successor_public_key=pubs[0], succession_sequence=1,
        predecessor_succession_hash=None,
        issued_at=NOW - timedelta(seconds=10), expires_at=NOW + LONG,
        key=priv[0],
    )
    with pytest.raises(MandateAuthorityError) as e2:
        validate_owner_trust_root_succession(
            ev, expected_slot_id=SLOT, expected_owner_id=OWNER_ID,
            expected_public_key=pubs[0], now=NOW,
        )
    assert "trust_root_succession_key_unchanged" in str(e2.value)


def test_replay_refused(tmp_path):
    priv, pubs = _keys()
    view = _view(tmp_path, pubs[0], durable=False)
    ev = _succession(priv[0], pubs[1], 1, None)
    view.admit_trust_root_succession(ev, now=NOW)
    with pytest.raises(MandateAuthorityError):
        view.admit_trust_root_succession(ev, now=NOW)
    assert view.succession_sequence(SLOT) == 1


def test_durable_restart_reconstructs_current(tmp_path):
    priv, pubs = _keys()
    view = _view(tmp_path, pubs[0], durable=True)
    ev = _succession(priv[0], pubs[1], 1, None)
    view.admit_trust_root_succession(ev, now=NOW)
    slots = {SLOT: {"owner_id": OWNER_ID, "public_key": pubs[0]}}
    view2 = MandateOwnerView(
        slots,
        durable_path=str(tmp_path / "heads.json"),
        trust_root_path=str(tmp_path / "trust_roots.json"),
    )
    assert view2.current_owner(SLOT)["public_key"] == pubs[1]
    assert view2.succession_sequence(SLOT) == 1
    assert len(view2.key_schedule(SLOT)) == 2


def test_trust_root_store_identity_mismatch_fail_closed(tmp_path):
    priv, pubs = _keys()
    view = _view(tmp_path, pubs[0], durable=True)
    slots = {SLOT: {"owner_id": OWNER_ID, "public_key": pubs[1]}}  # different genesis
    with pytest.raises(Exception):
        MandateOwnerView(
            slots,
            durable_path=str(tmp_path / "heads.json"),
            trust_root_path=str(tmp_path / "trust_roots.json"),
        )


def test_old_key_auth_rejected_new_key_accepted(tmp_path):
    priv, pubs = _keys()
    view = _view(tmp_path, pubs[0], durable=False)
    a1 = _auth(priv[0], "ACTIVE", 1, None)
    view.admit(a1, _mandate(), now=NOW)
    assert view.status(SLOT, now=NOW) == "ACTIVE"
    ev = _succession(priv[0], pubs[1], 1, None)
    view.admit_trust_root_succession(ev, now=NOW)
    a2 = _auth(priv[0], "ACTIVE", 2, a1["payload_hash"])
    with pytest.raises(MandateAuthorityError) as e:
        view.admit(a2, _mandate(), now=NOW)
    assert "mandate_authorization_owner_key_mismatch" in str(e.value)
    b2 = _auth(priv[1], "ACTIVE", 2, a1["payload_hash"])
    adm = view.admit(b2, _mandate(), now=NOW)
    assert adm["admitted"] is True
    assert view.status(SLOT, now=NOW) == "ACTIVE"


def test_assess_historical_distinction(tmp_path):
    priv, pubs = _keys()
    view = _view(tmp_path, pubs[0], durable=False)
    a1 = _auth(priv[0], "ACTIVE", 1, None)
    view.admit(a1, _mandate(), now=NOW)
    ev = _succession(priv[0], pubs[1], 1, None)
    view.admit_trust_root_succession(ev, now=NOW)
    b2 = _auth(priv[1], "ACTIVE", 2, a1["payload_hash"])
    view.admit(b2, _mandate(), now=NOW)

    old = view.assess(a1, _mandate(), now=NOW)
    assert old["verified"] is True
    assert old["current"] is False
    assert old["reason_codes"] == ["trust_root_succession_historical_key"]
    assert old["historical_public_key"] == pubs[0]

    cur = view.assess(b2, _mandate(), now=NOW)
    assert cur["verified"] is True
    assert cur["current"] is True

    priv3, pubs3 = [Ed25519PrivateKey.generate()], [None]
    pubs3[0] = public_key_hex(priv3[0])
    stranger = _auth(priv3[0], "ACTIVE", 9, b2["payload_hash"])
    bad = view.assess(stranger, _mandate(), now=NOW)
    assert bad["verified"] is False
    assert bad["current"] is False


def test_expired_succession_event_rejected():
    priv, pubs = _keys()
    ev = _succession(priv[0], pubs[1], 1, None,
                     issued=NOW - timedelta(days=4000))
    with pytest.raises(MandateAuthorityError) as e:
        validate_owner_trust_root_succession(
            ev, expected_slot_id=SLOT, expected_owner_id=OWNER_ID,
            expected_public_key=pubs[0], now=NOW,
        )
    assert "trust_root_succession_expired" in str(e.value)


def test_future_succession_event_rejected():
    priv, pubs = _keys()
    ev = _succession(priv[0], pubs[1], 1, None,
                     issued=NOW + timedelta(days=1))
    with pytest.raises(MandateAuthorityError) as e:
        validate_owner_trust_root_succession(
            ev, expected_slot_id=SLOT, expected_owner_id=OWNER_ID,
            expected_public_key=pubs[0], now=NOW,
        )
    assert "trust_root_succession_from_future" in str(e.value)
