"""Apparatus qualification for JEV-WITNESS-VERCEL-002 (pre-contact).

All fixtures are SYNTHETIC v1/evaluate-shaped payloads, labeled as such. They
qualify the apparatus only: signature, canonicalization, action binding,
policy bands, standing/revocation composition, mutation detection, replay
semantics, v1/evaluate request construction, generationId request-id
extraction, and ZDR opt-in. No network, no key, no Jev contact.
"""

from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from olp_gate.crypto import public_key_hex  # noqa: E402
from olp_gate.integrations.jev_vercel_v2 import (  # noqa: E402
    GATEWAY_EVALUATE_PATH,
    GATEWAY_EVALUATE_URL,
    GATEWAY_HOST,
    JEV_MODEL_ID,
    JEV_VERCEL_EVIDENCE_SCHEMA,
    JevVercelEvidenceError,
    JevVercelEvidenceLedger,
    JevVercelWitnessPolicy,
    build_evaluate_request,
    build_jev_vercel_evidence,
    canonical_action_hash,
    evaluate_jev_vercel_witness,
    extract_jev_signal,
    extract_request_id,
    extract_request_id_v2,
    verify_jev_vercel_evidence,
)

SYNTHETIC = True  # every fixture below is synthetic; never a Jev judgment

STATE = {"action": "write marker file marker-v1.txt in isolated workspace"}
QUESTIONS = {
    "proceed": {
        "type": "boolean",
        "instructions": (
            "Two plus two equals four. The proposed action writes one marker file "
            "with fixed content into an isolated demo directory; nothing else "
            "changes. Should the proposed harmless marker-file write proceed?"
        ),
        "criteria": {
            "true": "The write should proceed.",
            "false": "The write should not proceed.",
        },
    }
}
ACTION = {
    "kind": "write_marker_file",
    "filename": "marker-v1.txt",
    "content": "jev-witness-vercel-002 marker",
}
ACTION_B = {
    "kind": "write_marker_file",
    "filename": "marker-other.txt",
    "content": "jev-witness-vercel-002 marker",
}


def _synthetic_response(probability: float = 0.99) -> dict:
    return {
        "answers": {"proceed": {"type": "boolean", "probability": probability}},
        "usage": {"inputTokens": 120, "outputTokens": 0},
        "warnings": [],
        "providerMetadata": {
            "typesafe": {"judgment": "synthetic-fixture"},
            "gateway": {"generationId": "synthetic-gen-1"},
        },
    }


def _keys():
    witness_key = Ed25519PrivateKey.generate()
    return witness_key, public_key_hex(witness_key)


def _evidence(probability: float = 0.99, action: dict | None = None, **kw):
    witness_key, trusted = _keys()
    receipt = build_jev_vercel_evidence(
        state=STATE,
        questions=QUESTIONS,
        response=_synthetic_response(probability),
        response_headers={"x-request-id": "synthetic-req-1"},
        action=action or ACTION,
        witness_key=witness_key,
        request_id="synthetic-gen-1",
        **kw,
    )
    return receipt, witness_key, trusted


def _allow(_: None = None):
    return {"allowed": True, "standing": "ACTIVE", "terminal": False, "reason_codes": []}


def _deny_revoked():
    return {
        "allowed": False,
        "standing": "INACTIVE",
        "terminal": False,
        "reason_codes": ["standing_not_active"],
    }


def test_build_evaluate_request_shape():
    body = build_evaluate_request(STATE, QUESTIONS)
    assert body["model"] == JEV_MODEL_ID
    assert body["state"] == STATE
    assert body["questions"] == QUESTIONS
    assert body["providerOptions"]["gateway"]["zeroDataRetention"] is True


def test_evaluate_route_constants():
    assert GATEWAY_HOST == "ai-gateway.vercel.sh"
    assert GATEWAY_EVALUATE_PATH == "/v1/evaluate"
    assert GATEWAY_EVALUATE_URL == "https://ai-gateway.vercel.sh/v1/evaluate"
    assert JEV_MODEL_ID == "typesafe-ai/jev"


def test_request_id_generation_id():
    assert extract_request_id_v2(_synthetic_response()) == "synthetic-gen-1"
    assert extract_request_id_v2({"answers": {}}) is None
    assert extract_request_id_v2({"providerMetadata": {"gateway": {}}}) is None
    assert extract_request_id_v2({"providerMetadata": {"gateway": {"generationId": 7}}}) is None
    assert extract_request_id_v2(None) is None


def test_gateway_surface_identifiers():
    receipt, _, _ = _evidence()
    jev = receipt["jev"]
    assert jev["evaluate_path"] == "/v1/evaluate"
    assert jev["gateway_host"] == "ai-gateway.vercel.sh"
    assert jev["zero_data_retention_requested"] is True
    assert jev["evaluated_at_source"] == "witness_clock"
    assert "gateway_protocol_version" not in jev
    assert "eval_spec_version" not in jev


def test_build_verify_round_trip():
    assert SYNTHETIC
    receipt, witness_key, trusted = _evidence()
    assert receipt["schema"] == JEV_VERCEL_EVIDENCE_SCHEMA
    assert receipt["jev"]["surface"] == "vercel-ai-gateway"
    assert receipt["jev"]["model_requested"] == "typesafe-ai/jev"
    verified = verify_jev_vercel_evidence(
        receipt, expected_action=ACTION, trusted_witness_key=trusted
    )
    assert verified["evidence_id"] == receipt["evidence_id"]


def test_policy_id_v2_default():
    assert JevVercelWitnessPolicy().policy_id == "jev-witness-vercel-002-demo-policy-v1"


def test_signal_boolean():
    signal = extract_jev_signal(_synthetic_response(0.987), "proceed")
    assert signal == pytest.approx(0.987)


def test_signal_choice_requires_option():
    response = {
        "answers": {
            "proceed": {
                "type": "choice",
                "choice": "yes",
                "probabilities": {"yes": 0.97, "no": 0.03},
            }
        }
    }
    assert extract_jev_signal(response, "proceed", signal_option="yes") == pytest.approx(0.97)
    with pytest.raises(JevVercelEvidenceError):
        extract_jev_signal(response, "proceed")


def test_signal_score_refused():
    response = {"answers": {"proceed": {"type": "score", "score": 1.5}}}
    with pytest.raises(JevVercelEvidenceError):
        extract_jev_signal(response, "proceed")


def test_policy_bands():
    policy = JevVercelWitnessPolicy()
    assert policy.decide_signal(0.99) == "COMMIT"
    assert policy.decide_signal(0.95) == "COMMIT"
    assert policy.decide_signal(0.85) == "QUARANTINE"
    assert policy.decide_signal(0.80) == "QUARANTINE"
    assert policy.decide_signal(0.79) == "DENY"


def test_evaluate_commit_high_confidence(tmp_path):
    receipt, witness_key, trusted = _evidence(0.99)
    decision = evaluate_jev_vercel_witness(
        action=ACTION,
        evidence_receipt=receipt,
        policy=JevVercelWitnessPolicy(),
        authority_check=_allow,
        witness_key=witness_key,
        trusted_witness_key=trusted,
        decision_path=tmp_path / "decisions.jsonl",
    )
    assert decision["decision"] == "COMMIT"
    assert decision["policy_id"] == "jev-witness-vercel-002-demo-policy-v1"
    assert decision["signal"] == repr(0.99)


def test_evaluate_quarantine_mid_band(tmp_path):
    receipt, witness_key, trusted = _evidence(0.85)
    decision = evaluate_jev_vercel_witness(
        action=ACTION,
        evidence_receipt=receipt,
        policy=JevVercelWitnessPolicy(),
        authority_check=_allow,
        witness_key=witness_key,
        trusted_witness_key=trusted,
        decision_path=tmp_path / "decisions.jsonl",
    )
    assert decision["decision"] == "QUARANTINE"


def test_evaluate_deny_low_signal(tmp_path):
    receipt, witness_key, trusted = _evidence(0.10)
    decision = evaluate_jev_vercel_witness(
        action=ACTION,
        evidence_receipt=receipt,
        policy=JevVercelWitnessPolicy(),
        authority_check=_allow,
        witness_key=witness_key,
        trusted_witness_key=trusted,
        decision_path=tmp_path / "decisions.jsonl",
    )
    assert decision["decision"] == "DENY"


def test_evaluate_deny_after_revocation(tmp_path):
    # V2: same authentic evidence, authority revoked -> DENY; receipt verifies.
    receipt, witness_key, trusted = _evidence(0.99)
    verify_jev_vercel_evidence(receipt, expected_action=ACTION, trusted_witness_key=trusted)
    decision = evaluate_jev_vercel_witness(
        action=ACTION,
        evidence_receipt=receipt,
        policy=JevVercelWitnessPolicy(),
        authority_check=_deny_revoked,
        witness_key=witness_key,
        trusted_witness_key=trusted,
        decision_path=tmp_path / "decisions.jsonl",
    )
    assert decision["decision"] == "DENY"
    assert any(code.startswith("authority:") for code in decision["reason_codes"])


def test_action_substitution_refused(tmp_path):
    # V3: evidence bound to action A presented for action B -> DENY.
    receipt, witness_key, trusted = _evidence(0.99, action=ACTION)
    decision = evaluate_jev_vercel_witness(
        action=ACTION_B,
        evidence_receipt=receipt,
        policy=JevVercelWitnessPolicy(),
        authority_check=_allow,
        witness_key=witness_key,
        trusted_witness_key=trusted,
        decision_path=tmp_path / "decisions.jsonl",
    )
    assert decision["decision"] == "DENY"
    assert "jev_vercel_evidence_action_binding_mismatch" in decision["reason_codes"]


def test_evidence_mutation_detected(tmp_path):
    # V4: mutated state bytes -> signature verification failure -> DENY.
    receipt, witness_key, trusted = _evidence(0.99)
    mutated = copy.deepcopy(receipt)
    mutated["jev"]["state"] = {"action": "MUTATED"}
    with pytest.raises(JevVercelEvidenceError):
        verify_jev_vercel_evidence(mutated, expected_action=ACTION, trusted_witness_key=trusted)
    decision = evaluate_jev_vercel_witness(
        action=ACTION,
        evidence_receipt=mutated,
        policy=JevVercelWitnessPolicy(),
        authority_check=_allow,
        witness_key=witness_key,
        trusted_witness_key=trusted,
        decision_path=tmp_path / "decisions.jsonl",
    )
    assert decision["decision"] == "DENY"


def test_replay_refused(tmp_path):
    # V5: one-use ledger refuses the second consumption.
    receipt, _, _ = _evidence(0.99)
    ledger = JevVercelEvidenceLedger(tmp_path / "ledger.jsonl")
    assert ledger.consume(receipt["evidence_id"], decision_hash="abc") is True
    assert ledger.consume(receipt["evidence_id"], decision_hash="abc") is False
    assert ledger.is_consumed(receipt["evidence_id"]) is True


def test_expired_evidence_denied(tmp_path):
    witness_key, trusted = _keys()
    old = datetime.now(timezone.utc) - timedelta(seconds=3600)
    receipt = build_jev_vercel_evidence(
        state=STATE,
        questions=QUESTIONS,
        response=_synthetic_response(0.99),
        action=ACTION,
        witness_key=witness_key,
        evaluated_at=old,
    )
    with pytest.raises(JevVercelEvidenceError) as exc:
        verify_jev_vercel_evidence(receipt, expected_action=ACTION, trusted_witness_key=trusted)
    assert "expired" in str(exc.value)


def test_wrong_witness_key_rejected():
    receipt, _, _ = _evidence(0.99)
    _, other_trusted = _keys()
    with pytest.raises(JevVercelEvidenceError):
        verify_jev_vercel_evidence(
            receipt, expected_action=ACTION, trusted_witness_key=other_trusted
        )


def test_request_id_extraction_headers():
    assert extract_request_id({"X-Request-Id": "abc"}) == "abc"
    assert extract_request_id({"x-typesafe-request-id": "t-1"}) == "t-1"
    assert extract_request_id({"date": "today"}) is None
    assert extract_request_id(None) is None


def test_missing_authority_check_fails_closed(tmp_path):
    receipt, witness_key, trusted = _evidence(0.99)
    with pytest.raises(JevVercelEvidenceError):
        evaluate_jev_vercel_witness(
            action=ACTION,
            evidence_receipt=receipt,
            policy=JevVercelWitnessPolicy(),
            authority_check=None,
            witness_key=witness_key,
            trusted_witness_key=trusted,
            decision_path=tmp_path / "decisions.jsonl",
        )


def test_canonical_action_hash_stable():
    assert canonical_action_hash(ACTION) == canonical_action_hash(dict(ACTION))
    assert canonical_action_hash(ACTION) != canonical_action_hash(ACTION_B)


def test_decision_receipt_logged(tmp_path):
    receipt, witness_key, trusted = _evidence(0.99)
    path = tmp_path / "decisions.jsonl"
    evaluate_jev_vercel_witness(
        action=ACTION,
        evidence_receipt=receipt,
        policy=JevVercelWitnessPolicy(),
        authority_check=_allow,
        witness_key=witness_key,
        trusted_witness_key=trusted,
        decision_path=path,
    )
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["decision"] == "COMMIT"
