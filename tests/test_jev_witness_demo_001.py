"""Apparatus qualification for JEV-WITNESS-DEMO-001 (pre-contact).

All fixtures are SYNTHETIC v1/evaluate-shaped payloads, labeled as such. They
qualify the apparatus only: the second risk-class receiver policy
(COMMIT >= 0.80, illustrative, no quarantine band), the "jev-ok" protected
action, signature/canonicalization/action binding, standing/revocation
composition, mutation detection, replay semantics, v1/evaluate request
construction (disallowPromptTraining, NO zeroDataRetention), generationId
request-id extraction, and both terminal branches (PASS_JEV_WITNESS_DEMO_001
and BELOW_DEMO_THRESHOLD) via run_sequence with synthetic judgments.
No network, no key, no Jev contact.

DATA HYGIENE: this label uses synthetic non-sensitive fixture data only. This
run does NOT establish a ZDR execution path.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from olp_gate.crypto import public_key_hex  # noqa: E402
from olp_gate.integrations.jev_vercel_v3 import (  # noqa: E402
    GATEWAY_EVALUATE_URL,
    JEV_MODEL_ID,
    JevVercelEvidenceError,
    JevVercelEvidenceLedger,
    JevVercelWitnessPolicy,
    build_evaluate_request,
    build_jev_vercel_evidence,
    evaluate_jev_vercel_witness,
    extract_jev_signal,
    extract_request_id_v2,
    verify_jev_vercel_evidence,
)

HARNESS_DIR = REPO_ROOT / "experiments" / "jev-witness-demo-001" / "harness"
if str(HARNESS_DIR) not in sys.path:
    sys.path.insert(0, str(HARNESS_DIR))

from run_acceptance import (  # noqa: E402
    ACTION_B,
    ACTION_V1,
    POLICY,
    expected_band_disposition,
    run_sequence,
)

SYNTHETIC = True  # every fixture below is synthetic; never a Jev judgment

DEMO_ACTION = {
    "kind": "write_marker_file",
    "filename": "jev-ok.txt",
    "content": "jev-ok",
}


def _synthetic_response(probability: float) -> dict:
    return {
        "answers": {
            "proceed": {"type": "boolean", "probability": probability}
        },
        "usage": {"inputTokens": 369, "outputTokens": 21},
        "warnings": [],
        "providerMetadata": {
            "gateway": {"generationId": "gen_SYNTHETIC"},
            "typesafe": {"confidence": {}},
        },
    }


def _synthetic_headers() -> dict:
    return {"content-type": "application/json"}


def test_demo_policy_is_the_illustrative_second_risk_class():
    # Frozen demo policy: COMMIT >= 0.80, no quarantine band. The 003 policy
    # (0.95) coexists unchanged; this one does not replace it.
    assert POLICY.policy_id == "jev-witness-demo-001-product-demo-policy-v1"
    assert POLICY.commit_threshold == 0.80
    assert POLICY.review_band_low == 0.80
    assert POLICY.signal_question == "proceed"
    assert POLICY.decide_signal(0.80) == "COMMIT"
    assert POLICY.decide_signal(0.95) == "COMMIT"
    assert POLICY.decide_signal(0.799) == "DENY"
    assert expected_band_disposition(0.80) == "COMMIT"
    assert expected_band_disposition(0.799) == "DENY"


def test_demo_action_is_the_frozen_trivial_reversible_write():
    assert ACTION_V1 == DEMO_ACTION
    assert ACTION_V1["content"] == "jev-ok"
    assert ACTION_V1["kind"] == "write_marker_file"
    assert ACTION_B["content"] == "jev-ok"
    assert ACTION_B["filename"] != ACTION_V1["filename"]


def test_frozen_request_sends_disallow_prompt_training_not_zdr():
    request = build_evaluate_request(
        state={"action": "synthetic"},
        questions={
            "proceed": {"type": "boolean", "instructions": "synthetic"}
        },
    )
    assert request["model"] == JEV_MODEL_ID
    assert request["providerOptions"]["gateway"]["disallowPromptTraining"] is True
    assert "zeroDataRetention" not in request["providerOptions"]["gateway"]


def test_generation_id_extraction_from_synthetic_body():
    response = _synthetic_response(0.9)
    assert extract_request_id_v2(response) == "gen_SYNTHETIC"
    assert extract_request_id_v2({"answers": {"proceed": {"type": "boolean", "probability": 0.9}}}) is None


def test_evidence_binds_demo_action_and_request_flags():
    witness_key = Ed25519PrivateKey.generate()
    trusted = public_key_hex(witness_key.public_key())
    response = _synthetic_response(0.9)
    evidence = build_jev_vercel_evidence(
        state={"action": "synthetic"},
        questions={
            "proceed": {"type": "boolean", "instructions": "synthetic"}
        },
        response=response,
        response_headers=_synthetic_headers(),
        action=DEMO_ACTION,
        witness_key=witness_key,
        model_requested=JEV_MODEL_ID,
        model_reported=JEV_MODEL_ID,
        request_id=extract_request_id_v2(response),
        zero_data_retention_requested=False,
        disallow_prompt_training_requested=True,
    )
    verified = verify_jev_vercel_evidence(
        evidence, expected_action=DEMO_ACTION, trusted_witness_key=trusted
    )
    assert verified["jev"]["zero_data_retention_requested"] is False
    assert verified["jev"]["disallow_prompt_training_requested"] is True
    assert extract_jev_signal(verified["jev"]["response"], "proceed") == 0.9


def test_stub_qualification_commit_branch(tmp_path):
    """Synthetic 0.91 judgment: full V1-V5, terminal PASS_JEV_WITNESS_DEMO_001."""
    assert SYNTHETIC
    run_dir = tmp_path / "run-commit"
    summary = run_sequence(
        _synthetic_response(0.91), _synthetic_headers(), run_dir, verbose=False
    )
    assert summary["terminal"] == "PASS_JEV_WITNESS_DEMO_001"
    assert summary["signal_v1"] == 0.91
    assert summary["effect_count"] == 1
    for case in ("V1", "V2", "V3", "V4", "V5"):
        assert summary["cases"][case]["verdict"] == "PASS", case
    marker = run_dir / "protected_workspace" / "jev-ok.txt"
    assert marker.read_text(encoding="utf-8") == "jev-ok"
    assert not (run_dir / "protected_workspace" / ACTION_B["filename"]).exists()
    public = summary["public_output"]
    assert public[0] == "Jev: proceed, 0.91"
    assert public[1] == "Receiver policy: COMMIT"
    assert public[2] == "Effect: executed"
    assert "Owner revoked the agent." in public
    assert "Same Jev judgment. Same action." in public
    assert "Receiver: DENY" in public
    assert "Effect: not executed" in public


def test_stub_qualification_below_threshold_branch(tmp_path):
    """Synthetic 0.55 judgment: V1 frozen honestly, terminal BELOW_DEMO_THRESHOLD."""
    assert SYNTHETIC
    run_dir = tmp_path / "run-below"
    summary = run_sequence(
        _synthetic_response(0.55), _synthetic_headers(), run_dir, verbose=False
    )
    assert summary["terminal"] == "BELOW_DEMO_THRESHOLD"
    assert summary["signal_v1"] == 0.55
    assert summary["below_demo_threshold"] is True
    assert summary["effect_count"] == 0
    assert summary["cases"]["V1"]["verdict"] == "PASS"  # policy mapping for the band
    assert summary["cases"]["V2"]["verdict"] == "PASS"
    assert summary["cases"]["V3"]["verdict"] == "PASS"
    assert summary["cases"]["V4"]["verdict"] == "PASS"
    assert summary["cases"]["V5"]["verdict"] == "NOT_APPLICABLE"
    assert not (run_dir / "protected_workspace" / "jev-ok.txt").exists()


def test_stub_mutation_fails_closed(tmp_path):
    witness_key = Ed25519PrivateKey.generate()
    trusted = public_key_hex(witness_key.public_key())
    evidence = build_jev_vercel_evidence(
        state={"action": "synthetic"},
        questions={"proceed": {"type": "boolean", "instructions": "synthetic"}},
        response=_synthetic_response(0.9),
        response_headers=_synthetic_headers(),
        action=DEMO_ACTION,
        witness_key=witness_key,
    )
    mutated = copy.deepcopy(evidence)
    mutated["jev"]["state"] = {"action": "MUTATED"}
    try:
        verify_jev_vercel_evidence(
            mutated, expected_action=DEMO_ACTION, trusted_witness_key=trusted
        )
        assert False, "mutated evidence must not verify"
    except JevVercelEvidenceError:
        pass


def test_stub_ledger_one_use(tmp_path):
    ledger = JevVercelEvidenceLedger(tmp_path / "consumed.jsonl")
    assert ledger.consume("abc123", decision_hash="def456") is True
    assert ledger.consume("abc123", decision_hash="def456") is False
    assert ledger.is_consumed("abc123") is True
