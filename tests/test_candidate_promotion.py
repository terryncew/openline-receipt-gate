from copy import deepcopy

from olp_gate.candidate_promotion import (
    AssayReceipt,
    CandidateIdentity,
    DimensionRule,
    PromotionDecision,
    PromotionPolicy,
    evaluate_candidate,
    to_receipt_gate_policy_mapping,
)

SEQ = "a" * 64
RAW = "b" * 64
C = CandidateIdentity("cand-1", SEQ, "igg1", "batch-7")
P = PromotionPolicy(
    policy_id="candidate_promotion.cpg001",
    version="1.0.0",
    effective_at="2026-08-23T00:00:00Z",
    target="target-x",
    rules=(
        DimensionRule("HIC", "<=", 10.0, "min", ("HIC-v1",), 365),
        DimensionRule("SEC_AGG", "<=", 5.0, "%", ("SEC-v1",), 365),
    ),
)


def r(assay, value, *, status="CURRENT", method=None, observed="2026-08-20T00:00:00Z", **kw):
    return AssayReceipt(
        candidate_id=kw.get("candidate_id", C.candidate_id),
        sequence_sha256=kw.get("sequence_sha256", C.sequence_sha256),
        construct_id=kw.get("construct_id", C.construct_id),
        batch_id=kw.get("batch_id", C.batch_id),
        target=kw.get("target", "target-x"),
        assay_type=assay,
        measurement=value,
        units=kw.get("units", "min" if assay == "HIC" else "%"),
        method=method or ("HIC-v1" if assay == "HIC" else "SEC-v1"),
        method_version=kw.get("method_version", "1.2"),
        verifier=kw.get("verifier", "independent-lab"),
        observed_at=observed,
        raw_evidence_sha256=kw.get("raw_evidence_sha256", RAW),
        evidence_class=kw.get("evidence_class", "INDEPENDENT_ASSAY"),
        status=status,
    )


def decide(receipts):
    return evaluate_candidate(candidate=C, receipts=receipts, policy=P, decision_time="2026-08-23T12:00:00Z")


def test_complete_pass_commits():
    assert decide([r("HIC", 8.0), r("SEC_AGG", 2.0)]).decision is PromotionDecision.COMMIT


def test_non_compensation_threshold_fail_denies():
    result = decide([r("HIC", 100.0), r("SEC_AGG", 0.0)])
    assert result.decision is PromotionDecision.DENY
    assert "threshold_fail:HIC" in result.flags


def test_missing_required_assay_quarantines():
    result = decide([r("HIC", 8.0)])
    assert result.decision is PromotionDecision.QUARANTINE
    assert "missing:SEC_AGG" in result.flags


def test_unknown_quarantines():
    assert decide([r("HIC", 8.0), r("SEC_AGG", None, status="UNKNOWN")]).decision is PromotionDecision.QUARANTINE


def test_stale_quarantines():
    result = decide([r("HIC", 8.0, observed="2020-01-01T00:00:00Z"), r("SEC_AGG", 2.0)])
    assert result.decision is PromotionDecision.QUARANTINE
    assert "stale:HIC" in result.flags


def test_revoked_denies():
    assert decide([r("HIC", 8.0, status="REVOKED"), r("SEC_AGG", 2.0)]).decision is PromotionDecision.DENY


def test_sequence_identity_mismatch_denies():
    result = decide([r("HIC", 8.0, sequence_sha256="c" * 64), r("SEC_AGG", 2.0)])
    assert result.decision is PromotionDecision.DENY
    assert "identity_mismatch:HIC" in result.flags


def test_batch_identity_mismatch_denies():
    assert decide([r("HIC", 8.0, batch_id="wrong"), r("SEC_AGG", 2.0)]).decision is PromotionDecision.DENY


def test_unacceptable_method_denies():
    assert decide([r("HIC", 8.0, method="ranker-inferred"), r("SEC_AGG", 2.0)]).decision is PromotionDecision.DENY


def test_duplicate_receipts_fail_closed():
    result = decide([r("HIC", 8.0), r("HIC", 7.0), r("SEC_AGG", 2.0)])
    assert result.decision is PromotionDecision.DENY
    assert "ambiguous_receipts:HIC" in result.flags


def test_future_evidence_denies():
    assert decide([r("HIC", 8.0, observed="2027-01-01T00:00:00Z"), r("SEC_AGG", 2.0)]).decision is PromotionDecision.DENY


def test_policy_hash_changes_when_threshold_changes():
    q = PromotionPolicy(P.policy_id, P.version, P.effective_at, P.target, (DimensionRule("HIC", "<=", 9.0, "min"),))
    assert P.policy_sha256 != q.policy_sha256


def test_evidence_hash_is_deterministic():
    a = decide([r("HIC", 8.0), r("SEC_AGG", 2.0)])
    b = decide([r("SEC_AGG", 2.0), r("HIC", 8.0)])
    assert a.evidence_sha256 == b.evidence_sha256


def test_ranker_generated_assay_evidence_denies():
    result = decide([r("HIC", 8.0, evidence_class="RANKER_OUTPUT"), r("SEC_AGG", 2.0)])
    assert result.decision is PromotionDecision.DENY
    assert "unacceptable_evidence_class:HIC" in result.flags


def test_future_policy_cannot_authorize_past_decision():
    future = PromotionPolicy(P.policy_id, P.version, "2027-01-01T00:00:00Z", P.target, P.rules)
    result = evaluate_candidate(candidate=C, receipts=[r("HIC", 8.0), r("SEC_AGG", 2.0)], policy=future, decision_time="2026-08-23T12:00:00Z")
    assert result.decision is PromotionDecision.DENY
    assert "policy_not_effective" in result.flags


def test_compiles_into_existing_receipt_gate_policy_shape():
    compiled = to_receipt_gate_policy_mapping(policy=P, candidate=C)
    assert compiled["require_independent_source"] is True
    assert compiled["require_source_bound_evidence"] is True
    assert compiled["require_replay_guard"] is True
    assert compiled["metadata"]["ranker_authority"] == "ADVISORY_ONLY"
    assert set(compiled["required_evidence_ids"]) == {"candidate_assay:HIC", "candidate_assay:SEC_AGG"}
    assert any(a["path"] == "sequence_sha256" and a["value"] == SEQ for a in compiled["evidence_assertions"])
