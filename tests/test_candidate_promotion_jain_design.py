from __future__ import annotations

import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks" / "candidate_promotion"
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

from jain_design import (
    THRESHOLDED_ASSAYS,
    complete_case_candidates,
    correlation_audit,
    evaluate_fold,
    flatten_thresholds,
    primary_verdict,
    run_confirmatory,
    sha256_json,
    validate_design_lock,
)


def load(name: str):
    return json.loads((BENCH / name).read_text(encoding="utf-8"))


def make_row(cid: str, values: dict[str, float], approved: bool = False):
    base = {name: 0.0 for name in THRESHOLDED_ASSAYS}
    base.update(values)
    return {"candidate_id": cid, "approved_2017": approved, "stage_2017": "approved" if approved else "phase", "assays": base}


def synthetic_thresholds():
    return {
        "groups": {
            "group_1_cross_or_self_interaction": [
                {"assay_type": "PSR", "operator": "<=", "threshold": 1.0},
                {"assay_type": "AC_SINS", "operator": "<=", "threshold": 1.0},
                {"assay_type": "CSI_BLI", "operator": "<=", "threshold": 1.0},
                {"assay_type": "CIC", "operator": "<=", "threshold": 1.0},
            ],
            "group_2_hydrophobicity_or_colloidal": [
                {"assay_type": "HIC", "operator": "<=", "threshold": 1.0},
                {"assay_type": "SMAC", "operator": "<=", "threshold": 1.0},
                {"assay_type": "SGAC_SINS", "operator": ">=", "threshold": -1.0},
            ],
            "group_3_polyspecificity": [
                {"assay_type": "BVP", "operator": "<=", "threshold": 1.0},
                {"assay_type": "ELISA", "operator": "<=", "threshold": 1.0},
            ],
            "group_4_accelerated_stability": [
                {"assay_type": "AS", "operator": "<=", "threshold": 1.0},
            ],
        }
    }


def test_design_lock_validates_against_frozen_thresholds():
    assert validate_design_lock(load("JAIN_2017_DESIGN_LOCK.json"), load("JAIN_2017_THRESHOLDS.json")) == []


def test_affinity_explicitly_out_of_scope():
    lock = load("JAIN_2017_DESIGN_LOCK.json")
    assert "affinity" in lock["affinity_boundary"].lower()
    assert any("affinity" in value.lower() for value in lock["out_of_scope"])


def test_baseline_assay_set_is_exactly_ten_table1_flag_assays():
    flat = flatten_thresholds(load("JAIN_2017_THRESHOLDS.json"))
    assert set(flat) == set(THRESHOLDED_ASSAYS)
    assert "Fab_Tm" not in flat
    assert "transient_HEK_titer" not in flat


def test_complete_case_excludes_missing_without_imputation():
    good = make_row("good", {})
    bad = make_row("bad", {})
    del bad["assays"]["PSR"]
    included, excluded = complete_case_candidates([bad, good])
    assert [row["candidate_id"] for row in included] == ["good"]
    assert excluded == ["bad"]


def test_treatment_uses_same_score_after_veto_and_parity_matches():
    thresholds = synthetic_thresholds()
    rows = [
        make_row("A", {"PSR": 4.0, "HIC": -4.0, "BVP": -4.0, "AS": -4.0}),
        make_row("B", {"PSR": 0.2, "HIC": 0.2, "BVP": 0.2, "AS": 0.2}),
        make_row("C", {"PSR": 0.3, "HIC": 0.3, "BVP": 0.3, "AS": 0.3}),
        make_row("D", {"PSR": 0.4, "HIC": 0.4, "BVP": 0.4, "AS": 0.4}),
        make_row("E", {"PSR": 0.5, "HIC": 0.5, "BVP": 0.5, "AS": 0.5}),
        make_row("F", {"PSR": 0.6, "HIC": 0.6, "BVP": 0.6, "AS": 0.6}),
        make_row("G", {"PSR": 0.7, "HIC": 0.7, "BVP": 0.7, "AS": 0.7}),
        make_row("H", {"PSR": 0.8, "HIC": 0.8, "BVP": 0.8, "AS": 0.8}),
    ]
    result = evaluate_fold(rows, thresholds, "group_4_accelerated_stability", 0.25)
    assert result["authority_parity_control"]["matches_treatment"] is True
    assert result["treatment"]["gated_property_group_liability_rate"] == 0.0


def test_primary_verdict_supported_only_when_all_bars_pass():
    folds = []
    for i in range(4):
        folds.append({
            "budget": 0.25,
            "control": {
                "gated_property_group_liability_rate": 0.20,
                "heldout_property_group_flag_rate": 0.20,
            },
            "treatment": {
                "gated_property_group_liability_rate": 0.0,
                "heldout_property_group_flag_rate": 0.15,
                "top_k_fill_rate": 0.9,
            },
            "authority_parity_control": {"matches_treatment": True},
        })
    verdict = primary_verdict(folds, 0.9)
    assert verdict["verdict"] == "SUPPORTED_WITHIN_SCOPE"


def test_primary_verdict_friction_only_when_yield_collapses():
    folds = []
    for _ in range(4):
        folds.append({
            "budget": 0.25,
            "control": {
                "gated_property_group_liability_rate": 0.20,
                "heldout_property_group_flag_rate": 0.20,
            },
            "treatment": {
                "gated_property_group_liability_rate": 0.0,
                "heldout_property_group_flag_rate": 0.10,
                "top_k_fill_rate": 0.5,
            },
            "authority_parity_control": {"matches_treatment": True},
        })
    assert primary_verdict(folds, 0.9)["verdict"] == "FRICTION_ONLY"


def test_primary_verdict_no_signal_when_control_does_not_compensate():
    folds = []
    for _ in range(4):
        folds.append({
            "budget": 0.25,
            "control": {
                "gated_property_group_liability_rate": 0.05,
                "heldout_property_group_flag_rate": 0.20,
            },
            "treatment": {
                "gated_property_group_liability_rate": 0.0,
                "heldout_property_group_flag_rate": 0.10,
                "top_k_fill_rate": 1.0,
            },
            "authority_parity_control": {"matches_treatment": True},
        })
    assert primary_verdict(folds, 0.9)["verdict"] == "NO_COMPENSATION_SIGNAL"


def test_primary_verdict_downgrades_low_coverage_before_positive_claim():
    folds = []
    for _ in range(4):
        folds.append({
            "budget": 0.25,
            "control": {
                "gated_property_group_liability_rate": 0.30,
                "heldout_property_group_flag_rate": 0.30,
            },
            "treatment": {
                "gated_property_group_liability_rate": 0.0,
                "heldout_property_group_flag_rate": 0.10,
                "top_k_fill_rate": 1.0,
            },
            "authority_parity_control": {"matches_treatment": True},
        })
    assert primary_verdict(folds, 0.69)["verdict"] == "INCONCLUSIVE_COVERAGE"


def test_correlation_audit_never_authorizes_policy_mutation():
    rows = []
    for i in range(1, 8):
        rows.append(make_row(str(i), {name: float(i) for name in THRESHOLDED_ASSAYS}))
    report = correlation_audit(rows)
    assert report["statistical_independence_assumed"] is False
    assert report["policy_mutation_allowed"] is False
    assert report["high_correlation_pairs"]
    assert all(abs(item["spearman_rho"]) >= 0.70 for item in report["high_correlation_pairs"])


def test_confirmatory_runner_rejects_wrong_design_hash():
    lock = load("JAIN_2017_DESIGN_LOCK.json")
    thresholds = load("JAIN_2017_THRESHOLDS.json")
    normalized = {
        "schema": "openline.cpg001.jain_normalized.v0.1",
        "design_lock_sha256": "0" * 64,
        "thresholds_sha256": sha256_json(thresholds),
        "source_artifacts": [],
        "candidates": [],
    }
    try:
        run_confirmatory(normalized, thresholds, lock)
    except ValueError as exc:
        assert str(exc) == "design_lock_hash_mismatch"
    else:
        raise AssertionError("expected design hash mismatch")


def test_primary_success_numbers_are_frozen_not_qualitative():
    lock = load("JAIN_2017_DESIGN_LOCK.json")
    text = json.dumps(lock["primary_success_criteria"])
    for token in ("0.10", "0.80", "0.05", "0.70"):
        assert token in text


def test_primary_verdict_handles_zero_survivor_treatment_as_friction():
    folds = []
    for _ in range(4):
        folds.append({
            "budget": 0.25,
            "control": {
                "gated_property_group_liability_rate": 0.30,
                "heldout_property_group_flag_rate": 0.20,
            },
            "treatment": {
                "gated_property_group_liability_rate": 0.0,
                "heldout_property_group_flag_rate": None,
                "top_k_fill_rate": 0.0,
            },
            "authority_parity_control": {"matches_treatment": True},
        })
    assert primary_verdict(folds, 1.0)["verdict"] == "FRICTION_ONLY"


def test_source_requirements_pin_exact_three_pnas_supplements():
    req = load("JAIN_2017_SOURCE_REQUIREMENTS.json")
    assert [item["filename"] for item in req["required_artifacts"]] == [
        "pnas.1616408114.sd01.xlsx",
        "pnas.1616408114.sd02.xlsx",
        "pnas.1616408114.sd03.xlsx",
    ]
