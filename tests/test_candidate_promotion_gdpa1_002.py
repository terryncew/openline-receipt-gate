from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "benchmarks" / "candidate_promotion" / "gdpa1_002"

spec = importlib.util.spec_from_file_location("gdpa1_replay", HERE / "gdpa1_replay.py")
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def policy():
    return json.loads((HERE / "promotion-policy.json").read_text(encoding="utf-8"))


def row(cid, **overrides):
    base = {
        "Tm1": 75.0, "Tm2": 85.0, "HIC": 2.0, "SMAC": 2.0,
        "AC-SINS_pH6.0": 1.0, "AC-SINS_pH7.4": 5.0,
        "PR_CHO": 0.10, "PR_Ova": 0.10,
    }
    base.update(overrides)
    return {"antibody_id": cid, "assays": base}


def test_policy_has_four_groups_and_eight_unique_assays():
    p = policy()
    assert len(p["groups"]) == 4
    assert len(mod.flatten_policy(p)) == 8


def test_warning_equality_passes_both_directions():
    flat = mod.flatten_policy(policy())
    assert mod.warning(68.09, flat["Tm1"]) is False
    assert mod.warning(68.08, flat["Tm1"]) is True
    assert mod.warning(3.18, flat["HIC"]) is False
    assert mod.warning(3.19, flat["HIC"]) is True


def test_clinical_labels_are_forbidden_by_source_contract():
    s = json.loads((HERE / "SOURCE.json").read_text(encoding="utf-8"))
    forbidden = set(s["clinical_label_columns_forbidden_in_primary_analysis"])
    assert "highest_clinical_trial_asof_feb2025" in forbidden
    assert "est_status_asof_feb2025" in forbidden


def test_hac_exclusion_is_predeclared():
    p = policy()
    assert "HAC" in p["excluded_from_primary_policy"]
    assert "31 approved antibodies" in p["excluded_from_primary_policy"]["HAC"]


def test_treatment_blocks_noncompensable_failure_and_parity_matches():
    p = policy()
    rows = [
        row("A", HIC=8.0, Tm1=100.0, Tm2=100.0, PR_CHO=0.0, PR_Ova=0.0),
        row("B", HIC=2.0, Tm1=80.0, Tm2=90.0),
        row("C", HIC=2.1, Tm1=79.0, Tm2=89.0),
        row("D", HIC=2.2, Tm1=78.0, Tm2=88.0),
        row("E", HIC=2.3, Tm1=77.0, Tm2=87.0),
        row("F", HIC=2.4, Tm1=76.0, Tm2=86.0),
        row("G", HIC=2.5, Tm1=75.0, Tm2=85.0),
        row("H", HIC=2.6, Tm1=74.0, Tm2=84.0),
    ]
    stats = mod.score_statistics(rows, p)
    result = mod.evaluate_fold(rows, p, stats, "self_association", 0.25)
    assert result["authority_parity_control"]["matches_treatment"] is True
    assert result["treatment"]["gated_property_group_liability_rate"] == 0.0
    assert "A" not in result["treatment"]["selected"]


def fake_folds(control_liability=0.2, fill=1.0, heldout_control=0.2, heldout_treatment=0.1):
    folds = []
    for _ in range(4):
        k = 10
        selected = int(round(k * fill))
        folds.append({
            "top_k": k,
            "control": {
                "selected_count": k,
                "gated_property_group_liability_rate": control_liability,
                "heldout_property_group_flag_rate": heldout_control,
                "heldout_property_group_flag_count": int(round(k * heldout_control)),
            },
            "treatment": {
                "selected_count": selected,
                "gated_property_group_liability_rate": 0.0 if selected else None,
                "heldout_property_group_flag_rate": heldout_treatment if selected else None,
                "heldout_property_group_flag_count": int(round(selected * heldout_treatment)),
                "top_k_fill_rate": fill,
            },
            "authority_parity_control": {"matches_treatment": True},
        })
    return folds


def test_primary_verdict_can_support_without_tuning():
    p = policy()
    v = mod.primary_verdict(fake_folds(), 1.0, p["primary_success_criteria"])
    assert v["verdict"] == "SUPPORTED_REPLICATION_WITHIN_SCOPE"


def test_primary_verdict_preserves_no_signal_falsifier():
    p = policy()
    v = mod.primary_verdict(
        fake_folds(control_liability=0.05), 1.0, p["primary_success_criteria"]
    )
    assert v["verdict"] == "NO_COMPENSATION_SIGNAL"


def test_primary_verdict_reports_friction_when_yield_fails():
    p = policy()
    v = mod.primary_verdict(
        fake_folds(fill=0.5), 1.0, p["primary_success_criteria"]
    )
    assert v["verdict"] == "FRICTION_ONLY"


def test_coverage_precedes_positive_claim():
    p = policy()
    v = mod.primary_verdict(fake_folds(), 0.69, p["primary_success_criteria"])
    assert v["verdict"] == "INCONCLUSIVE_COVERAGE"


def test_budgets_and_primary_are_frozen():
    p = policy()
    assert p["budgets"] == [0.10, 0.25, 0.50]
    assert p["primary_budget"] == 0.25


def test_end_to_end_runner_and_independent_verifier_on_synthetic_source(tmp_path):
    import csv
    import hashlib
    import subprocess
    import sys

    p = policy()
    csv_path = tmp_path / "synthetic.csv"
    fields = [
        "antibody_id", "Tm1", "Tm2", "HIC", "SMAC",
        "AC-SINS_pH6.0", "AC-SINS_pH7.4", "PR_CHO", "PR_Ova",
    ]
    rows = []
    for i in range(12):
        item = row(f"X{i:02d}")
        rows.append({"antibody_id": item["antibody_id"], **item["assays"]})
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    data = csv_path.read_bytes()
    blob = hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()
    src = {
        "schema": "openline.cpg002.gdpa1_source.v0.1",
        "experiment_id": "CPG-002",
        "external_repository": "synthetic-test",
        "source_commit": "synthetic",
        "source_path": "synthetic.csv",
        "git_blob_sha1": blob,
        "byte_length": len(data),
        "required_columns": fields,
    }
    src_path = tmp_path / "SOURCE.json"
    pol_path = tmp_path / "policy.json"
    src_path.write_text(json.dumps(src), encoding="utf-8")
    pol_path.write_text(json.dumps(p), encoding="utf-8")
    out = tmp_path / "out"

    run = subprocess.run(
        [
            sys.executable, str(HERE / "run_replay.py"),
            "--csv", str(csv_path), "--out-dir", str(out),
            "--source", str(src_path), "--policy", str(pol_path),
        ],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert run.returncode == 0, run.stderr

    verification = subprocess.run(
        [
            sys.executable, "-I", str(HERE / "verify_result.py"),
            "--csv", str(csv_path), "--result-dir", str(out),
            "--source", str(src_path), "--policy", str(pol_path),
            "--output", str(out / "independent-verification.json"),
        ],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert verification.returncode == 0, verification.stderr
    result = json.loads((out / "independent-verification.json").read_text())
    assert result["verified"] is True
    assert result["mismatch_count"] == 0
