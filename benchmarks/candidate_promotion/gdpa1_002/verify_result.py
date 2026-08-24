from __future__ import annotations

# Intentionally stdlib-only and independent of gdpa1_replay.py.
import argparse
import csv
import hashlib
import json
import math
import statistics
from pathlib import Path
from typing import Any


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_sha(value: Any) -> str:
    return sha256(canonical(value))


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def pfloat(raw):
    text = "" if raw is None else str(raw).strip()
    if not text or text.lower() in {"na", "n/a", "nan", "none", "null"}:
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def flat_policy(policy):
    result = {}
    for group, specs in policy["groups"].items():
        for spec in specs:
            if spec["assay"] in result:
                raise ValueError("duplicate_policy_assay")
            result[spec["assay"]] = dict(spec, group=group)
    return result


def is_warning(value, spec):
    if spec["warning_direction"] == "LOWER":
        return value < float(spec["threshold"])
    if spec["warning_direction"] == "UPPER":
        return value > float(spec["threshold"])
    raise ValueError("bad_warning_direction")


def gflag(row, policy, group):
    return any(
        is_warning(float(row["assays"][spec["assay"]]), spec)
        for spec in policy["groups"][group]
    )


def build_expected(csv_path: Path, source, policy):
    data = csv_path.read_bytes()
    if len(data) != source["byte_length"]:
        raise ValueError("byte_length_mismatch")
    observed_blob = blob_sha(data)
    if observed_blob != source["git_blob_sha1"]:
        raise ValueError("blob_sha_mismatch")

    flat = flat_policy(policy)
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        if any(col not in fields for col in source["required_columns"]):
            raise ValueError("missing_required_column")
        rows = []
        ids = set()
        for raw in reader:
            cid = str(raw["antibody_id"]).strip()
            if not cid or cid in ids:
                raise ValueError("empty_or_duplicate_id")
            ids.add(cid)
            rows.append({
                "antibody_id": cid,
                "assays": {a: pfloat(raw.get(a)) for a in flat},
            })

    complete = [r for r in rows if all(r["assays"][a] is not None for a in flat)]
    excluded = sorted(
        r["antibody_id"] for r in rows
        if any(r["assays"][a] is None for a in flat)
    )
    coverage = len(complete) / len(rows) if rows else 0.0
    receipt = {
        "schema": "openline.cpg002.gdpa1_source_receipt.v0.1",
        "experiment_id": "CPG-002",
        "external_repository": source["external_repository"],
        "source_commit": source["source_commit"],
        "source_path": source["source_path"],
        "expected_git_blob_sha1": source["git_blob_sha1"],
        "observed_git_blob_sha1": observed_blob,
        "byte_length": len(data),
        "source_sha256": sha256(data),
        "observed_row_count": len(rows),
        "unique_candidate_count": len(ids),
        "complete_case_candidate_count": len(complete),
        "complete_case_coverage_fraction": coverage,
        "excluded_for_missing_primary_assay": excluded,
        "clinical_labels_read": False,
        "policy_sha256": json_sha(policy),
    }

    stats = {}
    for assay, spec in flat.items():
        values = [float(r["assays"][assay]) for r in complete]
        mean = statistics.fmean(values)
        sd = statistics.stdev(values) if len(values) > 1 else 0.0
        direction = 1.0 if spec["favorable_direction"] == "HIGHER" else -1.0
        stats[assay] = {"mean": mean, "sample_sd": sd, "direction": direction}

    def score(row, assays):
        values = []
        for assay in assays:
            st = stats[assay]
            values.append(
                0.0 if st["sample_sd"] == 0.0
                else st["direction"] * (float(row["assays"][assay]) - st["mean"])
                     / st["sample_sd"]
            )
        return statistics.fmean(values) if values else 0.0

    def rank(candidates, assays):
        items = [(score(r, assays), r["antibody_id"], r) for r in candidates]
        return [x[2] for x in sorted(items, key=lambda x: (-x[0], x[1]))]

    def metrics(selected, gated_groups, heldout):
        gated = sum(
            any(gflag(r, policy, group) for group in gated_groups)
            for r in selected
        )
        held = sum(gflag(r, policy, heldout) for r in selected)
        n = len(selected)
        return {
            "selected_count": n,
            "gated_property_group_liability_count": gated,
            "gated_property_group_liability_rate": gated / n if n else None,
            "heldout_property_group_flag_count": held,
            "heldout_property_group_flag_rate": held / n if n else None,
        }

    fold_results = []
    groups = list(policy["groups"])
    for budget in policy["budgets"]:
        for heldout in groups:
            gated_groups = [g for g in groups if g != heldout]
            gated_assays = [
                spec["assay"]
                for group in gated_groups
                for spec in policy["groups"][group]
            ]
            k = int(math.ceil(len(complete) * float(budget)))
            control_rows = rank(complete, gated_assays)[:k]
            eligible = [
                r for r in complete
                if all(not gflag(r, policy, group) for group in gated_groups)
            ]
            treatment_rows = rank(eligible, gated_assays)[:k]

            parity = []
            for row in rank(complete, gated_assays):
                if not [group for group in gated_groups if gflag(row, policy, group)]:
                    parity.append(row)
                if len(parity) >= k:
                    break

            control = metrics(control_rows, gated_groups, heldout)
            treatment = metrics(treatment_rows, gated_groups, heldout)
            treatment["eligible_candidate_count"] = len(eligible)
            treatment["eligible_candidate_yield"] = (
                len(eligible) / len(complete) if complete else 0.0
            )
            treatment["top_k_fill_rate"] = len(treatment_rows) / k if k else 1.0
            fold_results.append({
                "budget": float(budget),
                "candidate_count": len(complete),
                "top_k": k,
                "heldout_group": heldout,
                "gated_groups": gated_groups,
                "gated_assays": gated_assays,
                "control": {**control, "selected": [r["antibody_id"] for r in control_rows]},
                "treatment": {**treatment, "selected": [r["antibody_id"] for r in treatment_rows]},
                "authority_parity_control": {
                    "matches_treatment": [r["antibody_id"] for r in parity]
                    == [r["antibody_id"] for r in treatment_rows],
                    "selected": [r["antibody_id"] for r in parity],
                },
            })

    primary = [f for f in fold_results if f["budget"] == float(policy["primary_budget"])]
    crit = policy["primary_success_criteria"]
    parity_pass = all(f["authority_parity_control"]["matches_treatment"] for f in primary)
    reductions = []
    for f in primary:
        c = f["control"]["gated_property_group_liability_rate"]
        t = f["treatment"]["gated_property_group_liability_rate"]
        reductions.append(c - t if c is not None and t is not None else None)
    n_reduction = sum(
        x is not None
        and x >= float(crit["minimum_gated_liability_reduction_fraction"])
        for x in reductions
    )
    compensation = n_reduction >= int(
        crit["minimum_folds_with_10pp_gated_liability_reduction"]
    )
    fill = [f["treatment"]["top_k_fill_rate"] for f in primary]
    n_fill = sum(x >= float(crit["minimum_fold_fill_fraction"]) for x in fill)
    total_sel = sum(f["treatment"]["selected_count"] for f in primary)
    total_k = sum(f["top_k"] for f in primary)
    pooled_fill = total_sel / total_k if total_k else 1.0
    yield_pass = (
        n_fill >= int(crit["minimum_folds_with_80pct_fill"])
        and pooled_fill >= float(crit["minimum_pooled_fill_fraction"])
    )

    deltas, n_heldout = [], 0
    for f in primary:
        c = f["control"]["heldout_property_group_flag_rate"]
        t = f["treatment"]["heldout_property_group_flag_rate"]
        delta = None if c is None or t is None else t - c
        deltas.append(delta)
        if delta is not None and delta <= float(crit["maximum_heldout_degradation_fraction"]):
            n_heldout += 1

    def pooled(arm):
        n = sum(f[arm]["selected_count"] for f in primary)
        flags = sum(f[arm]["heldout_property_group_flag_count"] for f in primary)
        return flags / n if n else None

    pooled_c, pooled_t = pooled("control"), pooled("treatment")
    heldout_pass = (
        n_heldout >= int(crit["minimum_folds_with_heldout_within_5pp"])
        and pooled_c is not None and pooled_t is not None and pooled_t <= pooled_c
    )
    coverage_pass = coverage >= float(crit["minimum_complete_case_coverage_fraction"])

    if not coverage_pass:
        verdict_name = "INCONCLUSIVE_COVERAGE"
    elif not parity_pass:
        verdict_name = "INVALID_AUTHORITY_PARITY"
    elif not compensation:
        verdict_name = "NO_COMPENSATION_SIGNAL"
    elif not yield_pass or not heldout_pass:
        verdict_name = "FRICTION_ONLY"
    else:
        verdict_name = "SUPPORTED_REPLICATION_WITHIN_SCOPE"

    primary_verdict = {
        "coverage_fraction": coverage,
        "coverage_pass": coverage_pass,
        "authority_parity_pass": parity_pass,
        "gated_liability_reduction_by_fold": reductions,
        "folds_with_ge_10pp_reduction": n_reduction,
        "compensation_signal_pass": compensation,
        "folds_with_fill_ge_0_80": n_fill,
        "pooled_fill_rate": pooled_fill,
        "yield_pass": yield_pass,
        "heldout_delta_by_fold": deltas,
        "folds_with_heldout_within_5pp": n_heldout,
        "pooled_control_heldout_flag_rate": pooled_c,
        "pooled_treatment_heldout_flag_rate": pooled_t,
        "heldout_quality_pass": heldout_pass,
        "verdict": verdict_name,
    }
    score = {
        "schema": "openline.cpg002.gdpa1_score.v0.1",
        "experiment_id": "CPG-002",
        "source_sha256": receipt["source_sha256"],
        "policy_sha256": receipt["policy_sha256"],
        "observed_candidate_count": receipt["unique_candidate_count"],
        "complete_case_candidate_count": receipt["complete_case_candidate_count"],
        "complete_case_coverage_fraction": receipt["complete_case_coverage_fraction"],
        "score_statistics": stats,
        "fold_results": fold_results,
        "primary_verdict": primary_verdict,
        "clinical_labels_read": False,
    }
    verdict = {
        "schema": "openline.cpg002.gdpa1_verdict.v0.1",
        "experiment_id": "CPG-002",
        "verdict": verdict_name,
        "scientific_result_is_ci_failure": False,
        "policy_authority": "NONE",
        "source_sha256": receipt["source_sha256"],
        "score_sha256": json_sha(score),
        "claim_boundary": (
            "Historical developability promotion replay only. Does not predict "
            "clinical success, establish universal thresholds, or establish a "
            "superior antibody scoring algorithm."
        ),
        "stop_rule": (
            "If verdict is NO_COMPENSATION_SIGNAL, do not retune the composite, "
            "thresholds, groups, budgets, or success criteria to rescue the "
            "masked-liability hypothesis on these historical panels."
        ),
    }
    return receipt, score, verdict


def compare(a, b, path="$", mismatches=None):
    if mismatches is None:
        mismatches = []
    if isinstance(a, float) or isinstance(b, float):
        if a is None or b is None:
            if a != b:
                mismatches.append({"path": path, "expected": a, "observed": b})
            return mismatches
        try:
            af, bf = float(a), float(b)
        except (TypeError, ValueError):
            if a != b:
                mismatches.append({"path": path, "expected": a, "observed": b})
            return mismatches
        if math.isinf(af) or math.isinf(bf):
            if af != bf:
                mismatches.append({"path": path, "expected": a, "observed": b})
        elif not math.isclose(af, bf, rel_tol=1e-12, abs_tol=1e-12):
            mismatches.append({"path": path, "expected": a, "observed": b})
        return mismatches
    if type(a) is not type(b):
        mismatches.append({"path": path, "expected_type": type(a).__name__, "observed_type": type(b).__name__})
        return mismatches
    if isinstance(a, dict):
        if set(a) != set(b):
            mismatches.append({"path": path, "expected_keys": sorted(a), "observed_keys": sorted(b)})
            return mismatches
        for k in sorted(a):
            compare(a[k], b[k], f"{path}.{k}", mismatches)
    elif isinstance(a, list):
        if len(a) != len(b):
            mismatches.append({"path": path, "expected_len": len(a), "observed_len": len(b)})
            return mismatches
        for i, (x, y) in enumerate(zip(a, b)):
            compare(x, y, f"{path}[{i}]", mismatches)
    elif a != b:
        mismatches.append({"path": path, "expected": a, "observed": b})
    return mismatches


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", required=True)
    p.add_argument("--result-dir", required=True)
    p.add_argument("--source", default=str(Path(__file__).resolve().parent / "SOURCE.json"))
    p.add_argument("--policy", default=str(Path(__file__).resolve().parent / "promotion-policy.json"))
    p.add_argument("--output", required=True)
    args = p.parse_args()

    source, policy = load(Path(args.source)), load(Path(args.policy))
    expected_receipt, expected_score, expected_verdict = build_expected(
        Path(args.csv), source, policy
    )
    result_dir = Path(args.result_dir)
    observed_receipt = load(result_dir / "source-receipt.json")
    observed_score = load(result_dir / "score.json")
    observed_verdict = load(result_dir / "verdict.json")

    mismatches = []
    compare(expected_receipt, observed_receipt, "$.source_receipt", mismatches)
    compare(expected_score, observed_score, "$.score", mismatches)
    compare(expected_verdict, observed_verdict, "$.verdict", mismatches)

    output = {
        "schema": "openline.cpg002.gdpa1_independent_verification.v0.1",
        "experiment_id": "CPG-002",
        "verified": not mismatches,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches[:100],
        "source_sha256": expected_receipt["source_sha256"],
        "score_file_sha256": sha256((result_dir / "score.json").read_bytes()),
        "verdict_file_sha256": sha256((result_dir / "verdict.json").read_bytes()),
        "verdict": observed_verdict.get("verdict"),
        "policy_authority": "NONE",
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["verified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
