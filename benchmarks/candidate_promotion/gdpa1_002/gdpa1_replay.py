from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
from pathlib import Path
from typing import Any

ALLOWED_VERDICTS = {
    "INCONCLUSIVE_COVERAGE",
    "INVALID_AUTHORITY_PARITY",
    "NO_COMPENSATION_SIGNAL",
    "FRICTION_ONLY",
    "SUPPORTED_REPLICATION_WITHIN_SCOPE",
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def flatten_policy(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    flat: dict[str, dict[str, Any]] = {}
    for group, specs in policy["groups"].items():
        for spec in specs:
            assay = spec["assay"]
            if assay in flat:
                raise ValueError(f"duplicate_policy_assay:{assay}")
            flat[assay] = {**spec, "group": group}
    return flat


def parse_float(raw: str | None) -> float | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text or text.lower() in {"na", "n/a", "nan", "none", "null"}:
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def read_source(csv_path: Path, source: dict[str, Any], policy: dict[str, Any]):
    data = csv_path.read_bytes()
    if len(data) != int(source["byte_length"]):
        raise ValueError(f"source_byte_length_mismatch:{len(data)}!={source['byte_length']}")
    observed_blob = git_blob_sha1(data)
    if observed_blob != source["git_blob_sha1"]:
        raise ValueError(f"source_git_blob_mismatch:{observed_blob}!={source['git_blob_sha1']}")

    flat = flatten_policy(policy)
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        missing_columns = [c for c in source["required_columns"] if c not in fields]
        if missing_columns:
            raise ValueError(f"source_missing_columns:{','.join(missing_columns)}")

        rows = []
        seen = set()
        duplicate_ids = []
        for raw in reader:
            cid = str(raw.get("antibody_id", "")).strip()
            if not cid:
                raise ValueError("empty_antibody_id")
            if cid in seen:
                duplicate_ids.append(cid)
            seen.add(cid)
            assays = {assay: parse_float(raw.get(assay)) for assay in flat}
            rows.append({"antibody_id": cid, "assays": assays})

    if duplicate_ids:
        raise ValueError("duplicate_antibody_ids:" + ",".join(sorted(set(duplicate_ids))))

    complete = [
        row for row in rows
        if all(row["assays"].get(assay) is not None for assay in flat)
    ]
    excluded = sorted(
        row["antibody_id"] for row in rows
        if any(row["assays"].get(assay) is None for assay in flat)
    )
    coverage = len(complete) / len(rows) if rows else 0.0

    source_receipt = {
        "schema": "openline.cpg002.gdpa1_source_receipt.v0.1",
        "experiment_id": "CPG-002",
        "external_repository": source["external_repository"],
        "source_commit": source["source_commit"],
        "source_path": source["source_path"],
        "expected_git_blob_sha1": source["git_blob_sha1"],
        "observed_git_blob_sha1": observed_blob,
        "byte_length": len(data),
        "source_sha256": sha256_bytes(data),
        "observed_row_count": len(rows),
        "unique_candidate_count": len(seen),
        "complete_case_candidate_count": len(complete),
        "complete_case_coverage_fraction": coverage,
        "excluded_for_missing_primary_assay": excluded,
        "clinical_labels_read": False,
        "policy_sha256": sha256_json(policy),
    }
    return rows, complete, source_receipt


def warning(value: float, spec: dict[str, Any]) -> bool:
    threshold = float(spec["threshold"])
    direction = spec["warning_direction"]
    if direction == "LOWER":
        return value < threshold
    if direction == "UPPER":
        return value > threshold
    raise ValueError(f"unknown_warning_direction:{direction}")


def group_flag(row: dict[str, Any], policy: dict[str, Any], group: str) -> bool:
    return any(
        warning(float(row["assays"][spec["assay"]]), spec)
        for spec in policy["groups"][group]
    )


def score_statistics(rows: list[dict[str, Any]], policy: dict[str, Any]):
    flat = flatten_policy(policy)
    result = {}
    for assay, spec in flat.items():
        values = [float(row["assays"][assay]) for row in rows]
        mean = statistics.fmean(values)
        sd = statistics.stdev(values) if len(values) > 1 else 0.0
        direction = 1.0 if spec["favorable_direction"] == "HIGHER" else -1.0
        result[assay] = {"mean": mean, "sample_sd": sd, "direction": direction}
    return result


def candidate_score(row, assays, stats) -> float:
    parts = []
    for assay in assays:
        item = stats[assay]
        sd = float(item["sample_sd"])
        if sd == 0.0:
            parts.append(0.0)
        else:
            parts.append(
                float(item["direction"])
                * (float(row["assays"][assay]) - float(item["mean"])) / sd
            )
    return statistics.fmean(parts) if parts else 0.0


def ranked(rows, assays, stats):
    scored = [
        (candidate_score(row, assays, stats), row["antibody_id"], row)
        for row in rows
    ]
    scored.sort(key=lambda item: (-item[0], item[1]))
    return scored


def selected_metrics(selected_rows, policy, gated_groups, heldout_group):
    gated_liability_count = sum(
        any(group_flag(row, policy, group) for group in gated_groups)
        for row in selected_rows
    )
    heldout_flag_count = sum(
        group_flag(row, policy, heldout_group) for row in selected_rows
    )
    n = len(selected_rows)
    return {
        "selected_count": n,
        "gated_property_group_liability_count": gated_liability_count,
        "gated_property_group_liability_rate": gated_liability_count / n if n else None,
        "heldout_property_group_flag_count": heldout_flag_count,
        "heldout_property_group_flag_rate": heldout_flag_count / n if n else None,
    }


def evaluate_fold(rows, policy, stats, heldout_group: str, budget: float):
    groups = list(policy["groups"])
    gated_groups = [g for g in groups if g != heldout_group]
    gated_assays = [
        spec["assay"] for group in gated_groups for spec in policy["groups"][group]
    ]
    k = int(math.ceil(len(rows) * budget))

    control_rows = [item[2] for item in ranked(rows, gated_assays, stats)[:k]]

    eligible = [
        row for row in rows
        if not any(group_flag(row, policy, group) for group in gated_groups)
    ]
    treatment_rows = [
        item[2] for item in ranked(eligible, gated_assays, stats)[:k]
    ]

    parity_rows = []
    for _, _, row in ranked(rows, gated_assays, stats):
        constraint_pass = True
        for group in gated_groups:
            if group_flag(row, policy, group):
                constraint_pass = False
                break
        if constraint_pass:
            parity_rows.append(row)
        if len(parity_rows) == k:
            break

    control = selected_metrics(control_rows, policy, gated_groups, heldout_group)
    treatment = selected_metrics(treatment_rows, policy, gated_groups, heldout_group)
    treatment["eligible_candidate_count"] = len(eligible)
    treatment["eligible_candidate_yield"] = len(eligible) / len(rows) if rows else 0.0
    treatment["top_k_fill_rate"] = len(treatment_rows) / k if k else 1.0

    return {
        "budget": budget,
        "candidate_count": len(rows),
        "top_k": k,
        "heldout_group": heldout_group,
        "gated_groups": gated_groups,
        "gated_assays": gated_assays,
        "control": {**control, "selected": [row["antibody_id"] for row in control_rows]},
        "treatment": {**treatment, "selected": [row["antibody_id"] for row in treatment_rows]},
        "authority_parity_control": {
            "matches_treatment": [row["antibody_id"] for row in parity_rows]
            == [row["antibody_id"] for row in treatment_rows],
            "selected": [row["antibody_id"] for row in parity_rows],
        },
    }


def _pooled_rate(folds, arm, count_key):
    total_count = sum(int(f[arm][count_key]) for f in folds)
    total_selected = sum(int(f[arm]["selected_count"]) for f in folds)
    return total_count / total_selected if total_selected else None


def primary_verdict(primary_folds, coverage: float, criteria):
    parity_pass = all(
        f["authority_parity_control"]["matches_treatment"] for f in primary_folds
    )
    reductions = []
    for fold in primary_folds:
        c = fold["control"]["gated_property_group_liability_rate"]
        t = fold["treatment"]["gated_property_group_liability_rate"]
        reductions.append((c - t) if c is not None and t is not None else None)

    folds_with_reduction = sum(
        value is not None
        and value >= float(criteria["minimum_gated_liability_reduction_fraction"])
        for value in reductions
    )
    compensation_pass = folds_with_reduction >= int(
        criteria["minimum_folds_with_10pp_gated_liability_reduction"]
    )

    fill_rates = [float(f["treatment"]["top_k_fill_rate"]) for f in primary_folds]
    folds_with_fill = sum(
        value >= float(criteria["minimum_fold_fill_fraction"]) for value in fill_rates
    )
    total_selected = sum(int(f["treatment"]["selected_count"]) for f in primary_folds)
    total_k = sum(int(f["top_k"]) for f in primary_folds)
    pooled_fill = total_selected / total_k if total_k else 1.0
    yield_pass = (
        folds_with_fill >= int(criteria["minimum_folds_with_80pct_fill"])
        and pooled_fill >= float(criteria["minimum_pooled_fill_fraction"])
    )

    heldout_within = 0
    heldout_deltas = []
    for fold in primary_folds:
        c = fold["control"]["heldout_property_group_flag_rate"]
        t = fold["treatment"]["heldout_property_group_flag_rate"]
        if c is None or t is None:
            heldout_deltas.append(None)
            continue
        delta = t - c
        heldout_deltas.append(delta)
        if delta <= float(criteria["maximum_heldout_degradation_fraction"]):
            heldout_within += 1

    pooled_control = _pooled_rate(primary_folds, "control", "heldout_property_group_flag_count")
    pooled_treatment = _pooled_rate(primary_folds, "treatment", "heldout_property_group_flag_count")
    pooled_heldout_pass = (
        pooled_control is not None
        and pooled_treatment is not None
        and pooled_treatment <= pooled_control
    )
    heldout_pass = (
        heldout_within >= int(criteria["minimum_folds_with_heldout_within_5pp"])
        and pooled_heldout_pass
    )
    coverage_pass = coverage >= float(criteria["minimum_complete_case_coverage_fraction"])

    if not coverage_pass:
        verdict = "INCONCLUSIVE_COVERAGE"
    elif not parity_pass:
        verdict = "INVALID_AUTHORITY_PARITY"
    elif not compensation_pass:
        verdict = "NO_COMPENSATION_SIGNAL"
    elif not yield_pass or not heldout_pass:
        verdict = "FRICTION_ONLY"
    else:
        verdict = "SUPPORTED_REPLICATION_WITHIN_SCOPE"

    return {
        "coverage_fraction": coverage,
        "coverage_pass": coverage_pass,
        "authority_parity_pass": parity_pass,
        "gated_liability_reduction_by_fold": reductions,
        "folds_with_ge_10pp_reduction": folds_with_reduction,
        "compensation_signal_pass": compensation_pass,
        "folds_with_fill_ge_0_80": folds_with_fill,
        "pooled_fill_rate": pooled_fill,
        "yield_pass": yield_pass,
        "heldout_delta_by_fold": heldout_deltas,
        "folds_with_heldout_within_5pp": heldout_within,
        "pooled_control_heldout_flag_rate": pooled_control,
        "pooled_treatment_heldout_flag_rate": pooled_treatment,
        "heldout_quality_pass": heldout_pass,
        "verdict": verdict,
    }


def run(csv_path: Path, source_path: Path, policy_path: Path):
    source = load_json(source_path)
    policy = load_json(policy_path)
    _, complete, source_receipt = read_source(csv_path, source, policy)
    if not complete:
        raise ValueError("no_complete_case_candidates")

    stats = score_statistics(complete, policy)
    fold_results = []
    for budget in policy["budgets"]:
        for heldout in policy["groups"]:
            fold_results.append(
                evaluate_fold(complete, policy, stats, heldout, float(budget))
            )

    primary_budget = float(policy["primary_budget"])
    primary_folds = [
        fold for fold in fold_results if float(fold["budget"]) == primary_budget
    ]
    primary = primary_verdict(
        primary_folds,
        float(source_receipt["complete_case_coverage_fraction"]),
        policy["primary_success_criteria"],
    )

    score = {
        "schema": "openline.cpg002.gdpa1_score.v0.1",
        "experiment_id": "CPG-002",
        "source_sha256": source_receipt["source_sha256"],
        "policy_sha256": source_receipt["policy_sha256"],
        "observed_candidate_count": source_receipt["unique_candidate_count"],
        "complete_case_candidate_count": source_receipt["complete_case_candidate_count"],
        "complete_case_coverage_fraction": source_receipt["complete_case_coverage_fraction"],
        "score_statistics": stats,
        "fold_results": fold_results,
        "primary_verdict": primary,
        "clinical_labels_read": False,
    }
    verdict = {
        "schema": "openline.cpg002.gdpa1_verdict.v0.1",
        "experiment_id": "CPG-002",
        "verdict": primary["verdict"],
        "scientific_result_is_ci_failure": False,
        "policy_authority": "NONE",
        "source_sha256": source_receipt["source_sha256"],
        "score_sha256": sha256_json(score),
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
    if verdict["verdict"] not in ALLOWED_VERDICTS:
        raise ValueError(f"unexpected_verdict:{verdict['verdict']}")
    return source_receipt, score, verdict
