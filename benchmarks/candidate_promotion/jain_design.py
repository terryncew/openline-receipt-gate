from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


THRESHOLDED_ASSAYS = (
    "PSR",
    "AC_SINS",
    "CSI_BLI",
    "CIC",
    "HIC",
    "SMAC",
    "SGAC_SINS",
    "BVP",
    "ELISA",
    "AS",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def flatten_thresholds(thresholds: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    flat: dict[str, dict[str, Any]] = {}
    for group_name, rules in thresholds["groups"].items():
        for rule in rules:
            assay = str(rule["assay_type"])
            if assay in flat:
                raise ValueError(f"duplicate threshold assay: {assay}")
            flat[assay] = {**dict(rule), "group": group_name}
    return flat


def validate_design_lock(lock: Mapping[str, Any], thresholds: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if lock.get("experiment_id") != "CPG-001":
        errors.append("wrong_experiment_id")
    if lock.get("dataset") != "JAIN_2017":
        errors.append("wrong_dataset")
    if 0.25 != lock.get("primary_budget"):
        errors.append("primary_budget_not_0.25")
    if lock.get("selection_budgets") != [0.10, 0.25, 0.50]:
        errors.append("selection_budgets_changed")
    affinity_text = canonical_json(lock.get("out_of_scope", [])) + " " + str(lock.get("affinity_boundary", ""))
    if "affinity" not in affinity_text.lower():
        errors.append("affinity_boundary_missing")
    flat = flatten_thresholds(thresholds)
    if set(flat) != set(THRESHOLDED_ASSAYS):
        errors.append("threshold_assay_set_changed")
    if set(lock.get("folds", [])) != set(thresholds.get("groups", {})):
        errors.append("fold_groups_do_not_match_threshold_groups")
    criteria = lock.get("primary_success_criteria", {})
    for required in ("masked_liability_reduction", "yield", "heldout_quality", "coverage", "secondary_budgets"):
        if required not in criteria:
            errors.append(f"missing_success_criterion:{required}")
    correlation = lock.get("correlation_audit", {})
    if correlation.get("statistical_independence_assumed") is not False:
        errors.append("statistical_independence_must_be_false")
    return sorted(errors)


def complete_case_candidates(candidates: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    included: list[dict[str, Any]] = []
    excluded: list[str] = []
    for row in candidates:
        cid = str(row.get("candidate_id", ""))
        assays = row.get("assays", {})
        if not cid or not isinstance(assays, Mapping):
            excluded.append(cid or "<missing_candidate_id>")
            continue
        if all(_finite_number(assays.get(name)) for name in THRESHOLDED_ASSAYS):
            included.append(dict(row))
        else:
            excluded.append(cid)
    included.sort(key=lambda row: str(row["candidate_id"]))
    excluded.sort()
    return included, excluded


def sample_mean_sd(values: Sequence[float]) -> tuple[float, float]:
    if len(values) < 2:
        raise ValueError("need at least two values for sample SD")
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    sd = math.sqrt(variance)
    return mean, sd


def assay_direction(rule: Mapping[str, Any]) -> float:
    op = str(rule["operator"])
    if op in ("<=", "<"):
        return -1.0
    if op in (">=", ">"):
        return 1.0
    raise ValueError(f"unsupported operator: {op}")


def composite_scores(
    candidates: Sequence[Mapping[str, Any]],
    gated_assays: Sequence[str],
    threshold_map: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, float], dict[str, dict[str, float]]]:
    stats: dict[str, dict[str, float]] = {}
    for assay in gated_assays:
        values = [float(row["assays"][assay]) for row in candidates]
        mean, sd = sample_mean_sd(values)
        stats[assay] = {"mean": mean, "sample_sd": sd, "direction": assay_direction(threshold_map[assay])}

    scores: dict[str, float] = {}
    for row in candidates:
        parts = []
        for assay in gated_assays:
            stat = stats[assay]
            x = float(row["assays"][assay])
            if stat["sample_sd"] == 0:
                parts.append(0.0)
            else:
                parts.append(stat["direction"] * (x - stat["mean"]) / stat["sample_sd"])
        scores[str(row["candidate_id"])] = sum(parts) / len(parts)
    return scores, stats


def threshold_pass(value: float, rule: Mapping[str, Any]) -> bool:
    op = str(rule["operator"])
    threshold = float(rule["threshold"])
    if op == "<=":
        return value <= threshold
    if op == "<":
        return value < threshold
    if op == ">=":
        return value >= threshold
    if op == ">":
        return value > threshold
    raise ValueError(f"unsupported operator: {op}")


def failed_groups(
    row: Mapping[str, Any],
    groups: Mapping[str, Sequence[Mapping[str, Any]]],
    only_groups: Iterable[str] | None = None,
) -> list[str]:
    allowed = set(only_groups) if only_groups is not None else set(groups)
    failed: list[str] = []
    for group_name, rules in groups.items():
        if group_name not in allowed:
            continue
        if any(not threshold_pass(float(row["assays"][str(rule["assay_type"])]), rule) for rule in rules):
            failed.append(group_name)
    return sorted(failed)


def _rank(candidate_ids: Iterable[str], scores: Mapping[str, float]) -> list[str]:
    return sorted(candidate_ids, key=lambda cid: (-scores[cid], cid))


def _ceil_k(n: int, budget: float) -> int:
    return int(math.ceil(n * budget))


def evaluate_fold(
    candidates: Sequence[Mapping[str, Any]],
    thresholds: Mapping[str, Any],
    heldout_group: str,
    budget: float,
) -> dict[str, Any]:
    groups = thresholds["groups"]
    if heldout_group not in groups:
        raise ValueError(f"unknown heldout group: {heldout_group}")
    gated_groups = [group for group in groups if group != heldout_group]
    threshold_map = flatten_thresholds(thresholds)
    gated_assays = [
        str(rule["assay_type"])
        for group in gated_groups
        for rule in groups[group]
    ]
    scores, score_stats = composite_scores(candidates, gated_assays, threshold_map)
    ids = [str(row["candidate_id"]) for row in candidates]
    by_id = {str(row["candidate_id"]): row for row in candidates}
    k = _ceil_k(len(candidates), budget)

    control_ids = _rank(ids, scores)[:k]
    gate_eligible = [cid for cid in ids if not failed_groups(by_id[cid], groups, gated_groups)]
    treatment_ids = _rank(gate_eligible, scores)[:k]
    constrained_ids = _rank(gate_eligible, scores)[:k]

    def selected_metrics(selected: Sequence[str]) -> dict[str, Any]:
        if not selected:
            return {
                "selected": [],
                "gated_property_group_liability_rate": 0.0,
                "heldout_property_group_flag_rate": None,
                "approved_2017_count": 0,
                "approved_2017_selection_rate": None,
            }
        gated_bad = sum(bool(failed_groups(by_id[cid], groups, gated_groups)) for cid in selected)
        heldout_bad = sum(bool(failed_groups(by_id[cid], groups, [heldout_group])) for cid in selected)
        approval_values = [by_id[cid].get("approved_2017") for cid in selected]
        approval_known = [value for value in approval_values if isinstance(value, bool)]
        approved_count = sum(value is True for value in approval_known)
        return {
            "selected": list(selected),
            "gated_property_group_liability_rate": gated_bad / len(selected),
            "heldout_property_group_flag_rate": heldout_bad / len(selected),
            "approved_2017_count": approved_count,
            "approved_2017_selection_rate": (approved_count / len(approval_known)) if approval_known else None,
        }

    control = selected_metrics(control_ids)
    treatment = selected_metrics(treatment_ids)
    treatment["top_k_fill_rate"] = len(treatment_ids) / k if k else 1.0
    treatment["eligible_candidate_yield"] = len(gate_eligible) / len(candidates) if candidates else None

    return {
        "heldout_group": heldout_group,
        "budget": budget,
        "candidate_count": len(candidates),
        "top_k": k,
        "gated_groups": gated_groups,
        "gated_assays": gated_assays,
        "score_statistics": score_stats,
        "control": control,
        "treatment": treatment,
        "authority_parity_control": {
            "selected": constrained_ids,
            "matches_treatment": constrained_ids == treatment_ids,
        },
    }


def _average(values: Sequence[float | None]) -> float | None:
    usable = [float(value) for value in values if value is not None]
    return sum(usable) / len(usable) if usable else None


def primary_verdict(
    fold_results: Sequence[Mapping[str, Any]],
    coverage_fraction: float,
) -> dict[str, Any]:
    primary = [result for result in fold_results if abs(float(result["budget"]) - 0.25) < 1e-12]
    if len(primary) != 4:
        raise ValueError("primary verdict requires exactly four 25% folds")

    parity = all(bool(result["authority_parity_control"]["matches_treatment"]) for result in primary)
    reductions = []
    fill_pass = []
    heldout_pass = []
    control_heldout = []
    treatment_heldout = []
    treatment_fill = []
    for result in primary:
        c = float(result["control"]["gated_property_group_liability_rate"])
        t = float(result["treatment"]["gated_property_group_liability_rate"])
        reductions.append((c - t) >= 0.10 - 1e-12)
        fill = float(result["treatment"]["top_k_fill_rate"])
        treatment_fill.append(fill)
        fill_pass.append(fill >= 0.80 - 1e-12)
        ch_raw = result["control"]["heldout_property_group_flag_rate"]
        th_raw = result["treatment"]["heldout_property_group_flag_rate"]
        ch = None if ch_raw is None else float(ch_raw)
        th = None if th_raw is None else float(th_raw)
        control_heldout.append(ch)
        treatment_heldout.append(th)
        heldout_pass.append(ch is not None and th is not None and th <= ch + 0.05 + 1e-12)

    pooled_fill = _average(treatment_fill)
    pooled_control_heldout = _average(control_heldout)
    pooled_treatment_heldout = _average(treatment_heldout)
    compensation_signal = sum(reductions) >= 3
    yield_ok = sum(fill_pass) >= 3 and pooled_fill is not None and pooled_fill >= 0.80 - 1e-12
    heldout_ok = (
        sum(heldout_pass) >= 3
        and pooled_control_heldout is not None
        and pooled_treatment_heldout is not None
        and pooled_treatment_heldout <= pooled_control_heldout + 1e-12
    )

    if not parity:
        verdict = "IMPLEMENTATION_MISMATCH"
    elif coverage_fraction < 0.70:
        verdict = "INCONCLUSIVE_COVERAGE"
    elif not compensation_signal:
        verdict = "NO_COMPENSATION_SIGNAL"
    elif yield_ok and heldout_ok:
        verdict = "SUPPORTED_WITHIN_SCOPE"
    else:
        verdict = "FRICTION_ONLY"

    return {
        "verdict": verdict,
        "coverage_fraction": coverage_fraction,
        "compensation_signal_pass": compensation_signal,
        "folds_with_ge_10pp_reduction": sum(reductions),
        "yield_pass": yield_ok,
        "folds_with_fill_ge_0_80": sum(fill_pass),
        "pooled_fill_rate": pooled_fill,
        "heldout_quality_pass": heldout_ok,
        "folds_with_heldout_within_5pp": sum(heldout_pass),
        "pooled_control_heldout_flag_rate": pooled_control_heldout,
        "pooled_treatment_heldout_flag_rate": pooled_treatment_heldout,
        "authority_parity_pass": parity,
    }


def _rankdata(values: Sequence[float]) -> list[float]:
    indexed = sorted(enumerate(values), key=lambda item: item[1])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(indexed):
        j = i + 1
        while j < len(indexed) and indexed[j][1] == indexed[i][1]:
            j += 1
        avg_rank = ((i + 1) + j) / 2.0
        for k in range(i, j):
            ranks[indexed[k][0]] = avg_rank
        i = j
    return ranks


def _pearson(x: Sequence[float], y: Sequence[float]) -> float:
    if len(x) != len(y) or len(x) < 2:
        raise ValueError("correlation requires equal-length vectors with at least two values")
    mx = sum(x) / len(x)
    my = sum(y) / len(y)
    dx = [v - mx for v in x]
    dy = [v - my for v in y]
    denom = math.sqrt(sum(v * v for v in dx) * sum(v * v for v in dy))
    if denom == 0:
        return 0.0
    return sum(a * b for a, b in zip(dx, dy)) / denom


def spearman(x: Sequence[float], y: Sequence[float]) -> float:
    return _pearson(_rankdata(x), _rankdata(y))


def correlation_audit(candidates: Sequence[Mapping[str, Any]], threshold: float = 0.70) -> dict[str, Any]:
    pairs: list[dict[str, Any]] = []
    for i, left in enumerate(THRESHOLDED_ASSAYS):
        for right in THRESHOLDED_ASSAYS[i + 1 :]:
            x = [float(row["assays"][left]) for row in candidates]
            y = [float(row["assays"][right]) for row in candidates]
            rho = spearman(x, y)
            if abs(rho) >= threshold:
                pairs.append({"left": left, "right": right, "spearman_rho": rho})
    pairs.sort(key=lambda item: (-abs(float(item["spearman_rho"])), item["left"], item["right"]))
    return {
        "schema": "openline.cpg001.jain_correlation_audit.v0.1",
        "candidate_count": len(candidates),
        "threshold_abs_rho": threshold,
        "high_correlation_pairs": pairs,
        "statistical_independence_assumed": False,
        "policy_mutation_allowed": False,
    }


def run_confirmatory(
    normalized: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    design_lock: Mapping[str, Any],
) -> dict[str, Any]:
    errors = validate_design_lock(design_lock, thresholds)
    if errors:
        raise ValueError("invalid design lock: " + ",".join(errors))
    if normalized.get("schema") != "openline.cpg001.jain_normalized.v0.1":
        raise ValueError("unsupported normalized Jain schema")
    expected_lock_hash = sha256_json(design_lock)
    expected_threshold_hash = sha256_json(thresholds)
    if normalized.get("design_lock_sha256") != expected_lock_hash:
        raise ValueError("design_lock_hash_mismatch")
    if normalized.get("thresholds_sha256") != expected_threshold_hash:
        raise ValueError("thresholds_hash_mismatch")
    candidates_raw = normalized.get("candidates")
    if not isinstance(candidates_raw, list):
        raise ValueError("candidates must be an array")
    complete, excluded = complete_case_candidates(candidates_raw)
    if not complete:
        raise ValueError("no complete-case candidates")
    coverage_fraction = len(complete) / 137.0
    corr = correlation_audit(complete)
    fold_results = [
        evaluate_fold(complete, thresholds, heldout, budget)
        for budget in design_lock["selection_budgets"]
        for heldout in design_lock["folds"]
    ]
    verdict = primary_verdict(fold_results, coverage_fraction)
    return {
        "schema": "openline.cpg001.jain_confirmatory.v0.1",
        "experiment_id": "CPG-001",
        "claim_scope": "developability_only",
        "affinity_in_scope": False,
        "design_lock_sha256": expected_lock_hash,
        "thresholds_sha256": expected_threshold_hash,
        "source_artifacts": normalized.get("source_artifacts", []),
        "published_candidate_count": 137,
        "complete_case_candidate_count": len(complete),
        "excluded_for_missing_thresholded_assay": excluded,
        "complete_case_coverage_fraction": coverage_fraction,
        "correlation_audit": corr,
        "fold_results": fold_results,
        "primary_verdict": verdict,
    }
