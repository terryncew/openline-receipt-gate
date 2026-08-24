from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import math
import random
import statistics
import sys
import unicodedata
from pathlib import Path
from typing import Any, Mapping, Sequence

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


class ExternalSelectorError(ValueError):
    pass


def load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def canonical_json_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def normalize_name(value: str) -> str:
    return unicodedata.normalize("NFC", str(value).strip()).casefold()


def parse_float(value: Any) -> float | None:
    text = "" if value is None else str(value).strip()
    if not text or text.casefold() in {"na", "n/a", "nan", "none", "null"}:
        return None
    try:
        number = float(text)
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def load_frozen_selector(config: Mapping[str, Any]):
    path = REPO / config["discovery_parent"]["frozen_selector_path"]
    expected = config["discovery_parent"]["frozen_selector_sha256"]
    observed = sha256_file(path)
    if observed != expected:
        raise ExternalSelectorError(
            f"frozen_selector_hash_mismatch:{observed}!={expected}"
        )
    spec = importlib.util.spec_from_file_location(
        "openline_frozen_jain_selector_external001", path
    )
    if spec is None or spec.loader is None:
        raise ExternalSelectorError("cannot_load_frozen_selector")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def verify_bound_inputs(
    config: Mapping[str, Any],
    source_contract_path: Path,
    policy_path: Path,
    jain_cohort_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    source_contract = load_json(source_contract_path)
    policy = load_json(policy_path)
    cohort = load_json(jain_cohort_path)

    if sha256_file(source_contract_path) != config["external_source"]["source_contract_sha256"]:
        raise ExternalSelectorError("source_contract_hash_mismatch")
    if sha256_file(policy_path) != config["external_policy"]["policy_sha256"]:
        raise ExternalSelectorError("external_policy_hash_mismatch")

    candidate_ids = sorted(normalize_name(v) for v in cohort["candidate_ids"])
    if canonical_json_sha256(candidate_ids) != config["discovery_parent"]["jain_candidate_ids_sha256"]:
        raise ExternalSelectorError("jain_candidate_id_hash_mismatch")
    return source_contract, policy, cohort


def _policy_specs(policy: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for group, specs in policy["groups"].items():
        for spec in specs:
            assay = str(spec["assay"])
            if assay in out:
                raise ExternalSelectorError(f"duplicate_policy_assay:{assay}")
            out[assay] = {**spec, "group": group}
    return out


def build_thresholds(policy: Mapping[str, Any], frozen_module, assay_order: Sequence[str]):
    specs = _policy_specs(policy)
    if set(specs) != set(assay_order):
        raise ExternalSelectorError("external_assay_policy_set_mismatch")
    thresholds = {}
    for assay in assay_order:
        spec = specs[assay]
        direction = spec["warning_direction"]
        if direction == "LOWER":
            operator = ">="
        elif direction == "UPPER":
            operator = "<="
        else:
            raise ExternalSelectorError(f"unsupported_warning_direction:{direction}")
        thresholds[assay] = frozen_module.Threshold(
            operator=operator,
            value=float(spec["threshold"]),
        )
    return thresholds

def preflight_cohort_counts(
    candidates: Sequence[Mapping[str, Any]],
    thresholds: Mapping[str, Any],
    assay_order: Sequence[str],
    frozen_module,
) -> dict[str, int]:
    original_order = tuple(frozen_module.ASSAY_ORDER)
    frozen_module.ASSAY_ORDER = tuple(assay_order)
    try:
        _, flags = frozen_module.build_liability_matrix(candidates, thresholds)
    finally:
        frozen_module.ASSAY_ORDER = original_order
    positive = sum(int(any(row.values())) for row in flags.values())
    total = len(flags)
    return {
        "candidate_count": total,
        "liability_positive_count": positive,
        "liability_negative_count": total - positive,
    }


def cohort_ready(counts: Mapping[str, int], config: Mapping[str, Any]) -> bool:
    rule = config["missingness"]
    return (
        int(counts["candidate_count"]) >= int(rule["minimum_primary_candidate_count"])
        and int(counts["liability_positive_count"]) >= int(rule["minimum_liability_positive_count"])
        and int(counts["liability_negative_count"]) >= int(rule["minimum_liability_negative_count"])
    )


def inconclusive_grade(counts: Mapping[str, int], config: Mapping[str, Any]):
    grade_obj = {
        "schema": "openline.trial_selector.external001.grade.v1",
        "experiment_id": config["experiment_id"],
        "primary_candidate_count": int(counts["candidate_count"]),
        "liability_positive_count": int(counts["liability_positive_count"]),
        "liability_negative_count": int(counts["liability_negative_count"]),
        "cohort_ready": False,
        "selector": "continuous_value_conditional_risk",
        "selector_mean_assays_to_first_liability": None,
        "baseline_mean_assays_to_first_liability": {},
        "selector_strictly_lower_than_every_baseline": False,
        "efficiency_champion_baseline": None,
        "champion_mean_assays_to_first_liability": None,
        "paired_bootstrap": None,
        "bootstrap_lower_bound_gt_zero": False,
        "safety_budget": int(config["primary_evaluation"]["safety_budget"]),
        "selector_false_reassurance_fraction": None,
        "champion_false_reassurance_fraction": None,
        "safety_nonworse_than_champion": False,
        "verdict": "INCONCLUSIVE_EXTERNAL_COHORT",
    }
    verdict = {
        "schema": "openline.trial_selector.external001.verdict.v1",
        "experiment_id": config["experiment_id"],
        "verdict": "INCONCLUSIVE_EXTERNAL_COHORT",
        "scientific_result_is_ci_failure": False,
        "policy_authority": "NONE",
        "claim_boundary": config["claim_boundary"],
        "stop_rule": (
            "Do not retune the frozen Jain selector, Ginkgo thresholds, overlap "
            "rule, missingness rule, comparator set, information-gain rule, or "
            "verdict gate against this result."
        ),
    }
    return grade_obj, verdict


def load_primary_candidates(
    csv_path: Path,
    config: Mapping[str, Any],
    source_contract: Mapping[str, Any],
    policy: Mapping[str, Any],
    jain_cohort: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    data = csv_path.read_bytes()
    if len(data) != int(config["external_source"]["byte_length"]):
        raise ExternalSelectorError("external_source_byte_length_mismatch")
    observed_blob = git_blob_sha1(data)
    if observed_blob != config["external_source"]["git_blob_sha1"]:
        raise ExternalSelectorError("external_source_git_blob_mismatch")

    assay_order = list(config["assay_mapping"]["assay_order"])
    jain_ids = {normalize_name(v) for v in jain_cohort["candidate_ids"]}

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        required = {"antibody_id", "antibody_name", *assay_order}
        missing_fields = sorted(required - set(fields))
        if missing_fields:
            raise ExternalSelectorError(
                "external_source_missing_columns:" + ",".join(missing_fields)
            )

        observed_rows = 0
        ids_seen: set[str] = set()
        overlaps: list[dict[str, str]] = []
        nonoverlap_rows = 0
        primary: list[dict[str, Any]] = []
        excluded_missing: list[str] = []

        for raw in reader:
            observed_rows += 1
            cid = str(raw["antibody_id"]).strip()
            name = str(raw["antibody_name"]).strip()
            if not cid:
                raise ExternalSelectorError("empty_external_antibody_id")
            if cid in ids_seen:
                raise ExternalSelectorError(f"duplicate_external_antibody_id:{cid}")
            ids_seen.add(cid)
            if not name:
                raise ExternalSelectorError(f"empty_external_antibody_name:{cid}")

            normalized_name = normalize_name(name)
            if normalized_name in jain_ids:
                overlaps.append(
                    {
                        "antibody_id": cid,
                        "antibody_name": name,
                        "normalized_name": normalized_name,
                    }
                )
                continue

            nonoverlap_rows += 1
            assays = {assay: parse_float(raw.get(assay)) for assay in assay_order}
            if any(assays[a] is None for a in assay_order):
                excluded_missing.append(cid)
                continue

            primary.append(
                {
                    "candidate_id": cid,
                    "external_antibody_name": name,
                    "assays": {a: float(assays[a]) for a in assay_order},
                }
            )

    receipt = {
        "schema": "openline.trial_selector.external001.source_receipt.v1",
        "experiment_id": config["experiment_id"],
        "source_repository": config["external_source"]["repository"],
        "source_commit": config["external_source"]["commit"],
        "source_path": config["external_source"]["path"],
        "source_git_blob_sha1": observed_blob,
        "source_sha256": sha256_bytes(data),
        "source_bytes": len(data),
        "observed_row_count": observed_rows,
        "unique_antibody_id_count": len(ids_seen),
        "jain_overlap_match_rule": config["overlap_exclusion"]["match_rule"],
        "jain_overlap_count": len(overlaps),
        "jain_overlap": sorted(overlaps, key=lambda x: (x["normalized_name"], x["antibody_id"])),
        "nonoverlap_row_count": nonoverlap_rows,
        "complete_case_nonoverlap_count": len(primary),
        "excluded_nonoverlap_missing_count": len(excluded_missing),
        "excluded_nonoverlap_missing_antibody_ids": sorted(excluded_missing),
        "assay_order": assay_order,
        "clinical_status_columns_read": False,
        "imputation_used": False,
        "frozen_selector_sha256": config["discovery_parent"]["frozen_selector_sha256"],
        "external_policy_sha256": config["external_policy"]["policy_sha256"],
        "jain_candidate_ids_sha256": config["discovery_parent"]["jain_candidate_ids_sha256"],
    }
    return primary, receipt


def bernoulli_entropy_bits(p: float) -> float:
    p = min(1.0, max(0.0, float(p)))
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))


def expected_information_gain_trace(
    *,
    frozen_module,
    candidate_ids: Sequence[str],
    holdout: str,
    values: Mapping[str, Mapping[str, float]],
    flags: Mapping[str, Mapping[str, bool]],
    assay_order: Sequence[str],
) -> dict[str, Any]:
    train_ids = [cid for cid in candidate_ids if cid != holdout]
    observed: list[str] = []
    remaining = list(assay_order)
    steps: list[dict[str, Any]] = []

    while remaining:
        risks = frozen_module._predict_remaining_risks(
            train_ids=train_ids,
            holdout=holdout,
            observed=observed,
            remaining=remaining,
            values=values,
            flags=flags,
            binary_features=False,
        )
        information = {assay: bernoulli_entropy_bits(risks[assay]) for assay in remaining}
        assay = sorted(remaining, key=lambda a: (-information[a], a))[0]
        steps.append(
            {
                "step": len(steps) + 1,
                "assay": assay,
                "predicted_liability_probability": risks[assay],
                "expected_information_gain_bits": information[assay],
                "observed_value": values[holdout][assay],
                "liability": bool(flags[holdout][assay]),
            }
        )
        remaining.remove(assay)
        if flags[holdout][assay]:
            break
        observed.append(assay)

    return {
        "candidate_id": holdout,
        "has_any_liability": any(flags[holdout].values()),
        "assays_spent": len(steps),
        "steps": steps,
    }


def run_selector_family(
    candidates: Sequence[Mapping[str, Any]],
    thresholds: Mapping[str, Any],
    assay_order: Sequence[str],
    frozen_module,
) -> dict[str, Any]:
    original_order = tuple(frozen_module.ASSAY_ORDER)
    frozen_module.ASSAY_ORDER = tuple(assay_order)
    try:
        run = frozen_module.run_leave_one_out(candidates, thresholds)
        values, flags = frozen_module.build_liability_matrix(candidates, thresholds)
        candidate_ids = sorted(values)
        eig_traces = [
            expected_information_gain_trace(
                frozen_module=frozen_module,
                candidate_ids=candidate_ids,
                holdout=holdout,
                values=values,
                flags=flags,
                assay_order=assay_order,
            )
            for holdout in candidate_ids
        ]
        run["traces"]["expected_information_gain"] = eig_traces
        run["metrics"]["expected_information_gain"] = (
            frozen_module.summarize_deterministic_traces(eig_traces)
        )
        return run
    finally:
        frozen_module.ASSAY_ORDER = original_order


def positive_costs(
    run: Mapping[str, Any],
    assay_order: Sequence[str],
) -> dict[str, dict[str, float]]:
    positive_ids = sorted(
        cid
        for cid, assay_flags in run["liability_flags"].items()
        if any(bool(v) for v in assay_flags.values())
    )
    costs: dict[str, dict[str, float]] = {}
    for method, traces in run["traces"].items():
        by_id = {str(t["candidate_id"]): float(t["assays_spent"]) for t in traces}
        costs[method] = {cid: by_id[cid] for cid in positive_ids}

    n = len(assay_order)
    random_costs = {}
    for cid in positive_ids:
        k = sum(bool(v) for v in run["liability_flags"][cid].values())
        random_costs[cid] = (n + 1.0) / (k + 1.0)
    costs["uniform_random_expected"] = random_costs
    return costs


def champion_baseline(metrics: Mapping[str, Any], safety_budget: int) -> str:
    baseline_names = [
        "fixed_prevalence",
        "greedy_fixed_coverage",
        "uniform_random_expected",
        "binary_dynamic",
        "expected_information_gain",
    ]
    def key(name: str):
        metric = metrics[name]
        budget = metric["budgets"][str(safety_budget)]
        fr = (
            budget.get("false_reassurance_fraction")
            if "false_reassurance_fraction" in budget
            else budget["expected_false_reassurance_fraction"]
        )
        return (
            float(metric["mean_assays_to_first_liability_positive_only"]),
            float(fr),
            name,
        )
    return sorted(baseline_names, key=key)[0]


def _percentile(values: Sequence[float], q: float) -> float:
    ordered = sorted(float(v) for v in values)
    if not ordered:
        raise ExternalSelectorError("empty_percentile")
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def paired_bootstrap_improvement(
    selector_costs: Mapping[str, float],
    champion_costs: Mapping[str, float],
    *,
    replicates: int,
    seed: int,
) -> dict[str, Any]:
    ids = sorted(selector_costs)
    if ids != sorted(champion_costs):
        raise ExternalSelectorError("paired_cost_id_mismatch")
    if not ids:
        raise ExternalSelectorError("no_positive_candidates_for_bootstrap")
    rng = random.Random(seed)
    differences = [
        float(champion_costs[cid]) - float(selector_costs[cid]) for cid in ids
    ]
    observed = statistics.fmean(differences)
    boot = []
    for _ in range(replicates):
        sample = [differences[rng.randrange(len(differences))] for _ in differences]
        boot.append(statistics.fmean(sample))
    return {
        "sampling_unit_count": len(ids),
        "replicates": replicates,
        "seed": seed,
        "observed_mean_champion_minus_selector": observed,
        "percentile_95_lower": _percentile(boot, 0.025),
        "percentile_95_upper": _percentile(boot, 0.975),
    }


def _false_reassurance(metric: Mapping[str, Any], budget: int) -> float:
    item = metric["budgets"][str(budget)]
    if "false_reassurance_fraction" in item:
        return float(item["false_reassurance_fraction"])
    return float(item["expected_false_reassurance_fraction"])


def grade(
    run: Mapping[str, Any],
    config: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    metrics = run["metrics"]
    selector_name = "continuous_value_conditional_risk"
    selector_metric = metrics[selector_name]
    total = int(selector_metric["candidate_count"])
    positive = int(selector_metric["liability_positive_count"])
    negative = int(selector_metric["liability_negative_count"])

    admiss = config["missingness"]
    cohort_ready = (
        total >= int(admiss["minimum_primary_candidate_count"])
        and positive >= int(admiss["minimum_liability_positive_count"])
        and negative >= int(admiss["minimum_liability_negative_count"])
    )

    safety_budget = int(config["primary_evaluation"]["safety_budget"])
    champion = champion_baseline(metrics, safety_budget)
    baseline_names = [
        "fixed_prevalence",
        "greedy_fixed_coverage",
        "uniform_random_expected",
        "binary_dynamic",
        "expected_information_gain",
    ]
    selector_mean = float(selector_metric["mean_assays_to_first_liability_positive_only"])
    baseline_means = {
        name: float(metrics[name]["mean_assays_to_first_liability_positive_only"])
        for name in baseline_names
    }
    lower_than_every = all(selector_mean < value for value in baseline_means.values())

    costs = positive_costs(run, config["assay_mapping"]["assay_order"])
    bootstrap_cfg = config["primary_evaluation"]["bootstrap"]
    bootstrap = paired_bootstrap_improvement(
        costs[selector_name],
        costs[champion],
        replicates=int(bootstrap_cfg["replicates"]),
        seed=int(bootstrap_cfg["seed"]),
    )

    selector_fr = _false_reassurance(selector_metric, safety_budget)
    champion_fr = _false_reassurance(metrics[champion], safety_budget)
    bootstrap_pass = float(bootstrap["percentile_95_lower"]) > 0.0
    safety_pass = selector_fr <= champion_fr

    if not cohort_ready:
        verdict_name = "INCONCLUSIVE_EXTERNAL_COHORT"
    elif lower_than_every and bootstrap_pass and safety_pass:
        verdict_name = "EXTERNAL_ALLOCATION_SIGNAL"
    else:
        verdict_name = "EXTERNAL_GENERALIZATION_NOT_SUPPORTED"

    grade_obj = {
        "schema": "openline.trial_selector.external001.grade.v1",
        "experiment_id": config["experiment_id"],
        "primary_candidate_count": total,
        "liability_positive_count": positive,
        "liability_negative_count": negative,
        "cohort_ready": cohort_ready,
        "selector": selector_name,
        "selector_mean_assays_to_first_liability": selector_mean,
        "baseline_mean_assays_to_first_liability": baseline_means,
        "selector_strictly_lower_than_every_baseline": lower_than_every,
        "efficiency_champion_baseline": champion,
        "champion_mean_assays_to_first_liability": baseline_means[champion],
        "paired_bootstrap": bootstrap,
        "bootstrap_lower_bound_gt_zero": bootstrap_pass,
        "safety_budget": safety_budget,
        "selector_false_reassurance_fraction": selector_fr,
        "champion_false_reassurance_fraction": champion_fr,
        "safety_nonworse_than_champion": safety_pass,
        "verdict": verdict_name,
    }
    verdict = {
        "schema": "openline.trial_selector.external001.verdict.v1",
        "experiment_id": config["experiment_id"],
        "verdict": verdict_name,
        "scientific_result_is_ci_failure": False,
        "policy_authority": "NONE",
        "claim_boundary": config["claim_boundary"],
        "stop_rule": (
            "Do not retune the frozen Jain selector, Ginkgo thresholds, overlap "
            "rule, missingness rule, comparator set, information-gain rule, or "
            "verdict gate against this result."
        ),
    }
    return grade_obj, verdict


def run_external(
    *,
    csv_path: Path,
    config_path: Path,
    source_contract_path: Path,
    policy_path: Path,
    jain_cohort_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    config = load_json(config_path)
    source_contract, policy, cohort = verify_bound_inputs(
        config, source_contract_path, policy_path, jain_cohort_path
    )
    frozen = load_frozen_selector(config)
    candidates, source_receipt = load_primary_candidates(
        csv_path, config, source_contract, policy, cohort
    )
    thresholds = build_thresholds(
        policy, frozen, config["assay_mapping"]["assay_order"]
    )
    counts = preflight_cohort_counts(
        candidates,
        thresholds,
        config["assay_mapping"]["assay_order"],
        frozen,
    )
    if not cohort_ready(counts, config):
        grade_obj, verdict = inconclusive_grade(counts, config)
        result = {
            "schema": "openline.trial_selector.external001.result.v1",
            "experiment_id": config["experiment_id"],
            "status": "EXTERNAL_COHORT_INADMISSIBLE",
            "source_receipt_sha256": canonical_json_sha256(source_receipt),
            "config_sha256": sha256_file(config_path),
            "frozen_selector_sha256": config["discovery_parent"]["frozen_selector_sha256"],
            "external_policy_sha256": config["external_policy"]["policy_sha256"],
            "candidate_ids": sorted(row["candidate_id"] for row in candidates),
            "metrics": {},
            "traces": {},
            "grade": grade_obj,
            "claim_boundary": config["claim_boundary"],
            "policy_authority": "NONE",
        }
    else:
        run = run_selector_family(
            candidates,
            thresholds,
            config["assay_mapping"]["assay_order"],
            frozen,
        )
        grade_obj, verdict = grade(run, config)
        result = {
            "schema": "openline.trial_selector.external001.result.v1",
            "experiment_id": config["experiment_id"],
            "status": "EXTERNAL_CONFIRMATION_EXECUTED",
            "source_receipt_sha256": canonical_json_sha256(source_receipt),
            "config_sha256": sha256_file(config_path),
            "frozen_selector_sha256": config["discovery_parent"]["frozen_selector_sha256"],
            "external_policy_sha256": config["external_policy"]["policy_sha256"],
            "candidate_ids": run["candidate_ids"],
            "metrics": run["metrics"],
            "traces": run["traces"],
            "grade": grade_obj,
            "claim_boundary": config["claim_boundary"],
            "policy_authority": "NONE",
        }
    verdict["result_sha256"] = canonical_json_sha256(result)
    return source_receipt, result, verdict
