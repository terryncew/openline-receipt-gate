from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
import unicodedata
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def canonical_sha(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def norm(value: str) -> str:
    return unicodedata.normalize("NFC", str(value).strip()).casefold()


def pfloat(raw):
    text = "" if raw is None else str(raw).strip()
    if not text or text.casefold() in {"na", "n/a", "nan", "none", "null"}:
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def policy_specs(policy):
    out = {}
    for group, specs in policy["groups"].items():
        for spec in specs:
            if spec["assay"] in out:
                raise ValueError("duplicate_policy_assay")
            out[spec["assay"]] = dict(spec, group=group)
    return out


def liability(value, spec):
    if spec["warning_direction"] == "LOWER":
        return float(value) < float(spec["threshold"])
    if spec["warning_direction"] == "UPPER":
        return float(value) > float(spec["threshold"])
    raise ValueError("unsupported_warning_direction")


def read_primary(csv_path, config, policy, cohort):
    data = csv_path.read_bytes()
    if len(data) != int(config["external_source"]["byte_length"]):
        raise ValueError("byte_length_mismatch")
    blob = git_blob_sha1(data)
    if blob != config["external_source"]["git_blob_sha1"]:
        raise ValueError("blob_mismatch")

    assays = list(config["assay_mapping"]["assay_order"])
    jain_ids = {norm(v) for v in cohort["candidate_ids"]}
    ids = set()
    overlap, excluded, primary = [], [], []

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        required = {"antibody_id", "antibody_name", *assays}
        if not required.issubset(set(fields)):
            raise ValueError("missing_source_column")
        observed = 0
        nonoverlap = 0
        for raw in reader:
            observed += 1
            cid = str(raw["antibody_id"]).strip()
            name = str(raw["antibody_name"]).strip()
            if not cid or cid in ids or not name:
                raise ValueError("bad_identity")
            ids.add(cid)
            nname = norm(name)
            if nname in jain_ids:
                overlap.append({
                    "antibody_id": cid,
                    "antibody_name": name,
                    "normalized_name": nname,
                })
                continue
            nonoverlap += 1
            values = {a: pfloat(raw.get(a)) for a in assays}
            if any(values[a] is None for a in assays):
                excluded.append(cid)
                continue
            primary.append({
                "candidate_id": cid,
                "external_antibody_name": name,
                "assays": {a: float(values[a]) for a in assays},
            })

    receipt = {
        "schema": "openline.trial_selector.external001.source_receipt.v1",
        "experiment_id": config["experiment_id"],
        "source_repository": config["external_source"]["repository"],
        "source_commit": config["external_source"]["commit"],
        "source_path": config["external_source"]["path"],
        "source_git_blob_sha1": blob,
        "source_sha256": sha256_bytes(data),
        "source_bytes": len(data),
        "observed_row_count": observed,
        "unique_antibody_id_count": len(ids),
        "jain_overlap_match_rule": config["overlap_exclusion"]["match_rule"],
        "jain_overlap_count": len(overlap),
        "jain_overlap": sorted(overlap, key=lambda x: (x["normalized_name"], x["antibody_id"])),
        "nonoverlap_row_count": nonoverlap,
        "complete_case_nonoverlap_count": len(primary),
        "excluded_nonoverlap_missing_count": len(excluded),
        "excluded_nonoverlap_missing_antibody_ids": sorted(excluded),
        "assay_order": assays,
        "clinical_status_columns_read": False,
        "imputation_used": False,
        "frozen_selector_sha256": config["discovery_parent"]["frozen_selector_sha256"],
        "external_policy_sha256": config["external_policy"]["policy_sha256"],
        "jain_candidate_ids_sha256": config["discovery_parent"]["jain_candidate_ids_sha256"],
    }
    return primary, receipt


def build_values_flags(candidates, policy, assays):
    specs = policy_specs(policy)
    values, flags = {}, {}
    for row in candidates:
        cid = row["candidate_id"]
        values[cid] = {}
        flags[cid] = {}
        for assay in assays:
            value = float(row["assays"][assay])
            values[cid][assay] = value
            flags[cid][assay] = liability(value, specs[assay])
    return values, flags


def prevalence(flags, train_ids, assay):
    return sum(bool(flags[cid][assay]) for cid in train_ids) / len(train_ids)


def risks(train_ids, holdout, observed, remaining, values, flags, binary):
    if not observed:
        return {a: prevalence(flags, train_ids, a) for a in remaining}
    if binary:
        x_train = np.asarray(
            [[float(flags[cid][f]) for f in observed] for cid in train_ids],
            dtype=float,
        )
        x_holdout = np.asarray(
            [[float(flags[holdout][f]) for f in observed]], dtype=float
        )
    else:
        x_train = np.asarray(
            [[float(values[cid][f]) for f in observed] for cid in train_ids],
            dtype=float,
        )
        x_holdout = np.asarray(
            [[float(values[holdout][f]) for f in observed]], dtype=float
        )

    out = {}
    for assay in remaining:
        y = np.asarray([int(flags[cid][assay]) for cid in train_ids], dtype=int)
        if len(set(int(v) for v in y.tolist())) < 2:
            out[assay] = float(y[0])
            continue
        model = make_pipeline(
            StandardScaler(),
            LogisticRegression(
                penalty="l2",
                C=1.0,
                solver="liblinear",
                fit_intercept=True,
                class_weight=None,
                max_iter=1000,
                random_state=0,
            ),
        )
        model.fit(x_train, y)
        out[assay] = float(model.predict_proba(x_holdout)[0, 1])
    return out


def entropy(p):
    p = min(1.0, max(0.0, float(p)))
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -(p * math.log2(p) + (1.0-p) * math.log2(1.0-p))


def dynamic_trace(ids, holdout, values, flags, assays, binary=False, eig=False):
    train_ids = [cid for cid in ids if cid != holdout]
    observed, remaining, steps = [], list(assays), []
    while remaining:
        r = risks(train_ids, holdout, observed, remaining, values, flags, binary)
        if eig:
            info = {a: entropy(r[a]) for a in remaining}
            assay = sorted(remaining, key=lambda a: (-info[a], a))[0]
        else:
            info = None
            assay = sorted(remaining, key=lambda a: (-r[a], a))[0]
        step = {
            "step": len(steps) + 1,
            "assay": assay,
            "predicted_liability_probability": r[assay],
            "observed_value": values[holdout][assay],
            "liability": bool(flags[holdout][assay]),
        }
        if eig:
            step["expected_information_gain_bits"] = info[assay]
        steps.append(step)
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


def fixed_order_prevalence(flags, train_ids, assays):
    return sorted(
        assays,
        key=lambda a: (-prevalence(flags, train_ids, a), a),
    )


def fixed_order_greedy(flags, train_ids, assays):
    remaining = set(assays)
    covered, order = set(), []
    while remaining:
        assay = sorted(
            remaining,
            key=lambda a: (
                -sum(bool(flags[cid][a]) and cid not in covered for cid in train_ids),
                a,
            ),
        )[0]
        order.append(assay)
        remaining.remove(assay)
        covered.update(cid for cid in train_ids if flags[cid][assay])
    return order


def fixed_trace(order, holdout, values, flags):
    steps = []
    for assay in order:
        steps.append({
            "step": len(steps) + 1,
            "assay": assay,
            "observed_value": values[holdout][assay],
            "liability": bool(flags[holdout][assay]),
        })
        if flags[holdout][assay]:
            break
    return {
        "candidate_id": holdout,
        "has_any_liability": any(flags[holdout].values()),
        "assays_spent": len(steps),
        "steps": steps,
    }


def summarize(traces, budgets=(1,2,3,4,5)):
    positive = [t for t in traces if t["has_any_liability"]]
    out = {
        "candidate_count": len(traces),
        "liability_positive_count": len(positive),
        "liability_negative_count": len(traces)-len(positive),
        "mean_assays_to_first_liability_positive_only":
            sum(float(t["assays_spent"]) for t in positive) / len(positive),
        "budgets": {},
    }
    for budget in budgets:
        detected = sum(
            int(t["has_any_liability"] and int(t["assays_spent"]) <= budget)
            for t in traces
        )
        survivors = [t for t in traces if int(t["assays_spent"]) > budget]
        hidden = sum(int(t["has_any_liability"]) for t in survivors)
        out["budgets"][str(budget)] = {
            "positive_detected_count": detected,
            "positive_detected_fraction": detected / len(positive),
            "survivor_count": len(survivors),
            "hidden_liability_count": hidden,
            "false_reassurance_fraction": hidden / len(survivors) if survivors else 0.0,
        }
    return out


def random_summary(flags, ids, assays, budgets=(1,2,3,4,5)):
    n = len(assays)
    positive = [cid for cid in ids if any(flags[cid].values())]
    costs = []
    for cid in positive:
        k = sum(bool(flags[cid][a]) for a in assays)
        costs.append((n+1)/(k+1))
    out = {
        "candidate_count": len(ids),
        "liability_positive_count": len(positive),
        "liability_negative_count": len(ids)-len(positive),
        "mean_assays_to_first_liability_positive_only": sum(costs)/len(costs),
        "budgets": {},
        "method": "analytic uniform random permutation expectation",
    }
    negatives = len(ids)-len(positive)
    for budget in budgets:
        exp_pos_surv = 0.0
        for cid in positive:
            k = sum(bool(flags[cid][a]) for a in assays)
            survive = (
                0.0 if budget > n-k
                else math.comb(n-k, budget)/math.comb(n, budget)
            )
            exp_pos_surv += survive
        exp_detected = len(positive)-exp_pos_surv
        exp_survivors = negatives+exp_pos_surv
        out["budgets"][str(budget)] = {
            "expected_positive_detected_count": exp_detected,
            "expected_positive_detected_fraction": exp_detected/len(positive),
            "expected_survivor_count": exp_survivors,
            "expected_hidden_liability_count": exp_pos_surv,
            "expected_false_reassurance_fraction":
                exp_pos_surv/exp_survivors if exp_survivors else 0.0,
        }
    return out


def rebuild(candidates, policy, config):
    assays = list(config["assay_mapping"]["assay_order"])
    values, flags = build_values_flags(candidates, policy, assays)
    ids = sorted(values)
    traces = {
        "fixed_prevalence": [],
        "greedy_fixed_coverage": [],
        "binary_dynamic": [],
        "continuous_value_conditional_risk": [],
        "expected_information_gain": [],
    }
    for holdout in ids:
        train = [cid for cid in ids if cid != holdout]
        traces["fixed_prevalence"].append(
            fixed_trace(fixed_order_prevalence(flags, train, assays), holdout, values, flags)
        )
        traces["greedy_fixed_coverage"].append(
            fixed_trace(fixed_order_greedy(flags, train, assays), holdout, values, flags)
        )
        traces["binary_dynamic"].append(
            dynamic_trace(ids, holdout, values, flags, assays, binary=True)
        )
        traces["continuous_value_conditional_risk"].append(
            dynamic_trace(ids, holdout, values, flags, assays, binary=False)
        )
        traces["expected_information_gain"].append(
            dynamic_trace(ids, holdout, values, flags, assays, binary=False, eig=True)
        )
    metrics = {name: summarize(ts) for name, ts in traces.items()}
    metrics["uniform_random_expected"] = random_summary(flags, ids, assays)
    return {
        "candidate_ids": ids,
        "liability_flags": flags,
        "traces": traces,
        "metrics": metrics,
    }


def fr(metric, budget):
    item = metric["budgets"][str(budget)]
    return float(
        item.get("false_reassurance_fraction",
                 item.get("expected_false_reassurance_fraction"))
    )


def positive_costs(run, assays):
    positive = sorted(
        cid for cid, f in run["liability_flags"].items() if any(f.values())
    )
    costs = {}
    for name, traces in run["traces"].items():
        byid = {t["candidate_id"]: float(t["assays_spent"]) for t in traces}
        costs[name] = {cid: byid[cid] for cid in positive}
    n = len(assays)
    costs["uniform_random_expected"] = {
        cid: (n+1.0)/(sum(bool(v) for v in run["liability_flags"][cid].values())+1.0)
        for cid in positive
    }
    return costs


def percentile(values, q):
    ordered = sorted(values)
    pos = (len(ordered)-1)*q
    lo, hi = math.floor(pos), math.ceil(pos)
    if lo == hi:
        return ordered[lo]
    w = pos-lo
    return ordered[lo]*(1-w)+ordered[hi]*w


def grade(run, config):
    metrics = run["metrics"]
    selector = "continuous_value_conditional_risk"
    sm = metrics[selector]
    total = int(sm["candidate_count"])
    pos = int(sm["liability_positive_count"])
    neg = int(sm["liability_negative_count"])
    m = config["missingness"]
    ready = (
        total >= int(m["minimum_primary_candidate_count"])
        and pos >= int(m["minimum_liability_positive_count"])
        and neg >= int(m["minimum_liability_negative_count"])
    )
    baselines = [
        "fixed_prevalence", "greedy_fixed_coverage", "uniform_random_expected",
        "binary_dynamic", "expected_information_gain",
    ]
    budget = int(config["primary_evaluation"]["safety_budget"])
    champion = sorted(
        baselines,
        key=lambda name: (
            float(metrics[name]["mean_assays_to_first_liability_positive_only"]),
            fr(metrics[name], budget),
            name,
        ),
    )[0]
    selector_mean = float(sm["mean_assays_to_first_liability_positive_only"])
    means = {
        n: float(metrics[n]["mean_assays_to_first_liability_positive_only"])
        for n in baselines
    }
    lower_all = all(selector_mean < x for x in means.values())
    costs = positive_costs(run, config["assay_mapping"]["assay_order"])
    ids = sorted(costs[selector])
    diffs = [costs[champion][cid]-costs[selector][cid] for cid in ids]
    bcfg = config["primary_evaluation"]["bootstrap"]
    rng = random.Random(int(bcfg["seed"]))
    boots = []
    for _ in range(int(bcfg["replicates"])):
        sample = [diffs[rng.randrange(len(diffs))] for _ in diffs]
        boots.append(statistics.fmean(sample))
    boot = {
        "sampling_unit_count": len(ids),
        "replicates": int(bcfg["replicates"]),
        "seed": int(bcfg["seed"]),
        "observed_mean_champion_minus_selector": statistics.fmean(diffs),
        "percentile_95_lower": percentile(boots, 0.025),
        "percentile_95_upper": percentile(boots, 0.975),
    }
    sel_fr = fr(sm, budget)
    champ_fr = fr(metrics[champion], budget)
    boot_pass = boot["percentile_95_lower"] > 0.0
    safety = sel_fr <= champ_fr
    if not ready:
        verdict = "INCONCLUSIVE_EXTERNAL_COHORT"
    elif lower_all and boot_pass and safety:
        verdict = "EXTERNAL_ALLOCATION_SIGNAL"
    else:
        verdict = "EXTERNAL_GENERALIZATION_NOT_SUPPORTED"
    return {
        "schema": "openline.trial_selector.external001.grade.v1",
        "experiment_id": config["experiment_id"],
        "primary_candidate_count": total,
        "liability_positive_count": pos,
        "liability_negative_count": neg,
        "cohort_ready": ready,
        "selector": selector,
        "selector_mean_assays_to_first_liability": selector_mean,
        "baseline_mean_assays_to_first_liability": means,
        "selector_strictly_lower_than_every_baseline": lower_all,
        "efficiency_champion_baseline": champion,
        "champion_mean_assays_to_first_liability": means[champion],
        "paired_bootstrap": boot,
        "bootstrap_lower_bound_gt_zero": boot_pass,
        "safety_budget": budget,
        "selector_false_reassurance_fraction": sel_fr,
        "champion_false_reassurance_fraction": champ_fr,
        "safety_nonworse_than_champion": safety,
        "verdict": verdict,
    }


def compare(expected, observed, path="$", mismatches=None):
    if mismatches is None:
        mismatches = []
    if isinstance(expected, (int, float)) and isinstance(observed, (int, float)):
        if not math.isclose(float(expected), float(observed), rel_tol=1e-11, abs_tol=1e-11):
            mismatches.append({"path": path, "expected": expected, "observed": observed})
        return mismatches
    if type(expected) is not type(observed):
        mismatches.append({
            "path": path,
            "expected_type": type(expected).__name__,
            "observed_type": type(observed).__name__,
        })
        return mismatches
    if isinstance(expected, dict):
        if set(expected) != set(observed):
            mismatches.append({
                "path": path,
                "expected_keys": sorted(expected),
                "observed_keys": sorted(observed),
            })
            return mismatches
        for key in sorted(expected):
            compare(expected[key], observed[key], f"{path}.{key}", mismatches)
    elif isinstance(expected, list):
        if len(expected) != len(observed):
            mismatches.append({
                "path": path,
                "expected_len": len(expected),
                "observed_len": len(observed),
            })
            return mismatches
        for i, (a, b) in enumerate(zip(expected, observed)):
            compare(a, b, f"{path}[{i}]", mismatches)
    elif expected != observed:
        mismatches.append({"path": path, "expected": expected, "observed": observed})
    return mismatches


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", required=True, type=Path)
    p.add_argument("--result-dir", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--config", type=Path, default=HERE/"CONFIG.json")
    p.add_argument(
        "--policy", type=Path,
        default=REPO/"benchmarks/candidate_promotion/gdpa1_002/promotion-policy.json",
    )
    p.add_argument(
        "--jain-cohort", type=Path,
        default=REPO/"benchmarks/candidate_promotion/results/jain_canonical_01/JAIN_2017_CANONICAL_COHORT.json",
    )
    args = p.parse_args()

    config = load(args.config)
    policy = load(args.policy)
    cohort = load(args.jain_cohort)
    candidates, expected_receipt = read_primary(args.csv, config, policy, cohort)
    assays = list(config["assay_mapping"]["assay_order"])
    _, pre_flags = build_values_flags(candidates, policy, assays)
    positive = sum(int(any(row.values())) for row in pre_flags.values())
    counts = {
        "candidate_count": len(candidates),
        "liability_positive_count": positive,
        "liability_negative_count": len(candidates) - positive,
    }
    rule = config["missingness"]
    ready = (
        counts["candidate_count"] >= int(rule["minimum_primary_candidate_count"])
        and counts["liability_positive_count"] >= int(rule["minimum_liability_positive_count"])
        and counts["liability_negative_count"] >= int(rule["minimum_liability_negative_count"])
    )

    if ready:
        run = rebuild(candidates, policy, config)
        expected_grade = grade(run, config)
        expected_candidate_ids = run["candidate_ids"]
        expected_metrics = run["metrics"]
        expected_traces = run["traces"]
    else:
        expected_candidate_ids = sorted(row["candidate_id"] for row in candidates)
        expected_metrics = {}
        expected_traces = {}
        expected_grade = {
            "schema": "openline.trial_selector.external001.grade.v1",
            "experiment_id": config["experiment_id"],
            "primary_candidate_count": counts["candidate_count"],
            "liability_positive_count": counts["liability_positive_count"],
            "liability_negative_count": counts["liability_negative_count"],
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

    observed_receipt = load(args.result_dir/"source-receipt.json")
    observed_result = load(args.result_dir/"external-result.json")
    observed_verdict = load(args.result_dir/"verdict.json")

    mismatches = []
    compare(expected_receipt, observed_receipt, "$.source_receipt", mismatches)
    compare(expected_candidate_ids, observed_result["candidate_ids"], "$.candidate_ids", mismatches)
    compare(expected_metrics, observed_result["metrics"], "$.metrics", mismatches)
    compare(expected_traces, observed_result["traces"], "$.traces", mismatches)
    compare(expected_grade, observed_result["grade"], "$.grade", mismatches)
    if observed_verdict.get("verdict") != expected_grade["verdict"]:
        mismatches.append({
            "path": "$.verdict.verdict",
            "expected": expected_grade["verdict"],
            "observed": observed_verdict.get("verdict"),
        })

    output = {
        "schema": "openline.trial_selector.external001.independent_verification.v1",
        "experiment_id": config["experiment_id"],
        "verified": not mismatches,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches[:100],
        "source_sha256": expected_receipt["source_sha256"],
        "external_result_file_sha256": sha256_file(args.result_dir/"external-result.json"),
        "verdict_file_sha256": sha256_file(args.result_dir/"verdict.json"),
        "verdict": observed_verdict.get("verdict"),
        "policy_authority": "NONE",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["verified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
