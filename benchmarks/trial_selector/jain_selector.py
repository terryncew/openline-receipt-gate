from __future__ import annotations

import hashlib
import json
import math
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

try:
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
except ImportError as exc:  # pragma: no cover - explicit benchmark dependency
    raise RuntimeError(
        "Jain trial selector requires scikit-learn==1.8.0 for frozen reproduction"
    ) from exc

warnings.filterwarnings(
    "ignore",
    message="'penalty' was deprecated in version 1.8",
    category=FutureWarning,
    module="sklearn.linear_model._logistic",
)

ASSAY_ORDER = (
    "AC_SINS",
    "AS",
    "BVP",
    "CIC",
    "CSI_BLI",
    "ELISA",
    "HIC",
    "PSR",
    "SGAC_SINS",
    "SMAC",
)


class SelectorError(ValueError):
    pass


@dataclass(frozen=True)
class Threshold:
    operator: str
    value: float


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_thresholds(path: str | Path) -> dict[str, Threshold]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    out: dict[str, Threshold] = {}
    for items in raw["groups"].values():
        for item in items:
            out[item["assay_type"]] = Threshold(item["operator"], float(item["threshold"]))
    if tuple(sorted(out)) != ASSAY_ORDER:
        raise SelectorError("threshold_assay_set_mismatch")
    return out


def is_liability(value: float, threshold: Threshold) -> bool:
    if threshold.operator == "<=":
        return float(value) > threshold.value
    if threshold.operator == ">=":
        return float(value) < threshold.value
    raise SelectorError(f"unsupported_threshold_operator:{threshold.operator}")


def build_liability_matrix(
    candidates: Sequence[Mapping[str, Any]], thresholds: Mapping[str, Threshold]
) -> tuple[dict[str, dict[str, float]], dict[str, dict[str, bool]]]:
    values: dict[str, dict[str, float]] = {}
    flags: dict[str, dict[str, bool]] = {}
    for candidate in candidates:
        cid = str(candidate["candidate_id"])
        assays = candidate["assays"]
        if cid in values:
            raise SelectorError(f"duplicate_candidate:{cid}")
        values[cid] = {}
        flags[cid] = {}
        for assay in ASSAY_ORDER:
            value = assays.get(assay)
            if value is None or not math.isfinite(float(value)):
                raise SelectorError(f"missing_assay:{cid}:{assay}")
            values[cid][assay] = float(value)
            flags[cid][assay] = is_liability(float(value), thresholds[assay])
    return values, flags


def _training_ids(candidate_ids: Sequence[str], holdout: str) -> list[str]:
    return [cid for cid in candidate_ids if cid != holdout]


def _prevalence(flags: Mapping[str, Mapping[str, bool]], train_ids: Sequence[str], assay: str) -> float:
    return sum(bool(flags[cid][assay]) for cid in train_ids) / len(train_ids)


def fixed_prevalence_order(
    flags: Mapping[str, Mapping[str, bool]], train_ids: Sequence[str]
) -> list[str]:
    return sorted(ASSAY_ORDER, key=lambda a: (-_prevalence(flags, train_ids, a), a))


def greedy_coverage_order(
    flags: Mapping[str, Mapping[str, bool]], train_ids: Sequence[str]
) -> list[str]:
    remaining = set(ASSAY_ORDER)
    covered: set[str] = set()
    order: list[str] = []
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


def _predict_remaining_risks(
    *,
    train_ids: Sequence[str],
    holdout: str,
    observed: Sequence[str],
    remaining: Sequence[str],
    values: Mapping[str, Mapping[str, float]],
    flags: Mapping[str, Mapping[str, bool]],
    binary_features: bool,
) -> dict[str, float]:
    if not observed:
        return {assay: _prevalence(flags, train_ids, assay) for assay in remaining}

    if binary_features:
        x_train = np.asarray(
            [[float(flags[cid][feature]) for feature in observed] for cid in train_ids],
            dtype=float,
        )
        x_holdout = np.asarray(
            [[float(flags[holdout][feature]) for feature in observed]], dtype=float
        )
    else:
        x_train = np.asarray(
            [[float(values[cid][feature]) for feature in observed] for cid in train_ids],
            dtype=float,
        )
        x_holdout = np.asarray(
            [[float(values[holdout][feature]) for feature in observed]], dtype=float
        )

    risks: dict[str, float] = {}
    for assay in remaining:
        y = np.asarray([int(flags[cid][assay]) for cid in train_ids], dtype=int)
        if len(set(int(v) for v in y.tolist())) < 2:
            risks[assay] = float(y[0])
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
        risks[assay] = float(model.predict_proba(x_holdout)[0, 1])
    return risks


def dynamic_trace(
    *,
    candidate_ids: Sequence[str],
    holdout: str,
    values: Mapping[str, Mapping[str, float]],
    flags: Mapping[str, Mapping[str, bool]],
    binary_features: bool,
) -> dict[str, Any]:
    train_ids = _training_ids(candidate_ids, holdout)
    observed: list[str] = []
    remaining = list(ASSAY_ORDER)
    steps: list[dict[str, Any]] = []
    while remaining:
        risks = _predict_remaining_risks(
            train_ids=train_ids,
            holdout=holdout,
            observed=observed,
            remaining=remaining,
            values=values,
            flags=flags,
            binary_features=binary_features,
        )
        assay = sorted(remaining, key=lambda a: (-risks[a], a))[0]
        step = {
            "step": len(steps) + 1,
            "assay": assay,
            "predicted_liability_probability": risks[assay],
            "observed_value": values[holdout][assay],
            "liability": bool(flags[holdout][assay]),
        }
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


def fixed_trace(order: Sequence[str], holdout: str, values: Mapping[str, Mapping[str, float]], flags: Mapping[str, Mapping[str, bool]]) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    for assay in order:
        steps.append(
            {
                "step": len(steps) + 1,
                "assay": assay,
                "observed_value": values[holdout][assay],
                "liability": bool(flags[holdout][assay]),
            }
        )
        if flags[holdout][assay]:
            break
    return {
        "candidate_id": holdout,
        "has_any_liability": any(flags[holdout].values()),
        "assays_spent": len(steps),
        "steps": steps,
    }


def summarize_deterministic_traces(traces: Sequence[Mapping[str, Any]], budgets: Sequence[int] = (1, 2, 3, 4, 5)) -> dict[str, Any]:
    positive = [trace for trace in traces if trace["has_any_liability"]]
    out: dict[str, Any] = {
        "candidate_count": len(traces),
        "liability_positive_count": len(positive),
        "liability_negative_count": len(traces) - len(positive),
        "mean_assays_to_first_liability_positive_only": sum(float(t["assays_spent"]) for t in positive) / len(positive),
        "budgets": {},
    }
    for budget in budgets:
        detected = sum(int(t["has_any_liability"] and int(t["assays_spent"]) <= budget) for t in traces)
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


def random_expected_summary(flags: Mapping[str, Mapping[str, bool]], candidate_ids: Sequence[str], budgets: Sequence[int] = (1, 2, 3, 4, 5)) -> dict[str, Any]:
    n = len(ASSAY_ORDER)
    positive = [cid for cid in candidate_ids if any(flags[cid].values())]
    expected_costs = []
    for cid in positive:
        k = sum(bool(flags[cid][a]) for a in ASSAY_ORDER)
        expected_costs.append((n + 1) / (k + 1))
    out: dict[str, Any] = {
        "candidate_count": len(candidate_ids),
        "liability_positive_count": len(positive),
        "liability_negative_count": len(candidate_ids) - len(positive),
        "mean_assays_to_first_liability_positive_only": sum(expected_costs) / len(expected_costs),
        "budgets": {},
        "method": "analytic uniform random permutation expectation",
    }
    negatives = len(candidate_ids) - len(positive)
    denom_all_orders = math.comb(n, 0)  # marker for exact combinatorial method
    _ = denom_all_orders
    for budget in budgets:
        expected_positive_survivors = 0.0
        for cid in positive:
            k = sum(bool(flags[cid][a]) for a in ASSAY_ORDER)
            if budget > n - k:
                survive = 0.0
            else:
                survive = math.comb(n - k, budget) / math.comb(n, budget)
            expected_positive_survivors += survive
        expected_detected = len(positive) - expected_positive_survivors
        expected_survivors = negatives + expected_positive_survivors
        out["budgets"][str(budget)] = {
            "expected_positive_detected_count": expected_detected,
            "expected_positive_detected_fraction": expected_detected / len(positive),
            "expected_survivor_count": expected_survivors,
            "expected_hidden_liability_count": expected_positive_survivors,
            "expected_false_reassurance_fraction": expected_positive_survivors / expected_survivors,
        }
    return out


def run_leave_one_out(candidates: Sequence[Mapping[str, Any]], thresholds: Mapping[str, Threshold]) -> dict[str, Any]:
    values, flags = build_liability_matrix(candidates, thresholds)
    candidate_ids = sorted(values)
    traces: dict[str, list[dict[str, Any]]] = {
        "fixed_prevalence": [],
        "greedy_fixed_coverage": [],
        "binary_dynamic": [],
        "continuous_value_conditional_risk": [],
    }
    for holdout in candidate_ids:
        train_ids = _training_ids(candidate_ids, holdout)
        traces["fixed_prevalence"].append(
            fixed_trace(fixed_prevalence_order(flags, train_ids), holdout, values, flags)
        )
        traces["greedy_fixed_coverage"].append(
            fixed_trace(greedy_coverage_order(flags, train_ids), holdout, values, flags)
        )
        traces["binary_dynamic"].append(
            dynamic_trace(
                candidate_ids=candidate_ids,
                holdout=holdout,
                values=values,
                flags=flags,
                binary_features=True,
            )
        )
        traces["continuous_value_conditional_risk"].append(
            dynamic_trace(
                candidate_ids=candidate_ids,
                holdout=holdout,
                values=values,
                flags=flags,
                binary_features=False,
            )
        )
    metrics = {name: summarize_deterministic_traces(items) for name, items in traces.items()}
    metrics["uniform_random_expected"] = random_expected_summary(flags, candidate_ids)
    return {
        "candidate_ids": candidate_ids,
        "liability_flags": flags,
        "traces": traces,
        "metrics": metrics,
    }
