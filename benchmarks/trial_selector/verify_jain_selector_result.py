from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from benchmarks.candidate_promotion.jain_xlsx import normalize_sd03_assays
from benchmarks.trial_selector.jain_selector import (
    ASSAY_ORDER,
    build_liability_matrix,
    load_thresholds,
    run_leave_one_out,
    sha256_file,
)


def canonical_json_sha256(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def assert_close(left: float, right: float, label: str, tol: float = 1e-12) -> None:
    if not math.isclose(float(left), float(right), rel_tol=tol, abs_tol=tol):
        raise SystemExit(f"metric_mismatch:{label}:{left}:{right}")


def compare_metrics(expected: dict, actual: dict, prefix: str = "") -> None:
    if set(expected) != set(actual):
        raise SystemExit(f"metric_keys_mismatch:{prefix}")
    for key in expected:
        path = f"{prefix}.{key}" if prefix else key
        a, b = expected[key], actual[key]
        if isinstance(a, dict):
            compare_metrics(a, b, path)
        elif isinstance(a, (int, float)) and not isinstance(a, bool):
            assert_close(a, b, path)
        elif a != b:
            raise SystemExit(f"metric_value_mismatch:{path}:{a!r}:{b!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sd03", required=True, type=Path)
    parser.add_argument("--result", default=HERE / "results/jain_discovery_001/JAIN_SELECTOR_DISCOVERY_RESULT.json", type=Path)
    parser.add_argument("--freeze", default=HERE / "JAIN_SELECTOR_FREEZE.json", type=Path)
    parser.add_argument("--thresholds", default=REPO / "benchmarks/candidate_promotion/JAIN_2017_THRESHOLDS.json", type=Path)
    parser.add_argument("--column-rules", default=REPO / "benchmarks/candidate_promotion/JAIN_2017_SD03_COLUMN_RULES.json", type=Path)
    args = parser.parse_args()

    freeze = json.loads(args.freeze.read_text(encoding="utf-8"))
    result = json.loads(args.result.read_text(encoding="utf-8"))
    if sha256_file(args.freeze) != result["freeze_sha256"]:
        raise SystemExit("freeze_hash_mismatch")
    if sha256_file(args.sd03) != freeze["source_binding"]["sd03_sha256"]:
        raise SystemExit("source_hash_mismatch")
    threshold_obj = json.loads(args.thresholds.read_text(encoding="utf-8"))
    if canonical_json_sha256(threshold_obj) != freeze["source_binding"]["thresholds_canonical_sha256"]:
        raise SystemExit("threshold_canonical_hash_mismatch")
    if sha256_file(args.thresholds) != freeze["source_binding"]["thresholds_file_sha256"]:
        raise SystemExit("threshold_file_hash_mismatch")

    rules = json.loads(args.column_rules.read_text(encoding="utf-8"))
    normalized = normalize_sd03_assays(args.sd03, rules)
    thresholds = load_thresholds(args.thresholds)
    values, flags = build_liability_matrix(normalized["candidates"], thresholds)

    # Verify every recorded trace directly against source values and threshold flags.
    for selector_name, traces in result["traces"].items():
        seen_candidates: set[str] = set()
        for trace in traces:
            cid = trace["candidate_id"]
            if cid in seen_candidates or cid not in values:
                raise SystemExit(f"bad_trace_candidate:{selector_name}:{cid}")
            seen_candidates.add(cid)
            seen_assays: set[str] = set()
            for index, step in enumerate(trace["steps"], 1):
                assay = step["assay"]
                if assay not in ASSAY_ORDER or assay in seen_assays:
                    raise SystemExit(f"bad_trace_assay:{selector_name}:{cid}:{assay}")
                seen_assays.add(assay)
                if int(step["step"]) != index:
                    raise SystemExit(f"bad_trace_step:{selector_name}:{cid}")
                assert_close(step["observed_value"], values[cid][assay], f"trace_value.{selector_name}.{cid}.{assay}")
                if bool(step["liability"]) != bool(flags[cid][assay]):
                    raise SystemExit(f"trace_liability_mismatch:{selector_name}:{cid}:{assay}")
                if index < len(trace["steps"]) and bool(step["liability"]):
                    raise SystemExit(f"trace_continues_after_liability:{selector_name}:{cid}")
            if int(trace["assays_spent"]) != len(trace["steps"]):
                raise SystemExit(f"trace_cost_mismatch:{selector_name}:{cid}")
            if bool(trace["has_any_liability"]) != any(flags[cid].values()):
                raise SystemExit(f"trace_any_liability_mismatch:{selector_name}:{cid}")

    # Independently rerun the frozen selectors and compare both metrics and chosen assay paths.
    rerun = run_leave_one_out(normalized["candidates"], thresholds)
    compare_metrics(result["metrics"], rerun["metrics"])
    for selector_name, traces in result["traces"].items():
        actual = rerun["traces"][selector_name]
        if [t["candidate_id"] for t in traces] != [t["candidate_id"] for t in actual]:
            raise SystemExit(f"trace_order_mismatch:{selector_name}")
        for expected_trace, actual_trace in zip(traces, actual):
            if [s["assay"] for s in expected_trace["steps"]] != [s["assay"] for s in actual_trace["steps"]]:
                raise SystemExit(f"selector_path_mismatch:{selector_name}:{expected_trace['candidate_id']}")

    if canonical_json_sha256(result["metrics"]) != result["metrics_sha256"]:
        raise SystemExit("metrics_hash_mismatch")
    print("JAIN_SELECTOR_RESULT_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
