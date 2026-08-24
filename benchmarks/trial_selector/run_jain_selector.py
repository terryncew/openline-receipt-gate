from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from benchmarks.candidate_promotion.jain_xlsx import normalize_sd03_assays
from benchmarks.trial_selector.jain_selector import load_thresholds, run_leave_one_out, sha256_file


def canonical_json_sha256(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sd03", required=True, type=Path)
    parser.add_argument("--thresholds", default=REPO / "benchmarks/candidate_promotion/JAIN_2017_THRESHOLDS.json", type=Path)
    parser.add_argument("--column-rules", default=REPO / "benchmarks/candidate_promotion/JAIN_2017_SD03_COLUMN_RULES.json", type=Path)
    parser.add_argument("--freeze", default=HERE / "JAIN_SELECTOR_FREEZE.json", type=Path)
    parser.add_argument("--output", default=HERE / "results/jain_discovery_001/JAIN_SELECTOR_DISCOVERY_RESULT.json", type=Path)
    args = parser.parse_args()

    freeze = json.loads(args.freeze.read_text(encoding="utf-8"))
    expected = freeze["source_binding"]
    actual_sd03_hash = sha256_file(args.sd03)
    if actual_sd03_hash != expected["sd03_sha256"]:
        raise SystemExit(f"sd03_hash_mismatch:{actual_sd03_hash}")
    threshold_obj = json.loads(args.thresholds.read_text(encoding="utf-8"))
    threshold_canonical_hash = canonical_json_sha256(threshold_obj)
    if threshold_canonical_hash != expected["thresholds_canonical_sha256"]:
        raise SystemExit(f"threshold_canonical_hash_mismatch:{threshold_canonical_hash}")
    if sha256_file(args.thresholds) != expected["thresholds_file_sha256"]:
        raise SystemExit("threshold_file_hash_mismatch")

    rules = json.loads(args.column_rules.read_text(encoding="utf-8"))
    normalized = normalize_sd03_assays(args.sd03, rules)
    if normalized["candidate_count"] != expected["canonical_candidate_count"]:
        raise SystemExit(f"candidate_count_mismatch:{normalized['candidate_count']}")

    candidate_ids = sorted(item["candidate_id"] for item in normalized["candidates"])
    candidate_hash = canonical_json_sha256(candidate_ids)
    if candidate_hash != expected["canonical_candidate_ids_sha256"]:
        raise SystemExit(f"candidate_id_hash_mismatch:{candidate_hash}")

    thresholds = load_thresholds(args.thresholds)
    run = run_leave_one_out(normalized["candidates"], thresholds)
    result = {
        "schema": "openline.trial_selector.jain_discovery_result.v1",
        "experiment_id": freeze["experiment_id"],
        "status": "EXPLORATORY_DISCOVERY_ONLY",
        "created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": {
            "sd03_sha256": actual_sd03_hash,
            "thresholds_canonical_sha256": threshold_canonical_hash,
            "thresholds_file_sha256": sha256_file(args.thresholds),
            "candidate_ids_sha256": candidate_hash,
            "candidate_count": len(candidate_ids),
        },
        "freeze_sha256": sha256_file(args.freeze),
        "metrics": run["metrics"],
        "traces": run["traces"],
        "claim_boundary": "Retrospective Jain discovery result only. No external generalization, clinical prediction, or dollar-cost claim.",
    }
    result["metrics_sha256"] = canonical_json_sha256(result["metrics"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["metrics"], indent=2, sort_keys=True))
    print(f"wrote:{args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
