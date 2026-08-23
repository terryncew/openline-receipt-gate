from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from jain_design import load_json, sha256_json, validate_design_lock


def main() -> int:
    lock = load_json(HERE / "JAIN_2017_DESIGN_LOCK.json")
    thresholds = load_json(HERE / "JAIN_2017_THRESHOLDS.json")
    prereg = load_json(HERE / "PREREGISTRATION.json")
    errors = validate_design_lock(lock, thresholds)
    if prereg.get("primary_budget") != lock.get("primary_budget"):
        errors.append("prereg_primary_budget_mismatch")
    if prereg.get("selection_budgets") != lock.get("selection_budgets"):
        errors.append("prereg_selection_budgets_mismatch")
    result = {
        "schema": "openline.cpg001.jain_design_verification.v0.1",
        "valid": not errors,
        "errors": sorted(set(errors)),
        "design_lock_sha256": sha256_json(lock),
        "thresholds_sha256": sha256_json(thresholds),
        "preregistration_sha256": sha256_json(prereg),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
