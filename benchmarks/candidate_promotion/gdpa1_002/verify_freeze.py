from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def main() -> int:
    freeze = json.loads((HERE / "FREEZE.json").read_text(encoding="utf-8"))
    errors = []
    if freeze.get("status") != "EXTERNAL_REPLICATION_READY_UNRUN":
        errors.append("status_changed")
    if freeze.get("parent_experiment", {}).get("canonical_result") != "NO_COMPENSATION_SIGNAL":
        errors.append("parent_negative_result_erased")
    if freeze.get("policy_or_threshold_mutation_after_freeze") != "FORBIDDEN":
        errors.append("mutation_boundary_changed")
    for rel, expected in sorted(freeze.get("frozen_file_sha256", {}).items()):
        path = ROOT / rel
        observed = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "MISSING"
        if observed != expected:
            errors.append(f"{rel}:{observed}!={expected}")
    payload = {
        "schema": "openline.cpg002.freeze_verification.v0.1",
        "experiment_id": "CPG-002",
        "valid": not errors,
        "errors": errors,
        "status": freeze.get("status"),
        "policy_authority": "NONE",
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
