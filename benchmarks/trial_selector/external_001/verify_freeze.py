from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    freeze = json.loads((HERE / "FREEZE.json").read_text(encoding="utf-8"))
    config = json.loads((HERE / "CONFIG.json").read_text(encoding="utf-8"))
    errors = []

    if freeze.get("status") != "EXTERNAL_CONFIRMATION_READY_UNRUN":
        errors.append("freeze_status_changed")
    if freeze.get("full_external_selector_score_seen_at_freeze") is not False:
        errors.append("pre_score_boundary_changed")
    if config.get("status") != "EXTERNAL_CONFIRMATION_READY_UNRUN":
        errors.append("config_status_changed")
    if config.get("policy_authority") != "NONE":
        errors.append("policy_authority_changed")

    for rel, expected in sorted(freeze.get("frozen_file_sha256", {}).items()):
        path = REPO / rel
        if not path.is_file():
            errors.append(f"missing_frozen_file:{rel}")
            continue
        observed = sha(path)
        if observed != expected:
            errors.append(f"frozen_file_hash_mismatch:{rel}:{observed}!={expected}")

    refs = freeze["referenced_frozen_inputs"]

    selector_path = REPO / config["discovery_parent"]["frozen_selector_path"]
    if selector_path.is_file():
        observed = sha(selector_path)
        if observed != refs["jain_selector_sha256"]:
            errors.append(f"jain_selector_hash_mismatch:{observed}")

    source_contract = REPO / config["external_source"]["source_contract_path"]
    if source_contract.is_file():
        observed = sha(source_contract)
        if observed != refs["cpg002_source_contract_sha256"]:
            errors.append(f"source_contract_hash_mismatch:{observed}")

    policy = REPO / config["external_policy"]["policy_path"]
    if policy.is_file():
        observed = sha(policy)
        if observed != refs["cpg002_policy_sha256"]:
            errors.append(f"policy_hash_mismatch:{observed}")

    cohort_path = REPO / config["discovery_parent"]["jain_cohort_path"]
    if cohort_path.is_file():
        cohort = json.loads(cohort_path.read_text(encoding="utf-8"))
        ids = sorted(str(v).strip().casefold() for v in cohort["candidate_ids"])
        observed = canonical(ids)
        if observed != refs["jain_candidate_ids_sha256"]:
            errors.append(f"jain_candidate_ids_hash_mismatch:{observed}")

    payload = {
        "schema": "openline.trial_selector.external001.freeze_verification.v1",
        "experiment_id": freeze["experiment_id"],
        "valid": not errors,
        "errors": errors,
        "status": freeze["status"],
        "policy_authority": "NONE",
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
