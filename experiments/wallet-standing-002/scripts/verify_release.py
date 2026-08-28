#!/usr/bin/env python3
"""Independently verify the WALLET-STANDING-002 frozen release."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
MANIFEST = ROOT / "RELEASE_MANIFEST.json"
EXPECTED_VERDICT = "QUORUM_ROOT_SUCCESSION_ENFORCED_WITH_DECLARED_RECOVERY_LAG"
EXPECTED_ARMS = [
    "01_genesis_root_legitimate_action",
    "02_compromised_root_before_recovery_acceptance",
    "03_old_root_self_declares_successor",
    "04_one_of_three_guardians",
    "05_duplicate_guardian_approval",
    "06_valid_two_of_three_root_succession",
    "07_compromised_descendant_after_acceptance",
    "08_legitimate_old_descendant_after_acceptance",
    "09_old_history_remains_authentic_noncurrent",
    "10_successor_root_action",
    "11_unrelated_principal_control",
    "12_tamper_replay_and_rollback",
    "13_recovery_threshold_compromise",
]
EXPECTED_METRICS = {
    "arm_count": 13,
    "passed_arm_count": 13,
    "recovery_lag_seconds": 300,
    "pre_acceptance_compromised_root_execution_count": 1,
    "post_acceptance_old_root_execution_count": 0,
    "below_threshold_acceptance_count": 0,
    "successor_execution_count": 1,
    "unrelated_principal_collateral_loss_count": 0,
    "historically_authentic_noncurrent_count": 1,
    "declared_threshold_compromise_acceptance_count": 1,
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, errors: list[str], label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{label}:{type(exc).__name__}")
        return {}


def main() -> int:
    errors: list[str] = []
    manifest = _load(MANIFEST, errors, "manifest")
    if not isinstance(manifest, dict):
        manifest = {}
    if manifest.get("base_repo") != "terryncew/openline-receipt-gate":
        errors.append("manifest:base_repo")
    if manifest.get("verdict") != EXPECTED_VERDICT:
        errors.append("manifest:verdict")
    files = manifest.get("files", {})
    if not isinstance(files, dict) or not files:
        errors.append("manifest:files")
        files = {}
    for relative, expected in sorted(files.items()):
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"missing:{relative}")
        elif _sha256(path) != expected:
            errors.append(f"hash:{relative}")

    dependency = _load(ROOT / "DEPENDENCY_PIN.json", errors, "dependency")
    if not isinstance(dependency, dict):
        dependency = {}
    wallet001 = dependency.get("wallet_standing_001", {})
    if not isinstance(wallet001, dict):
        wallet001 = {}
    if wallet001.get("mutation_allowed") is not False:
        errors.append("dependency:mutation_boundary")
    for path_key, hash_key in (
        ("protocol_path", "protocol_sha256"),
        ("frozen_result_path", "frozen_result_sha256"),
        ("release_manifest_path", "release_manifest_sha256"),
    ):
        relative = wallet001.get(path_key)
        expected = wallet001.get(hash_key)
        if not isinstance(relative, str) or not isinstance(expected, str):
            errors.append(f"dependency:{path_key}")
            continue
        path = REPO_ROOT / relative
        if not path.is_file():
            errors.append(f"dependency_missing:{relative}")
        elif _sha256(path) != expected:
            errors.append(f"dependency_hash:{relative}")

    prereg = _load(ROOT / "preregistration.json", errors, "prereg")
    result = _load(ROOT / "frozen_result.json", errors, "result")
    freeze = _load(ROOT / "FREEZE.json", errors, "freeze")
    if not isinstance(prereg, dict):
        prereg = {}
    if not isinstance(result, dict):
        result = {}
    if not isinstance(freeze, dict):
        freeze = {}
    if prereg.get("verdict_if_successful") != EXPECTED_VERDICT:
        errors.append("prereg:verdict")
    if prereg.get("authority_split", {}).get("wallet_policy_authority") != "NONE":
        errors.append("prereg:wallet_authority")
    if result.get("verdict") != EXPECTED_VERDICT or result.get("passed") is not True:
        errors.append("result:verdict")
    if result.get("wallet_policy_authority") != "NONE":
        errors.append("result:wallet_authority")
    if result.get("succession_authority") != "PRECOMMITTED_GUARDIAN_QUORUM":
        errors.append("result:succession_authority")
    if result.get("decision_authority") != "RECEIVER_GATE":
        errors.append("result:decision_authority")

    rows = result.get("rows", [])
    if not isinstance(rows, list):
        rows = []
        errors.append("result:rows")
    if [row.get("arm_id") for row in rows] != EXPECTED_ARMS:
        errors.append("result:arm_order")
    if not rows or not all(row.get("passed") is True for row in rows):
        errors.append("result:arm_failure")
    if result.get("metrics") != EXPECTED_METRICS:
        errors.append("result:metrics")
    if len(rows) == 13:
        pre_acceptance = rows[1]
        threshold_compromise = rows[12]
        if pre_acceptance.get("declared_exposure") is not True:
            errors.append("result:recovery_lag_hidden")
        if pre_acceptance.get("observed", {}).get("decision") != "PASS":
            errors.append("result:recovery_lag_rewritten")
        if threshold_compromise.get("declared_exposure") is not True:
            errors.append("result:threshold_floor_hidden")
        if threshold_compromise.get("observed", {}).get("decision") != "ACCEPT_SUCCESSION":
            errors.append("result:threshold_floor_rewritten")
        if rows[8].get("observed", {}).get("execution_authority") != "NONE":
            errors.append("result:history_execution_authority")

    boundaries = " ".join(result.get("explicit_boundaries", []))
    for required in (
        "until the receiver accepts",
        "threshold compromise",
        "virgin Gate",
        "including legitimate old mandates",
        "policy authority NONE",
    ):
        if required not in boundaries:
            errors.append(f"result:boundary:{required.replace(' ', '_')}")

    if freeze.get("verdict") != EXPECTED_VERDICT:
        errors.append("freeze:verdict")
    if freeze.get("wallet_policy_authority") != "NONE":
        errors.append("freeze:wallet_authority")
    frozen_files = freeze.get("files", {})
    if not isinstance(frozen_files, dict) or not frozen_files:
        errors.append("freeze:files")
    else:
        for relative, expected in sorted(frozen_files.items()):
            path = ROOT / relative
            if not path.is_file():
                errors.append(f"freeze_missing:{relative}")
            elif _sha256(path) != expected:
                errors.append(f"freeze_hash:{relative}")

    if errors:
        print("WALLET002_RELEASE_FAIL " + " ".join(errors))
        return 1
    print("WALLET002_RELEASE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
