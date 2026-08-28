#!/usr/bin/env python3
"""Independently verify the WALLET-STANDING-003 frozen release."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
MANIFEST = ROOT / "RELEASE_MANIFEST.json"
EXPECTED_VERDICT = (
    "RECEIVED_FREEZE_AND_FORK_QUARANTINE_ENFORCED_"
    "WITH_DECLARED_INFORMATION_LAG"
)
EXPECTED_BASE = "bf3cb5fd9345f481aa0ae30d2990c74af986e485"
EXPECTED_ARMS = [
    "01_fresh_single_guardian_freeze",
    "02_received_freeze_blocks_old_root",
    "03_unreceived_freeze_information_lag",
    "04_fresh_cross_delivery_blocks",
    "05_stale_freeze_is_not_backdated",
    "06_freeze_replay_cannot_extend",
    "07_malicious_guardian_bounded_dos",
    "08_exact_expiry_restores_current_root",
    "09_old_root_cannot_fake_guardian",
    "10_quorum_succession_clears_freeze",
    "11_successor_executes_after_quorum",
    "12_virgin_gate_requires_checkpoint",
    "13_fresh_quorum_checkpoint_admits_known_root",
    "14_checkpoint_tamper_stale_and_threshold",
    "15_partitioned_quorum_fork_quarantine",
]
EXPECTED_METRICS = {
    "arm_count": 15,
    "passed_arm_count": 15,
    "freeze_received_old_root_execution_count": 0,
    "freeze_unreceived_old_root_execution_count": 1,
    "stale_freeze_old_root_execution_count": 1,
    "freeze_replay_extension_seconds": 0,
    "malicious_guardian_dos_seconds": 600,
    "post_expiry_legitimate_execution_count": 1,
    "post_quorum_successor_execution_count": 2,
    "virgin_without_checkpoint_execution_count": 0,
    "virgin_with_checkpoint_execution_count": 1,
    "partitioned_conflicting_branch_execution_count": 2,
    "post_fork_detection_execution_count": 0,
    "automatic_convergence_count": 0,
    "fork_quarantine_count": 2,
}
EXPECTED_AUTHORITY = {
    "wallet_policy_authority": "NONE",
    "freeze_authority": "ONE_PRECOMMITTED_GUARDIAN_REDUCE_ONLY",
    "succession_authority": "PRECOMMITTED_GUARDIAN_QUORUM",
    "decision_authority": "RECEIVER_GATE",
}
EXPECTED_FILES = {
    "CLAIM_BOUNDARY.md",
    "DEPENDENCY_PIN.json",
    "FREEZE.json",
    "README.md",
    "frozen_result.json",
    "preregistration.json",
    "scripts/run_frozen.py",
    "scripts/verify_release.py",
    "tests/test_wallet003.py",
    "wallet003/__init__.py",
    "wallet003/distribution.py",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, errors: list[str], label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{label}:{type(exc).__name__}")
        return {}


def _verify_dependency_group(
    dependency: dict,
    group_name: str,
    pairs: tuple[tuple[str, str], ...],
    errors: list[str],
) -> None:
    group = dependency.get(group_name, {})
    if not isinstance(group, dict):
        errors.append(f"dependency:{group_name}")
        return
    if group.get("mutation_allowed") is not False:
        errors.append(f"dependency:{group_name}:mutation_boundary")
    for path_key, hash_key in pairs:
        relative = group.get(path_key)
        expected = group.get(hash_key)
        if not isinstance(relative, str) or not isinstance(expected, str):
            errors.append(f"dependency:{group_name}:{path_key}")
            continue
        path = REPO_ROOT / relative
        if not path.is_file():
            errors.append(f"dependency_missing:{relative}")
        elif _sha256(path) != expected:
            errors.append(f"dependency_hash:{relative}")


def main() -> int:
    errors: list[str] = []
    manifest = _load(MANIFEST, errors, "manifest")
    if not isinstance(manifest, dict):
        manifest = {}
    if manifest.get("base_repo") != "terryncew/openline-receipt-gate":
        errors.append("manifest:base_repo")
    if manifest.get("base_commit") != EXPECTED_BASE:
        errors.append("manifest:base_commit")
    if manifest.get("verdict") != EXPECTED_VERDICT:
        errors.append("manifest:verdict")
    for key, expected in EXPECTED_AUTHORITY.items():
        if manifest.get(key) != expected:
            errors.append(f"manifest:{key}")
    files = manifest.get("files", {})
    if not isinstance(files, dict):
        errors.append("manifest:files")
        files = {}
    if set(files) != EXPECTED_FILES:
        errors.append("manifest:file_set")
    for relative, expected in sorted(files.items()):
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"missing:{relative}")
        elif _sha256(path) != expected:
            errors.append(f"hash:{relative}")

    dependency = _load(ROOT / "DEPENDENCY_PIN.json", errors, "dependency")
    if not isinstance(dependency, dict):
        dependency = {}
    if dependency.get("base_commit") != EXPECTED_BASE:
        errors.append("dependency:base_commit")
    _verify_dependency_group(
        dependency,
        "wallet_standing_001",
        (
            ("protocol_path", "protocol_sha256"),
            ("frozen_result_path", "frozen_result_sha256"),
            ("release_manifest_path", "release_manifest_sha256"),
        ),
        errors,
    )
    _verify_dependency_group(
        dependency,
        "wallet_standing_002",
        (
            ("recovery_path", "recovery_sha256"),
            ("frozen_result_path", "frozen_result_sha256"),
            ("release_manifest_path", "release_manifest_sha256"),
        ),
        errors,
    )

    prereg = _load(ROOT / "preregistration.json", errors, "prereg")
    result = _load(ROOT / "frozen_result.json", errors, "result")
    freeze = _load(ROOT / "FREEZE.json", errors, "freeze")
    if not isinstance(prereg, dict):
        prereg = {}
    if not isinstance(result, dict):
        result = {}
    if not isinstance(freeze, dict):
        freeze = {}

    prereg_arms = prereg.get("primary_arms", [])
    if not isinstance(prereg_arms, list):
        prereg_arms = []
    if [arm.get("arm_id") for arm in prereg_arms] != EXPECTED_ARMS:
        errors.append("prereg:arm_order")
    if prereg.get("success_criteria") != {
        key: value for key, value in EXPECTED_METRICS.items() if key not in {"arm_count", "passed_arm_count"}
    } | {"all_arms_match": True}:
        errors.append("prereg:success_criteria")
    if prereg.get("verdict_if_successful") != EXPECTED_VERDICT:
        errors.append("prereg:verdict")
    if prereg.get("authority_split", {}).get("wallet_policy_authority") != "NONE":
        errors.append("prereg:wallet_authority")

    if result.get("verdict") != EXPECTED_VERDICT or result.get("passed") is not True:
        errors.append("result:verdict")
    for key, expected in EXPECTED_AUTHORITY.items():
        if result.get(key) != expected:
            errors.append(f"result:{key}")
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

    if len(rows) == 15:
        by_id = {row.get("arm_id"): row for row in rows}
        for arm_id in (
            "03_unreceived_freeze_information_lag",
            "05_stale_freeze_is_not_backdated",
            "07_malicious_guardian_bounded_dos",
            "08_exact_expiry_restores_current_root",
            "15_partitioned_quorum_fork_quarantine",
        ):
            if by_id[arm_id].get("declared_exposure") is not True:
                errors.append(f"result:exposure_hidden:{arm_id}")
        if by_id["03_unreceived_freeze_information_lag"].get("observed", {}).get("decision") != "PASS":
            errors.append("result:unreceived_freeze_rewritten")
        stale = by_id["05_stale_freeze_is_not_backdated"].get("observed", {})
        if stale.get("execution", {}).get("decision") != "PASS":
            errors.append("result:stale_freeze_rewritten")
        if by_id["08_exact_expiry_restores_current_root"].get("observed", {}).get("decision") != "PASS":
            errors.append("result:expiry_rewritten")
        fork = by_id["15_partitioned_quorum_fork_quarantine"].get("observed", {})
        if fork.get("partition_x", {}).get("decision") != "PASS" or fork.get("partition_y", {}).get("decision") != "PASS":
            errors.append("result:partition_exposure_rewritten")
        if fork.get("post_detection_x", {}).get("decision") != "BLOCK" or fork.get("post_detection_y", {}).get("decision") != "BLOCK":
            errors.append("result:fork_quarantine")
        if fork.get("automatic_resolution") != "NONE":
            errors.append("result:invented_convergence")

    boundaries = " ".join(result.get("explicit_boundaries", []))
    for required in (
        "not a real network",
        "cannot enforce a freeze it has not received",
        "600 seconds",
        "risk resumes at exact expiry",
        "checkpoint confirms an already-known view",
        "may each execute during a partition",
        "requires external resolution",
        "policy authority NONE",
    ):
        if required not in boundaries:
            errors.append(f"result:boundary:{required.replace(' ', '_')}")

    if freeze.get("base_commit") != EXPECTED_BASE:
        errors.append("freeze:base_commit")
    if freeze.get("verdict") != EXPECTED_VERDICT:
        errors.append("freeze:verdict")
    for key, expected in EXPECTED_AUTHORITY.items():
        if freeze.get(key) != expected:
            errors.append(f"freeze:{key}")
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
    declared = freeze.get("declared_exposures", {})
    for key in (
        "unreceived_freeze",
        "first_seen_stale_freeze",
        "malicious_single_guardian",
        "freeze_expiry_without_quorum",
        "partitioned_valid_fork",
        "threshold_guardian_compromise",
    ):
        if not isinstance(declared, dict) or key not in declared:
            errors.append(f"freeze:declared_exposure:{key}")

    if errors:
        print("WALLET003_RELEASE_FAIL " + " ".join(errors))
        return 1
    print("WALLET003_RELEASE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
