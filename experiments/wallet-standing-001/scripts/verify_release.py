#!/usr/bin/env python3
"""Independently verify the frozen WALLET-STANDING-001 release surface."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "RELEASE_MANIFEST.json"
EXPECTED_VERDICT = "EPOCH_REVOCATION_ENFORCED_WITH_BOUNDED_OFFLINE_LAG"
EXPECTED_ARMS = [
    "01_high_fresh_active",
    "02_high_fresh_revoked",
    "03_high_stale_active_witness",
    "04_high_missing_witness",
    "05_high_successor_epoch",
    "06_high_independent_root_sibling",
    "07_low_within_ttl_no_witness",
    "08_low_revoked_but_unexpired_offline",
    "09_low_at_expiry_no_witness",
    "10_projection_and_holder_tampering",
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    errors: list[str] = []
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"WALLET001_RELEASE_FAIL manifest:{type(exc).__name__}")
        return 1

    if manifest.get("base_repo") != "terryncew/openline-receipt-gate":
        errors.append("manifest:base_repo")
    if manifest.get("verdict") != EXPECTED_VERDICT:
        errors.append("manifest:verdict")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        errors.append("manifest:files")
        files = {}
    for relative, expected in sorted(files.items()):
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"missing:{relative}")
        elif _sha256(path) != expected:
            errors.append(f"hash:{relative}")

    try:
        prereg = json.loads((ROOT / "preregistration.json").read_text(encoding="utf-8"))
        result = json.loads((ROOT / "frozen_result.json").read_text(encoding="utf-8"))
        freeze = json.loads((ROOT / "FREEZE.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"frozen_json:{type(exc).__name__}")
        prereg, result, freeze = {}, {}, {}

    if prereg.get("verdict_if_successful") != EXPECTED_VERDICT:
        errors.append("prereg:verdict")
    if prereg.get("authority_split", {}).get("wallet_policy_authority") != "NONE":
        errors.append("prereg:wallet_authority")
    if result.get("verdict") != EXPECTED_VERDICT or result.get("passed") is not True:
        errors.append("result:verdict")
    if result.get("policy_authority") != "NONE":
        errors.append("result:wallet_authority")
    if result.get("decision_authority") != "RECEIVER_GATE":
        errors.append("result:gate_authority")

    rows = result.get("rows")
    if not isinstance(rows, list):
        rows = []
        errors.append("result:rows")
    if [row.get("arm_id") for row in rows] != EXPECTED_ARMS:
        errors.append("result:arm_order")
    if not rows or not all(row.get("passed") is True for row in rows):
        errors.append("result:arm_failure")
    metrics = result.get("metrics", {})
    expected_metrics = {
        "arm_count": 10,
        "passed_arm_count": 10,
        "high_risk_stale_execution_count": 0,
        "collateral_loss_count": 0,
        "declared_low_risk_stale_pass_count": 1,
        "offline_exposure_ceiling_seconds": 600,
    }
    if metrics != expected_metrics:
        errors.append("result:metrics")
    if len(rows) >= 9:
        exposure = rows[7]
        if exposure.get("declared_exposure") is not True:
            errors.append("result:exposure_not_declared")
        if exposure.get("observed", {}).get("decision") != "PASS":
            errors.append("result:offline_boundary_hidden")
        if rows[8].get("observed", {}).get("reason_codes") != ["MANDATE_EXPIRED"]:
            errors.append("result:expiry_boundary")
    salt = result.get("salt_invariants", {})
    if salt.get("duplicate_salt_count") != 0 or salt.get("passed") is not True:
        errors.append("result:salt_invariant")
    boundaries = " ".join(result.get("explicit_boundaries", []))
    for required in ("Distribution", "Root loss", "never grants itself policy authority"):
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
        print("WALLET001_RELEASE_FAIL " + " ".join(errors))
        return 1
    print("WALLET001_RELEASE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
