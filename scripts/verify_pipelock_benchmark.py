#!/usr/bin/env python3
"""Verify the sealed Pipelock benchmark without rerunning timed checks."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_child(root: Path, relative: str) -> Path | None:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return None
    return resolved


def main() -> int:
    root = (
        Path(sys.argv[1]).resolve()
        if len(sys.argv) > 1
        else Path(__file__).resolve().parents[1]
    )
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    bench = root / "benchmarks" / "pipelock"
    errors: list[str] = []

    try:
        report = load_json(bench / "RUN_REPORT.json")
        cases_spec = load_json(bench / "CASES.json")
        manifest = load_json(bench / "FIXTURE_MANIFEST.json")
        freeze = load_json(bench / "FREEZE.json")
        amendment = load_json(bench / "AMENDMENT-001.json")
        amendment_2 = load_json(bench / "AMENDMENT-002.json")
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "errors": [f"benchmark_unreadable:{exc}"]}, indent=2))
        return 2

    protocol_hash = sha256(bench / "PROTOCOL.md")
    recorded_protocol_hash = (
        (bench / "PROTOCOL.sha256").read_text(encoding="ascii").strip().split()[0]
    )
    if protocol_hash != recorded_protocol_hash:
        errors.append("protocol_hash_mismatch")
    if protocol_hash != amendment_2.get("current_protocol_sha256"):
        errors.append("amendment_2_protocol_hash_mismatch")
    frozen_snapshot_hash = sha256(bench / "PROTOCOL-FROZEN-v0.3.0.md")
    if frozen_snapshot_hash != freeze.get("protocol_sha256"):
        errors.append("embedded_freeze_protocol_hash_mismatch")
    if frozen_snapshot_hash != amendment_2.get("embedded_snapshot_sha256"):
        errors.append("amendment_2_snapshot_hash_mismatch")
    scored_protocol_hash = (
        report.get("pipelock_head_to_head", {})
        .get("protocol", {})
        .get("current_protocol_sha256")
    )
    if scored_protocol_hash != amendment_2.get("prior_scored_protocol_sha256"):
        errors.append("prior_scored_protocol_hash_mismatch")
    for unchanged in (
        "cases_changed",
        "expected_outcomes_changed",
        "fixtures_changed",
        "results_changed",
        "scoring_rule_changed",
        "source_pins_changed",
    ):
        if amendment_2.get(unchanged) is not False:
            errors.append(f"amendment_2_unexpected_change:{unchanged}")
    if amendment_2.get("review", {}).get("third_party_independent_reproduction") is not False:
        errors.append("vendor_review_misclassified")
    if report.get("schema") != "openline.release_run_report.v0.2":
        errors.append("report_schema_invalid")
    if report.get("version") != "0.3.0" or report.get("passed") is not True:
        errors.append("report_not_passing_v030")

    changed_manifest = next(
        (
            item
            for item in amendment.get("changed", [])
            if item.get("path") == "FIXTURE_MANIFEST.json"
        ),
        None,
    )
    if changed_manifest is None or sha256(bench / "FIXTURE_MANIFEST.json") != changed_manifest.get("new_sha256"):
        errors.append("fixture_manifest_amendment_mismatch")
    if sha256(bench / "CASES.json") != amendment.get("cases_sha256_unchanged"):
        errors.append("cases_hash_mismatch")

    fixture_root = bench / "fixtures"
    for entry in manifest.get("files", []):
        relative = entry.get("path")
        if not isinstance(relative, str):
            errors.append("fixture_manifest_entry_invalid")
            continue
        path = safe_child(fixture_root, relative)
        if path is None or not path.is_file():
            errors.append(f"fixture_missing_or_unsafe:{relative}")
        elif sha256(path) != entry.get("sha256"):
            errors.append(f"fixture_hash_mismatch:{relative}")

    block = report.get("pipelock_head_to_head", {})
    aggregate = block.get("aggregate", {})
    expected_counts = {
        "pipelock_native": {"correct": 5, "incorrect": 0, "undecidable": 0},
        "olp": {"correct": 5, "incorrect": 0, "undecidable": 0},
        "pipelock_aarp": {
            "correct": 3,
            "incorrect": 0,
            "undecidable": 0,
            "not_applicable": 2,
        },
    }
    for lane, expected in expected_counts.items():
        if aggregate.get(lane) != expected:
            errors.append(f"aggregate_mismatch:{lane}")
    if aggregate.get("reference_boolean_parity") != 5:
        errors.append("official_reference_parity_incomplete")

    rows = block.get("cases")
    if not isinstance(rows, list) or len(rows) != 5:
        errors.append("benchmark_case_count_invalid")
        rows = []
    rows_by_id = {
        row.get("case_id"): row for row in rows if isinstance(row, dict)
    }
    for case in cases_spec.get("cases", []):
        case_id = case.get("case_id")
        row = rows_by_id.get(case_id)
        if row is None:
            errors.append(f"benchmark_case_missing:{case_id}")
            continue
        native = row.get("pipelock_native", {})
        olp = row.get("olp", {})
        for key, value in case.get("native_expected", {}).items():
            if native.get(key) != value:
                errors.append(f"native_expectation_mismatch:{case_id}:{key}")
        for key, value in case.get("olp_expected", {}).items():
            if olp.get(key) != value:
                errors.append(f"olp_expectation_mismatch:{case_id}:{key}")
        if native.get("benchmark_outcome") != "correct":
            errors.append(f"native_not_correct:{case_id}")
        if olp.get("benchmark_outcome") != "correct":
            errors.append(f"olp_not_correct:{case_id}")
        if row.get("pipelock_reference_python", {}).get("boolean_parity_with_native") is not True:
            errors.append(f"official_reference_disagreement:{case_id}")

    case_two = rows_by_id.get("case-02-allow-missing-evidence", {})
    if "downstream_claim_evidence_sufficient" not in case_two.get("pipelock_aarp", {}).get("claimed_unverified", []):
        errors.append("aarp_did_not_flag_flagship_claim")
    finding = block.get("flagship_finding", {})
    if finding.get("strong_hypothesis_falsified") is not True:
        errors.append("strong_hypothesis_not_marked_falsified")

    block_case = rows_by_id.get("case-04-native-block", {})
    block_olp = block_case.get("olp", {})
    if (
        block_case.get("pipelock_native", {}).get("action_verdict") != "block"
        or block_olp.get("decision") != "DENY"
        or block_olp.get("verdict") != "REJECTED"
        or "source_signal:pipelock_source_verdict_block"
        not in block_olp.get("reason_codes", [])
    ):
        errors.append("native_block_was_not_preserved")

    decision_meta = block.get("decision_receipts", {})
    decision_relative = decision_meta.get("path")
    decision_path = (
        safe_child(root, decision_relative)
        if isinstance(decision_relative, str)
        else None
    )
    public_key = decision_meta.get("trusted_gate_public_key")
    if not isinstance(public_key, str) or re.fullmatch(r"[0-9a-f]{64}", public_key) is None:
        errors.append("benchmark_gate_key_invalid")
    if decision_path is None or not decision_path.is_file():
        errors.append("decision_log_missing_or_unsafe")
    else:
        if sha256(decision_path) != decision_meta.get("sha256"):
            errors.append("decision_log_hash_mismatch")
        try:
            decisions = [
                json.loads(line)
                for line in decision_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except json.JSONDecodeError as exc:
            errors.append(f"decision_log_invalid_json:{exc}")
            decisions = []
        if len(decisions) != decision_meta.get("count") or len(decisions) != 5:
            errors.append("decision_log_count_mismatch")
        if isinstance(public_key, str):
            from olp_gate.gateway import verify_decision_receipt

            for index, decision in enumerate(decisions):
                result = verify_decision_receipt(decision, [public_key])
                if result.get("valid") is not True:
                    errors.append(f"decision_receipt_invalid:{index}")

    result = {
        "valid": not errors,
        "schema": report.get("schema"),
        "freeze_proof": {
            "mode": "embedded_snapshot",
            "original_commit": freeze.get("freeze_commit"),
            "snapshot_sha256": frozen_snapshot_hash,
            "temporal_limit": (
                "The embedded snapshot proves exact frozen bytes inside this "
                "release; it does not independently timestamp the freeze."
            ),
        },
        "version": report.get("version"),
        "case_count": len(rows),
        "strong_hypothesis_falsified": finding.get("strong_hypothesis_falsified"),
        "errors": sorted(set(errors)),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
