#!/usr/bin/env python3
"""Independent stdlib verifier for the pinned x402 consequence comparison."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_COMMIT = "167a828e8319aa7b403f4f4312489e9cffadff10"
EXPECTED_SOURCE = Path("python/x402/mcp/server_async.py")
EXPECTED_SOURCE_SHA256 = (
    "49354704d6a59e2d075fa21e258693632b26074097784edef76d3f9b8b4fd36c"
)
EXPECTED_ARTIFACTS = {
    "benchmarks/x402_upstream_consequence/results/effects/native-failed-settlement.log": b"native tool effect before failed settlement\n",
    "benchmarks/x402_upstream_consequence/results/effects/native-success.log": b"native tool effect before successful settlement\n",
    "benchmarks/x402_upstream_consequence/results/effects/airlock-success.log": b"airlock release after confirmed settlement\n",
}
EXPECTED_ABSENT = (
    "benchmarks/x402_upstream_consequence/results/effects/airlock-failed-settlement.log"
)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def call_lines(source: bytes) -> tuple[int, int]:
    tree = ast.parse(source.decode("utf-8"))
    handlers: list[int] = []
    settlements: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "handler":
            handlers.append(node.lineno)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "settle_payment"
        ):
            settlements.append(node.lineno)
    if not handlers or not settlements:
        raise ValueError("required_calls_not_found")
    return min(handlers), min(settlements)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-root", required=True, type=Path)
    parser.add_argument(
        "--report",
        type=Path,
        default=(
            ROOT
            / "benchmarks"
            / "x402_upstream_consequence"
            / "results"
            / "comparison.json"
        ),
    )
    args = parser.parse_args()
    errors: list[str] = []
    upstream_root = args.upstream_root.resolve()
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=upstream_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 or completed.stdout.strip() != EXPECTED_COMMIT:
        errors.append("upstream_commit_mismatch")

    source = (upstream_root / EXPECTED_SOURCE).read_bytes()
    source_sha = digest(source)
    if source_sha != EXPECTED_SOURCE_SHA256:
        errors.append("upstream_source_sha256_mismatch")
    try:
        handler_line, settlement_line = call_lines(source)
    except (SyntaxError, UnicodeDecodeError, ValueError):
        handler_line, settlement_line = 0, 0
        errors.append("upstream_execution_calls_not_found")
    if not (handler_line and handler_line < settlement_line):
        errors.append("handler_does_not_precede_settlement")

    try:
        report: dict[str, Any] = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        report = {}
        errors.append("comparison_report_invalid")
    upstream = report.get("upstream", {})
    if upstream.get("commit") != EXPECTED_COMMIT:
        errors.append("report_commit_mismatch")
    if upstream.get("source_sha256") != EXPECTED_SOURCE_SHA256:
        errors.append("report_source_sha256_mismatch")
    if upstream.get("handler_call_line") != handler_line:
        errors.append("report_handler_line_mismatch")
    if upstream.get("settlement_call_line") != settlement_line:
        errors.append("report_settlement_line_mismatch")

    observations = report.get("observations", {})
    native_failure = observations.get("native_settlement_failure", {})
    native_success = observations.get("native_success_control", {})
    airlock_failure = observations.get("airlock_settlement_failure", {})
    airlock_success = observations.get("airlock_success_control", {})
    expected_values = {
        "native_failure_returned_error": native_failure.get("returned_error") is True,
        "native_failure_effect_once": native_failure.get("durable_tool_effect_count") == 1,
        "native_success_returned_success": native_success.get("returned_error") is False,
        "native_success_effect_once": native_success.get("durable_tool_effect_count") == 1,
        "airlock_failure_settlement_once": airlock_failure.get("settlement_calls") == 1,
        "airlock_failure_release_zero": airlock_failure.get("protected_release_calls") == 0,
        "airlock_failure_effect_absent": airlock_failure.get("protected_effect_exists") is False,
        "airlock_success_authorized": airlock_success.get("authorized") is True,
        "airlock_success_confirmed": airlock_success.get("settlement_confirmed") is True,
        "airlock_success_released": airlock_success.get("resource_released") is True,
        "airlock_success_release_once": airlock_success.get("protected_release_calls") == 1,
        "airlock_success_effect_once": airlock_success.get("protected_effect_count") == 1,
    }
    errors.extend(name for name, okay in expected_values.items() if not okay)

    report_artifacts = report.get("artifacts", {})
    for relative, expected_bytes in EXPECTED_ARTIFACTS.items():
        path = ROOT / relative
        try:
            actual = path.read_bytes()
        except OSError:
            errors.append(f"artifact_missing:{relative}")
            continue
        if actual != expected_bytes:
            errors.append(f"artifact_bytes_mismatch:{relative}")
        if report_artifacts.get(relative) != digest(actual):
            errors.append(f"artifact_digest_mismatch:{relative}")
    if (ROOT / EXPECTED_ABSENT).exists():
        errors.append("failed_airlock_effect_exists")
    if report.get("expected_absent_artifact") != EXPECTED_ABSENT:
        errors.append("expected_absent_artifact_mismatch")
    if report.get("passed") is not True:
        errors.append("comparison_not_passed")
    if set(report.get("checks", {}).values()) != {True}:
        errors.append("comparison_checks_not_all_true")

    result = {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "upstream_commit": EXPECTED_COMMIT,
        "upstream_source_sha256": source_sha,
        "handler_call_line": handler_line,
        "settlement_call_line": settlement_line,
        "native_failed_settlement_effect_count": native_failure.get(
            "durable_tool_effect_count"
        ),
        "airlock_failed_settlement_release_count": airlock_failure.get(
            "protected_release_calls"
        ),
        "airlock_success_release_count": airlock_success.get(
            "protected_release_calls"
        ),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

