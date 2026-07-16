#!/usr/bin/env python3
"""Run the release gate and seal its reproducible evidence."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
VERSION = "0.4.0"
PIPELOCK_INTEGRATION_TESTS = 9
ASSAY_INTEGRATION_TESTS = 5
ASSAY_VERSION = "3.32.0"
ASSAY_RELEASE_COMMIT = "04d3db10adbe191aa731d52a6c2b77dad8bc0ca7"
ASSAY_ARCHIVE_SHA256 = "243f5e3935530cb1405dbb54fa57acc944de2800d28537d08dfc305b2a117775"
PIPELOCK_VERIFY_COMMIT = "329f1c76fdfa5fc5b165a3794f7c62906a076c03"
PIPELOCK_REQUIREMENT = (
    "pipelock-verify @ "
    "git+https://github.com/luckyPipewrench/pipelock-verify-python.git@"
    f"{PIPELOCK_VERIFY_COMMIT}"
)


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def execute(
    name: str,
    command: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    expected: tuple[int, ...] = (0,),
) -> tuple[dict[str, Any], bool]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    record = {
        "name": name,
        "command": command,
        "expected_returncodes": list(expected),
        "returncode": completed.returncode,
        "passed": completed.returncode in expected,
        "stdout": completed.stdout[-16000:],
        "stderr": completed.stderr[-16000:],
    }
    return record, bool(record["passed"])


def pipelock_runtime() -> dict[str, Any]:
    try:
        module = importlib.import_module("pipelock_verify")
    except ImportError:
        return {
            "available": False,
            "version": None,
            "supported": False,
            "install_command": "pip install -r requirements-pipelock.txt",
            "source_commit": PIPELOCK_VERIFY_COMMIT,
        }
    version = str(getattr(module, "__version__", "unknown"))
    return {
        "available": True,
        "version": version,
        "supported": version.startswith("0.2."),
        "install_command": "pip install -r requirements-pipelock.txt",
        "source_commit": PIPELOCK_VERIFY_COMMIT,
    }


def assay_runtime() -> dict[str, Any]:
    from olp_gate.adapters_assay import find_assay_binary

    binary = find_assay_binary()
    if binary is None:
        return {
            "available": False,
            "version": None,
            "supported": False,
            "binary": None,
            "release_commit": ASSAY_RELEASE_COMMIT,
            "release_archive_sha256": ASSAY_ARCHIVE_SHA256,
            "install_instructions": "benchmarks/assay/PROTOCOL.md",
        }
    completed = subprocess.run(
        [str(binary), "--version"],
        check=False,
        capture_output=True,
        text=True,
    )
    version = completed.stdout.strip()
    return {
        "available": True,
        "version": version or None,
        "supported": completed.returncode == 0 and version == f"assay {ASSAY_VERSION}",
        "binary": str(binary),
        "release_commit": ASSAY_RELEASE_COMMIT,
        "release_archive_sha256": ASSAY_ARCHIVE_SHA256,
        "install_instructions": "benchmarks/assay/PROTOCOL.md",
    }


def unittest_counts(record: dict[str, Any]) -> dict[str, int | None]:
    output = f"{record.get('stdout', '')}\n{record.get('stderr', '')}"
    discovered_match = re.search(r"Ran (\d+) tests?", output)
    skipped_match = re.search(r"skipped=(\d+)", output)
    discovered = int(discovered_match.group(1)) if discovered_match else None
    skipped = int(skipped_match.group(1)) if skipped_match else 0
    return {
        "discovered": discovered,
        "executed": discovered - skipped if discovered is not None else None,
        "skipped": skipped,
    }


def releasable_files() -> list[Path]:
    excluded_parts = {".git", "__pycache__", ".pytest_cache", "build", "dist"}
    excluded_names = {"MANIFEST.json", "session_ledger.json", "session_ledger.json.lock"}
    ephemeral_outputs = {
        "results/demo_all_summary.json",
        "results/proof_to_policy_demo/decision_receipts.jsonl",
    }
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if path.is_symlink() or not path.is_file() or any(part in excluded_parts or part.endswith(".egg-info") for part in relative.parts):
            continue
        if relative.parts and relative.parts[0] == "receipts":
            continue
        if relative.as_posix() in ephemeral_outputs:
            continue
        if path.name in excluded_names or path.suffix in {".pyc", ".key", ".pem", ".zip", ".lock"}:
            continue
        files.append(relative)
    return sorted(files, key=lambda value: value.as_posix())


def write_manifest(
    *,
    checks_passed: bool,
    proof_summary: dict[str, Any],
    pipelock_summary: dict[str, Any],
    assay_summary: dict[str, Any],
    optional_integrations: dict[str, Any],
) -> None:
    entries = []
    for relative in releasable_files():
        data = (ROOT / relative).read_bytes()
        entries.append({
            "path": relative.as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        })
    manifest = {
        "schema": "openline.release_manifest.v0.2",
        "repo": "openline-receipt-gate",
        "version": VERSION,
        "created_at": iso_now(),
        "release_status": "ready" if checks_passed else "failed",
        "claim": "Signed source receipts can drive externally configured, independently verifiable policy decisions within declared inputs and trust assumptions.",
        "proof_to_policy_demo": {
            "passed": proof_summary.get("passed", False),
            "decision_receipt_count": proof_summary.get("decision_receipt_count", 0),
            "observed": proof_summary.get("observed", {}),
        },
        "pipelock_head_to_head": {
            "passed": pipelock_summary.get("passed", False),
            "strong_hypothesis_falsified": pipelock_summary.get(
                "strong_hypothesis_falsified"
            ),
            "aggregate": pipelock_summary.get("aggregate", {}),
        },
        "assay_head_to_head": {
            "passed": assay_summary.get("passed", False),
            "strong_signing_uniqueness_hypothesis_falsified": assay_summary.get(
                "strong_signing_uniqueness_hypothesis_falsified"
            ),
            "aggregate": assay_summary.get("aggregate", {}),
        },
        "optional_integrations": optional_integrations,
        "files": entries,
    }
    (ROOT / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    proof_output = ROOT / "results" / "proof_to_policy_demo"
    shutil.rmtree(proof_output, ignore_errors=True)
    steps: list[dict[str, Any]] = []
    passed: list[bool] = []
    pipelock_info = pipelock_runtime()
    assay_info = assay_runtime()
    requirement_value = (ROOT / "requirements-pipelock.txt").read_text(
        encoding="utf-8"
    ).strip()
    requirement_okay = requirement_value == PIPELOCK_REQUIREMENT
    steps.append(
        {
            "name": "pipelock_dependency_pin",
            "passed": requirement_okay,
            "expected_commit": PIPELOCK_VERIFY_COMMIT,
            "requirement": requirement_value,
        }
    )
    passed.append(requirement_okay)
    try:
        benchmark_report = json.loads(
            (ROOT / "benchmarks" / "pipelock" / "RUN_REPORT.json").read_text(
                encoding="utf-8"
            )
        )
        pipelock_summary = benchmark_report["pipelock_head_to_head"]
        benchmark_gate_key = str(
            pipelock_summary["decision_receipts"]["trusted_gate_public_key"]
        )
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        benchmark_report = {}
        pipelock_summary = {}
        benchmark_gate_key = ""
    try:
        assay_benchmark_report = json.loads(
            (ROOT / "benchmarks" / "assay" / "RUN_REPORT.json").read_text(
                encoding="utf-8"
            )
        )
        assay_summary = assay_benchmark_report["assay_head_to_head"]
        assay_gate_key = str(
            assay_summary["decision_receipts"]["trusted_gate_public_key"]
        )
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        assay_benchmark_report = {}
        assay_summary = {}
        assay_gate_key = ""

    unit_command = [
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "-s",
        "tests",
        "-v",
    ]
    unit_record, unit_okay = execute("unittest", unit_command)
    unit_counts = unittest_counts(unit_record)
    expected_main_skips = (
        (0 if pipelock_info["supported"] else PIPELOCK_INTEGRATION_TESTS)
        + (0 if assay_info["supported"] else ASSAY_INTEGRATION_TESTS)
    )
    unit_record["counts"] = unit_counts
    unit_record["optional_pipelock"] = pipelock_info
    unit_record["optional_assay"] = assay_info
    unit_okay = (
        unit_okay
        and unit_counts["discovered"] is not None
        and unit_counts["skipped"] == expected_main_skips
    )
    unit_record["passed"] = unit_okay
    steps.append(unit_record)
    passed.append(unit_okay)

    absent_environment = os.environ.copy()
    absent_environment["OLP_TEST_DISABLE_PIPELOCK"] = "1"
    absent_environment["OLP_TEST_DISABLE_ASSAY"] = "1"
    absent_record, absent_okay = execute(
        "unittest_without_optional_integrations",
        unit_command,
        env=absent_environment,
    )
    absent_counts = unittest_counts(absent_record)
    absent_record["counts"] = absent_counts
    absent_okay = (
        absent_okay
        and absent_counts["discovered"] is not None
        and absent_counts["skipped"]
        == PIPELOCK_INTEGRATION_TESTS + ASSAY_INTEGRATION_TESTS
    )
    absent_record["passed"] = absent_okay
    steps.append(absent_record)
    passed.append(absent_okay)

    for name, command in (
        ("legacy_demo", [sys.executable, "examples/demo_all.py"]),
        ("proof_to_policy_demo", [sys.executable, "-m", "olp_gate.cli", "demo-proof-to-policy", "--output", str(proof_output)]),
    ):
        record, okay = execute(name, command)
        steps.append(record)
        passed.append(okay)

    try:
        initial_summary = json.loads((proof_output / "demo_summary.json").read_text(encoding="utf-8"))
        fixture_gate_key = str(initial_summary["gate_public_key"])
    except (OSError, json.JSONDecodeError, KeyError):
        fixture_gate_key = ""
    for name, command in (
        (
            "python_decision_verifier",
            [sys.executable, "-m", "olp_gate.cli", "verify-decision", str(proof_output / "decision_receipts.jsonl"), "--gate-key", fixture_gate_key],
        ),
        (
            "node_decision_verifier",
            ["node", "verify-decision-node.mjs", str(proof_output / "decision_receipts.jsonl"), "--gate-key", fixture_gate_key],
        ),
        ("compileall", [sys.executable, "-m", "compileall", "-q", "olp_gate"]),
        (
            "frozen_pipelock_benchmark_verifier",
            [sys.executable, "scripts/verify_pipelock_benchmark.py"],
        ),
        (
            "pipelock_decisions_node_verifier",
            [
                "node",
                "verify-decision-node.mjs",
                "benchmarks/pipelock/results/decision_receipts.jsonl",
                "--gate-key",
                benchmark_gate_key,
            ],
        ),
        (
            "frozen_assay_benchmark_verifier",
            [sys.executable, "scripts/verify_assay_benchmark.py"],
        ),
        (
            "assay_decisions_node_verifier",
            [
                "node",
                "verify-decision-node.mjs",
                "benchmarks/assay/results/decision_receipts.jsonl",
                "--gate-key",
                assay_gate_key,
            ],
        ),
    ):
        record, okay = execute(name, command)
        steps.append(record)
        passed.append(okay)

    assay_live_benchmark_executed = False
    assay_live_benchmark_passed = False
    with tempfile.TemporaryDirectory(prefix="openline-release-") as temporary:
        temp = Path(temporary)
        assay_archive_value = os.environ.get("OLP_ASSAY_ARCHIVE")
        if assay_info["supported"] and assay_archive_value:
            assay_live_benchmark_executed = True
            assay_reproduction = temp / "assay-reproduction"
            record, okay = execute(
                "live_assay_benchmark_reproduction",
                [
                    sys.executable,
                    "benchmarks/assay/run_head_to_head.py",
                    "--assay-bin",
                    str(assay_info["binary"]),
                    "--assay-archive",
                    assay_archive_value,
                    "--output",
                    str(assay_reproduction / "RUN_REPORT.json"),
                    "--report",
                    str(assay_reproduction / "REPORT.md"),
                    "--results-dir",
                    str(assay_reproduction / "results"),
                ],
            )
            assay_live_benchmark_passed = okay
            steps.append(record)
            passed.append(okay)
        tampered = temp / "tampered.jsonl"
        source_log = proof_output / "decision_receipts.jsonl"
        if source_log.exists():
            original = source_log.read_text(encoding="utf-8")
            modified = original.replace('"decision":"COMMIT"', '"decision":"DENY"', 1)
            if modified == original:
                passed.append(False)
                steps.append({"name": "tamper_fixture", "passed": False, "error": "COMMIT receipt not found"})
            else:
                tampered.write_text(modified, encoding="utf-8")
                for name, command, expected in (
                    ("python_rejects_tamper", [sys.executable, "-m", "olp_gate.cli", "verify-decision", str(tampered), "--gate-key", fixture_gate_key], (2,)),
                    ("node_rejects_tamper", ["node", "verify-decision-node.mjs", str(tampered), "--gate-key", fixture_gate_key], (1,)),
                ):
                    record, okay = execute(name, command, expected=expected)
                    steps.append(record)
                    passed.append(okay)

        wheelhouse = temp / "wheelhouse"
        wheelhouse.mkdir()
        install_environment = os.environ.copy()
        install_environment["PIP_CACHE_DIR"] = str(temp / "pip-cache")
        record, okay = execute(
            "build_release_wheel",
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                ".",
                "--wheel-dir",
                str(wheelhouse),
                "--no-deps",
                "--no-build-isolation",
            ],
            env=install_environment,
        )
        steps.append(record)
        passed.append(okay)
        if okay:
            wheels = sorted(wheelhouse.glob("openline_receipt_gate-0.4.0-*.whl"))
            if len(wheels) != 1:
                okay = False
                steps.append(
                    {
                        "name": "release_wheel_selection",
                        "passed": False,
                        "error": f"expected one release wheel, found {len(wheels)}",
                    }
                )
                passed.append(False)
        if okay:
            site = temp / "site"
            record, okay = execute(
                "clean_wheel_install",
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    str(wheels[0]),
                    "--target",
                    str(site),
                    "--no-deps",
                    "--no-index",
                ],
                env=install_environment,
            )
            steps.append(record)
            passed.append(okay)
        if okay:
            outside = temp / "outside"
            outside.mkdir()
            installed_output = outside / "installed_demo"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(site)
            record, okay = execute(
                "installed_cli_from_unrelated_cwd",
                [sys.executable, "-m", "olp_gate.cli", "demo-proof-to-policy", "--output", str(installed_output)],
                cwd=outside,
                env=environment,
            )
            steps.append(record)
            passed.append(okay)
            if okay:
                installed_summary = json.loads((installed_output / "demo_summary.json").read_text(encoding="utf-8"))
                record, okay = execute(
                    "installed_output_node_verification",
                    [
                        "node",
                        str(ROOT / "verify-decision-node.mjs"),
                        str(installed_output / "decision_receipts.jsonl"),
                        "--gate-key",
                        str(installed_summary["gate_public_key"]),
                    ],
                    cwd=outside,
                )
                steps.append(record)
                passed.append(okay)

    try:
        proof_summary = json.loads((proof_output / "demo_summary.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        proof_summary = {}
    passed.append(proof_summary.get("passed") is True)
    passed.append(proof_summary.get("decision_receipt_count") == 5)
    passed.append(benchmark_report.get("passed") is True)
    passed.append(
        pipelock_summary.get("flagship_finding", {}).get(
            "strong_hypothesis_falsified"
        )
        is True
    )
    passed.append(assay_benchmark_report.get("passed") is True)
    passed.append(
        assay_summary.get("capability_control", {}).get(
            "strong_signing_uniqueness_hypothesis_falsified"
        )
        is True
    )
    release_passed = all(passed)
    live_pipelock_tests_passed = bool(
        pipelock_info["supported"]
        and unit_okay
        and unit_counts["skipped"] == 0
    )
    live_assay_tests_passed = bool(
        assay_info["supported"]
        and unit_okay
        and unit_counts["skipped"]
        == (0 if pipelock_info["supported"] else PIPELOCK_INTEGRATION_TESTS)
    )
    optional_integrations = {
        "pipelock": {
            **pipelock_info,
            "live_adapter_tests_executed": pipelock_info["supported"],
            "live_adapter_tests_passed": live_pipelock_tests_passed,
            "dependency_absent_suite_passed": absent_okay,
            "integration_test_count": PIPELOCK_INTEGRATION_TESTS,
        },
        "assay": {
            **assay_info,
            "live_adapter_tests_executed": assay_info["supported"],
            "live_adapter_tests_passed": live_assay_tests_passed,
            "live_benchmark_executed": assay_live_benchmark_executed,
            "live_benchmark_passed": assay_live_benchmark_passed,
            "dependency_absent_suite_passed": absent_okay,
            "integration_test_count": ASSAY_INTEGRATION_TESTS,
        }
    }
    report = {
        "schema": "openline.release_run_report.v0.2",
        "repo": "openline-receipt-gate",
        "version": VERSION,
        "created_at": iso_now(),
        "passed": release_passed,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "node": subprocess.run(["node", "--version"], check=False, capture_output=True, text=True).stdout.strip(),
        },
        "checks": steps,
        "test_count": unit_counts["discovered"],
        "test_executed": unit_counts["executed"],
        "test_skipped": unit_counts["skipped"],
        "test_matrix": {
            "current_environment": unit_counts,
            "without_optional_integrations": absent_counts,
        },
        "optional_integrations": optional_integrations,
        "published_interop_fixture": {
            "project": "Agent Receipts",
            "version": "0.5.0",
            "source_commit": "df6833a39743e17127d5ad4b10cdc8f6734d8e03",
            "signature_and_hash_match": release_passed,
        },
        "published_pipelock_interop_fixture": {
            "project": "Pipelock ActionReceipt",
            "version": "1",
            "pipelock_source_commit": "371893f0084ed693c1f69adf6da81c269e84aeff",
            "pipelock_verify_source_commit": "329f1c76fdfa5fc5b165a3794f7c62906a076c03",
            "sealed_benchmark_artifacts_verified": release_passed,
            "live_adapter_tests_executed": pipelock_info["supported"],
            "live_adapter_tests_passed": live_pipelock_tests_passed,
        },
        "published_assay_interop_fixture": {
            "project": "Assay Evidence Contract / Trust Basis",
            "version": ASSAY_VERSION,
            "assay_source_commit": ASSAY_RELEASE_COMMIT,
            "assay_release_archive_sha256": ASSAY_ARCHIVE_SHA256,
            "sealed_benchmark_artifacts_verified": release_passed,
            "live_adapter_tests_executed": assay_info["supported"],
            "live_adapter_tests_passed": live_assay_tests_passed,
            "live_benchmark_executed": assay_live_benchmark_executed,
            "live_benchmark_passed": assay_live_benchmark_passed,
        },
        "proof_to_policy_demo": proof_summary,
        "pipelock_head_to_head": pipelock_summary,
        "assay_head_to_head": assay_summary,
        "claim_boundary": "A passing synthetic release gate does not prove production safety, issuer honesty, complete capture, witness independence, or rollback execution. Frozen benchmark artifact verification is distinct from an optional live benchmark rerun. Assay can sign caller-supplied DSSE predicates; OLP's observed addition is its standardized receiver-policy decision contract, not unique signing.",
    }
    (ROOT / "RUN_REPORT.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_manifest(
        checks_passed=release_passed,
        proof_summary=proof_summary,
        pipelock_summary={
            "passed": benchmark_report.get("passed", False),
            "strong_hypothesis_falsified": pipelock_summary.get(
                "flagship_finding", {}
            ).get("strong_hypothesis_falsified"),
            "aggregate": pipelock_summary.get("aggregate", {}),
        },
        assay_summary={
            "passed": assay_benchmark_report.get("passed", False),
            "strong_signing_uniqueness_hypothesis_falsified": assay_summary.get(
                "capability_control", {}
            ).get("strong_signing_uniqueness_hypothesis_falsified"),
            "aggregate": assay_summary.get("aggregate", {}),
        },
        optional_integrations=optional_integrations,
    )

    manifest_check = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_manifest.py"), str(ROOT)],
        check=False,
        capture_output=True,
        text=True,
    )
    print(json.dumps({
        "passed": release_passed and manifest_check.returncode == 0,
        "release_checks": len(steps),
        "proof_to_policy_cases": proof_summary.get("decision_receipt_count", 0),
        "manifest": json.loads(manifest_check.stdout) if manifest_check.stdout else {"valid": False},
    }, indent=2, sort_keys=True))
    return 0 if release_passed and manifest_check.returncode == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
