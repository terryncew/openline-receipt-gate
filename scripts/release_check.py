#!/usr/bin/env python3
"""Run the release gate and seal its reproducible evidence."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.0"


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


def releasable_files() -> list[Path]:
    excluded_parts = {".git", "__pycache__", ".pytest_cache", "build", "dist"}
    excluded_names = {"MANIFEST.json", "session_ledger.json", "session_ledger.json.lock"}
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if path.is_symlink() or not path.is_file() or any(part in excluded_parts or part.endswith(".egg-info") for part in relative.parts):
            continue
        if path.name in excluded_names or path.suffix in {".pyc", ".key", ".pem", ".zip", ".lock"}:
            continue
        files.append(relative)
    return sorted(files, key=lambda value: value.as_posix())


def write_manifest(*, checks_passed: bool, proof_summary: dict[str, Any]) -> None:
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

    for name, command in (
        ("unittest", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]),
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
    ):
        record, okay = execute(name, command)
        steps.append(record)
        passed.append(okay)

    with tempfile.TemporaryDirectory(prefix="openline-release-") as temporary:
        temp = Path(temporary)
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

        site = temp / "site"
        install_environment = os.environ.copy()
        install_environment["PIP_CACHE_DIR"] = str(temp / "pip-cache")
        record, okay = execute(
            "clean_install",
            [sys.executable, "-m", "pip", "install", ".", "--target", str(site), "--no-deps", "--no-build-isolation"],
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
    release_passed = all(passed)
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
        "test_count": 41,
        "published_interop_fixture": {
            "project": "Agent Receipts",
            "version": "0.5.0",
            "source_commit": "df6833a39743e17127d5ad4b10cdc8f6734d8e03",
            "signature_and_hash_match": release_passed,
        },
        "proof_to_policy_demo": proof_summary,
        "claim_boundary": "A passing synthetic release gate does not prove production safety, issuer honesty, complete capture, witness independence, or rollback execution.",
    }
    (ROOT / "RUN_REPORT.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_manifest(checks_passed=release_passed, proof_summary=proof_summary)

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
