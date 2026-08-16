#!/usr/bin/env python3
"""Run the release gate and seal its reproducible evidence."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
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
VERSION = "0.6.0rc6"
PIPELOCK_INTEGRATION_TESTS = 9
ASSAY_INTEGRATION_TESTS = 5
MODEL_SWAP_INTEGRATION_TESTS = 8
VERIFIED_CONTINUATION_INTEGRATION_TESTS = 2
HALF_LIFE_VERSION = "0.2.0rc5"
HALF_LIFE_COMMIT = "70121b53e86196d69b2c3457174b38ad32667b43"
VENDORED_HALF_LIFE_ROOT = (
    ROOT / "vendor" / "openline-half-life-0.2.0rc5"
)
VENDORED_HALF_LIFE_WHEEL = (
    VENDORED_HALF_LIFE_ROOT
    / "openline_half_life-0.2.0rc5-py3-none-any.whl"
)
VENDORED_HALF_LIFE_SITE = VENDORED_HALF_LIFE_ROOT / "site"
VENDORED_HALF_LIFE_VERIFIER = (
    ROOT / "scripts" / "verify_vendored_half_life.py"
)
ASSAY_VERSION = "3.32.0"
ASSAY_RELEASE_COMMIT = "04d3db10adbe191aa731d52a6c2b77dad8bc0ca7"
ASSAY_ARCHIVE_SHA256 = "243f5e3935530cb1405dbb54fa57acc944de2800d28537d08dfc305b2a117775"
PIPELOCK_VERIFY_COMMIT = "329f1c76fdfa5fc5b165a3794f7c62906a076c03"
PIPELOCK_REQUIREMENT = (
    "pipelock-verify @ "
    "git+https://github.com/luckyPipewrench/pipelock-verify-python.git@"
    f"{PIPELOCK_VERIFY_COMMIT}"
)
MODEL_SWAP_REQUIREMENT = (
    "openline-half-life @ "
    "git+https://github.com/terryncew/openline-half-life.git@"
    f"{HALF_LIFE_COMMIT}"
)
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release-check.yml"
CI_REQUIRED_SNIPPETS = (
    "actions/checkout@v6",
    "actions/setup-python@v6",
    "actions/setup-node@v6",
    HALF_LIFE_COMMIT,
    "167a828e8319aa7b403f4f4312489e9cffadff10",
    "OLP_X402_UPSTREAM_ROOT",
    "OLP_HALF_LIFE_ROOT",
    "OLP_HALF_LIFE_SOURCE_ROOT",
    "Verify vendored Half-Life release fixture",
    "python scripts/verify_vendored_half_life.py",
    'python -m pip install "setuptools==82.0.1" "wheel==0.47.0"',
    "python -m pip install --no-build-isolation .",
    "Verify frozen benchmark source closure",
    "benchmarks/warning_time/results/control/decision_receipts.jsonl",
    "benchmarks/warning_time/results/dropped_counterevidence/decision_receipts.jsonl",
    "benchmarks/warning_time/results/unflagged_contradiction/decision_receipts.jsonl",
    "benchmarks/x402_airlock/FREEZE.json",
    "benchmarks/x402_airlock/results/hostile_report.json",
    "benchmarks/verified_continuation/FREEZE.json",
    "benchmarks/verified_continuation/results/continuation_report.json",
    "Verify frozen Verified Continuation harness",
    "python scripts/verify_verified_continuation.py",
    "python scripts/release_check.py",
    "python scripts/verify_manifest.py",
    "python scripts/verify_warning_time_benchmark.py",
    "python benchmarks/x402_airlock/run_hostile_suite.py",
    "python scripts/verify_x402_airlock.py",
    "benchmarks/x402_upstream_consequence/results/comparison.json",
    "python benchmarks/x402_upstream_consequence/run_comparison.py",
    "python scripts/verify_x402_upstream_consequence.py",
    "benchmarks/role_confusion_consequence/FREEZE.json",
    "benchmarks/role_confusion_consequence/results/hostile_report.json",
    "python benchmarks/role_confusion_consequence/run_suite.py",
    "python scripts/verify_role_confusion_consequence.py",
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


def _vendored_half_life_verification() -> dict[str, Any]:
    command = [sys.executable, str(VENDORED_HALF_LIFE_VERIFIER)]
    source_root = os.environ.get("OLP_HALF_LIFE_SOURCE_ROOT")
    if source_root:
        command.extend(["--external-root", source_root])
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        result = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        result = {
            "valid": False,
            "errors": ["vendored_verifier_output_invalid"],
        }
    result["returncode"] = completed.returncode
    if completed.stderr:
        result["stderr"] = completed.stderr[-4000:]
    result["valid"] = bool(
        completed.returncode == 0 and result.get("valid") is True
    )
    return result


def _activate_vendored_half_life() -> dict[str, Any]:
    verification = _vendored_half_life_verification()
    if verification.get("valid") is not True:
        return verification
    site_value = str(VENDORED_HALF_LIFE_SITE)
    if site_value not in sys.path:
        sys.path.insert(0, site_value)
    current_pythonpath = os.environ.get("PYTHONPATH", "")
    pythonpath_parts = [
        value for value in current_pythonpath.split(os.pathsep) if value
    ]
    if site_value not in pythonpath_parts:
        os.environ["PYTHONPATH"] = os.pathsep.join(
            [site_value, *pythonpath_parts]
        )
    os.environ["OLP_HALF_LIFE_ROOT"] = str(VENDORED_HALF_LIFE_ROOT)
    importlib.invalidate_caches()
    return verification


def model_swap_runtime() -> dict[str, Any]:
    root_value = os.environ.get("OLP_HALF_LIFE_ROOT")
    source_mode = "external_environment"
    bundle_verification: dict[str, Any] | None = None
    if not root_value:
        source_mode = "vendored_offline_fallback"
        bundle_verification = _activate_vendored_half_life()
        if bundle_verification.get("valid") is True:
            root_value = str(VENDORED_HALF_LIFE_ROOT)
    root = Path(root_value).resolve() if root_value else None
    fixture_files = (
        root / "examples" / "demo_output" / "half_life_receipt.json",
        root / "policy" / "succession_policy_public_key.hex",
        root / "policy" / "compaction_policy_public_key.hex",
    ) if root is not None else ()
    try:
        version = importlib.metadata.version("openline-half-life")
    except importlib.metadata.PackageNotFoundError:
        version = None
    available = version is not None and bool(fixture_files) and all(
        path.is_file() for path in fixture_files
    )
    return {
        "available": available,
        "version": version,
        "supported": available and version == HALF_LIFE_VERSION,
        "source_commit": HALF_LIFE_COMMIT,
        "source_mode": source_mode,
        "fixture_root": str(root) if root is not None else None,
        "vendored_bundle_verified": (
            bundle_verification.get("valid")
            if bundle_verification is not None
            else None
        ),
        "vendored_bundle_errors": (
            bundle_verification.get("errors", [])
            if bundle_verification is not None
            else []
        ),
        "install_command": "pip install -r requirements-model-swap.txt",
        "required_for_v0.6_release": True,
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
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if path.is_symlink() or not path.is_file() or any(part in excluded_parts or part.endswith(".egg-info") for part in relative.parts):
            continue
        if relative.parts and relative.parts[0] == "receipts":
            continue
        if path.name in excluded_names or path.suffix in {".pyc", ".key", ".pem", ".zip", ".lock"}:
            continue
        files.append(relative)
    return sorted(files, key=lambda value: value.as_posix())


def write_manifest(
    *,
    checks_passed: bool,
    proof_summary: dict[str, Any],
    model_swap_summary: dict[str, Any],
    verified_commit_summary: dict[str, Any],
    verified_continuation_summary: dict[str, Any],
    branch_authorization_summary: dict[str, Any],
    handoff_summary: dict[str, Any],
    pipelock_summary: dict[str, Any],
    assay_summary: dict[str, Any],
    warning_time_summary: dict[str, Any],
    x402_airlock_summary: dict[str, Any],
    x402_upstream_summary: dict[str, Any],
    role_confusion_summary: dict[str, Any],
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
        "verified_model_swap": {
            "passed": model_swap_summary.get("passed", False),
            "decision": model_swap_summary.get("decision"),
            "capsule_matches_oracle": model_swap_summary.get(
                "capsule_matches_oracle"
            ),
            "archive_matches_oracle": model_swap_summary.get(
                "archive_matches_oracle"
            ),
            "summary_lost_count": model_swap_summary.get("summary_lost_count"),
            "proof_card_sha256": model_swap_summary.get("proof_card_sha256"),
        },
        "verified_commit": {
            "passed": verified_commit_summary.get("passed", False),
            "decision": verified_commit_summary.get("decision"),
            "authorization_hash": verified_commit_summary.get(
                "authorization_hash"
            ),
            "action_hash": verified_commit_summary.get("action_hash"),
            "mutations_blocked_before_execution": verified_commit_summary.get(
                "mutations_blocked_before_execution"
            ),
            "simultaneous_authorized": verified_commit_summary.get(
                "simultaneous_authorized"
            ),
            "simultaneous_blocked": verified_commit_summary.get(
                "simultaneous_blocked"
            ),
            "replay_blocked": verified_commit_summary.get("replay_blocked"),
        },
        "verified_continuation": {
            "harness_valid": verified_continuation_summary.get("valid", False),
            "continuation_disposition": verified_continuation_summary.get(
                "continuation_disposition"
            ),
            "mechanism_rule_passed": verified_continuation_summary.get(
                "mechanism_rule_passed"
            ),
            "report_hash": verified_continuation_summary.get("report_hash"),
            "authorization_passed": branch_authorization_summary.get(
                "passed", False
            ),
            "authorization_report_hash": branch_authorization_summary.get(
                "report_hash"
            ),
            "wrong_branch_blocked": branch_authorization_summary.get(
                "wrong_branch_blocked"
            ),
            "mutated_target_blocked": branch_authorization_summary.get(
                "mutated_target_blocked"
            ),
            "expired_blocked": branch_authorization_summary.get(
                "expired_blocked"
            ),
            "replay_blocked": branch_authorization_summary.get(
                "replay_blocked"
            ),
        },
        "handoff_check": {
            "disposition": handoff_summary.get("disposition"),
            "source": handoff_summary.get("source"),
            "source_history_sha256": handoff_summary.get("source_history_sha256"),
            "capsule_sha256": handoff_summary.get("capsule_sha256"),
            "receipt_sha256": handoff_summary.get("receipt_sha256"),
            "metrics": handoff_summary.get("metrics", {}),
        },
        "pipelock_head_to_head": {
            "passed": pipelock_summary.get("passed", False),
            "strong_hypothesis_falsified": pipelock_summary.get(
                "strong_hypothesis_falsified"
            ),
            "aggregate": pipelock_summary.get("aggregate", {}),
        },
        "warning_time_benchmark": {
            "report_hash": warning_time_summary.get("report_hash"),
            "calibration_profile_payload_hash": warning_time_summary.get("calibration_profile_payload_hash"),
            "calibration_profile_signature_valid": warning_time_summary.get("calibration_profile_signature_valid"),
            "calibration_evidence_hash": warning_time_summary.get("calibration_evidence_hash"),
            "thresholds_hash": warning_time_summary.get("thresholds_hash"),
            "metric_input_boundary": warning_time_summary.get("metric_input_boundary"),
            "label_leak_probe_passed": warning_time_summary.get("label_leak_probe", {}).get("passed"),
            "paired_heldout_seeds": warning_time_summary.get("paired_heldout_seeds"),
            "external_freeze_anchor_valid": warning_time_summary.get("external_freeze_anchor_valid"),
            "external_freeze_anchor": warning_time_summary.get("external_freeze_anchor"),
            "calibration_clean_runs": warning_time_summary.get("heldout", {}).get("calibration_clean_runs"),
            "heldout_clean_runs_evaluated": warning_time_summary.get("aggregate", {}).get("heldout_clean_runs_evaluated"),
            "heldout_clean_run_false_alarms": warning_time_summary.get("aggregate", {}).get("heldout_clean_run_false_alarms"),
            "heldout_corruption_runs": warning_time_summary.get("aggregate", {}).get("heldout_corruption_runs"),
            "missed_corruptions": warning_time_summary.get("aggregate", {}).get("missed_corruptions"),
            "final_decision_counts": warning_time_summary.get("aggregate", {}).get("final_decision_counts", {}),
            "reference_warning_times": {
                case: warning_time_summary.get("reference_cases", {}).get(case, {}).get("warning_time_steps")
                for case in ("dropped_counterevidence", "unflagged_contradiction")
            },
            "interpretation": warning_time_summary.get("interpretation"),
        },
        "x402_transaction_airlock": {
            "valid": x402_airlock_summary.get("valid", False),
            "source": x402_airlock_summary.get("source"),
            "case_count": x402_airlock_summary.get("case_count"),
            "passed_cases": x402_airlock_summary.get("passed_cases"),
            "rules_covered": x402_airlock_summary.get(
                "rules_covered", []
            ),
            "required_falsifier_axes": x402_airlock_summary.get(
                "required_falsifier_axes", {}
            ),
            "settlement_callback_count": x402_airlock_summary.get(
                "settlement_callback_count"
            ),
            "release_callback_count": x402_airlock_summary.get(
                "release_callback_count"
            ),
            "resource_release_confirmed_count": x402_airlock_summary.get(
                "resource_release_confirmed_count"
            ),
        },
        "x402_upstream_consequence": {
            "passed": x402_upstream_summary.get("passed", False),
            "claim": x402_upstream_summary.get("claim"),
            "claim_boundary": x402_upstream_summary.get("claim_boundary"),
            "upstream": x402_upstream_summary.get("upstream", {}),
            "observations": x402_upstream_summary.get("observations", {}),
        },
        "role_confusion_consequence": {
            "passed": role_confusion_summary.get("passed", False),
            "case_count": role_confusion_summary.get("case_count"),
            "cases_passed": role_confusion_summary.get("cases_passed"),
            "authorization_valid_hostile_cases": role_confusion_summary.get(
                "authorization_valid_hostile_cases"
            ),
            "authorization_valid_hostile_effects_blocked": role_confusion_summary.get(
                "authorization_valid_hostile_effects_blocked"
            ),
            "protected_effect_callback_count": role_confusion_summary.get(
                "protected_effect_callback_count"
            ),
            "blocked_rows_invoked_effect": role_confusion_summary.get(
                "blocked_rows_invoked_effect"
            ),
            "matched_legitimate_twin_committed": role_confusion_summary.get(
                "matched_legitimate_twin_committed"
            ),
            "unrelated_untrusted_addition_committed": role_confusion_summary.get(
                "unrelated_untrusted_addition_committed"
            ),
            "injection_text_visible_to_gate": role_confusion_summary.get(
                "injection_text_visible_to_gate"
            ),
            "attack_label_visible_to_gate": role_confusion_summary.get(
                "attack_label_visible_to_gate"
            ),
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
    model_swap_output = ROOT / "results" / "verified_model_swap_demo"
    verified_commit_output = ROOT / "results" / "verified_commit_demo"
    verified_continuation_output = (
        ROOT / "results" / "verified_continuation_fixture"
    )
    branch_authorization_output = (
        ROOT / "results" / "verified_continuation_authorization"
    )
    handoff_output = ROOT / "results" / "handoff_check_demo"
    shutil.rmtree(proof_output, ignore_errors=True)
    shutil.rmtree(model_swap_output, ignore_errors=True)
    shutil.rmtree(verified_commit_output, ignore_errors=True)
    shutil.rmtree(verified_continuation_output, ignore_errors=True)
    shutil.rmtree(branch_authorization_output, ignore_errors=True)
    shutil.rmtree(handoff_output, ignore_errors=True)
    steps: list[dict[str, Any]] = []
    passed: list[bool] = []
    pipelock_info = pipelock_runtime()
    assay_info = assay_runtime()
    vendored_half_life_info = _vendored_half_life_verification()
    model_swap_info = model_swap_runtime()
    steps.append(
        {
            "name": "vendored_half_life_release_bundle",
            "passed": vendored_half_life_info.get("valid") is True,
            **vendored_half_life_info,
        }
    )
    passed.append(vendored_half_life_info.get("valid") is True)
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
    model_swap_requirement_value = (
        ROOT / "requirements-model-swap.txt"
    ).read_text(encoding="utf-8").strip()
    model_swap_requirement_okay = (
        model_swap_requirement_value == MODEL_SWAP_REQUIREMENT
    )
    steps.append(
        {
            "name": "model_swap_dependency_pin",
            "passed": model_swap_requirement_okay,
            "expected_commit": HALF_LIFE_COMMIT,
            "requirement": model_swap_requirement_value,
        }
    )
    passed.append(model_swap_requirement_okay)
    try:
        ci_workflow_text = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
    except OSError:
        ci_workflow_text = ""
    ci_missing = [
        snippet for snippet in CI_REQUIRED_SNIPPETS
        if snippet not in ci_workflow_text
    ]
    ci_workflow_okay = not ci_missing
    steps.append(
        {
            "name": "github_actions_release_gate",
            "passed": ci_workflow_okay,
            "path": str(CI_WORKFLOW_PATH.relative_to(ROOT)),
            "missing_required_snippets": ci_missing,
        }
    )
    passed.append(ci_workflow_okay)
    steps.append(
        {
            "name": "model_swap_runtime_and_fixture_required",
            "passed": model_swap_info["supported"],
            **model_swap_info,
        }
    )
    passed.append(bool(model_swap_info["supported"]))
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
    try:
        warning_time_report = json.loads(
            (ROOT / "benchmarks" / "warning_time" / "results" / "benchmark_report.json").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        warning_time_report = {}
    try:
        x402_airlock_report = json.loads(
            (
                ROOT
                / "benchmarks"
                / "x402_airlock"
                / "results"
                / "hostile_report.json"
            ).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        x402_airlock_report = {}
    try:
        x402_upstream_report = json.loads(
            (
                ROOT
                / "benchmarks"
                / "x402_upstream_consequence"
                / "results"
                / "comparison.json"
            ).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        x402_upstream_report = {}

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
        + (0 if model_swap_info["supported"] else MODEL_SWAP_INTEGRATION_TESTS)
        + (
            0
            if model_swap_info["supported"]
            else VERIFIED_CONTINUATION_INTEGRATION_TESTS
        )
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
    absent_environment.pop("OLP_HALF_LIFE_ROOT", None)
    absent_environment.pop("OLP_HALF_LIFE_SOURCE_ROOT", None)
    absent_environment["PYTHONPATH"] = os.pathsep.join(
        value
        for value in absent_environment.get("PYTHONPATH", "").split(
            os.pathsep
        )
        if value and value != str(VENDORED_HALF_LIFE_SITE)
    )
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
        == PIPELOCK_INTEGRATION_TESTS
        + ASSAY_INTEGRATION_TESTS
        + MODEL_SWAP_INTEGRATION_TESTS
        + VERIFIED_CONTINUATION_INTEGRATION_TESTS
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

    handoff_summary: dict[str, Any] = {}
    handoff_command = [
        sys.executable,
        "-m",
        "olp_gate.command",
        "handoff-check",
        "examples/handoff/generic-history.jsonl",
        "--next",
        "implement the authentication refactor",
        "--source",
        "generic",
        "--output",
        str(handoff_output),
    ]
    record, handoff_okay = execute("handoff_check_demo", handoff_command)
    steps.append(record)
    passed.append(handoff_okay)
    if handoff_okay:
        try:
            handoff_summary = json.loads(record["stdout"])
        except (json.JSONDecodeError, TypeError):
            handoff_okay = False
            passed.append(False)
            steps.append({"name": "handoff_check_demo_parse", "passed": False})

    role_confusion_summary: dict[str, Any] = {}
    role_suite_command = [
        sys.executable,
        "benchmarks/role_confusion_consequence/run_suite.py",
    ]
    record, role_suite_okay = execute(
        "role_confusion_consequence_suite",
        role_suite_command,
    )
    steps.append(record)
    passed.append(role_suite_okay)
    if role_suite_okay:
        try:
            role_confusion_summary = json.loads(
                (
                    ROOT
                    / "benchmarks"
                    / "role_confusion_consequence"
                    / "results"
                    / "hostile_report.json"
                ).read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError, TypeError):
            role_suite_okay = False
            passed.append(False)
            steps.append(
                {
                    "name": "role_confusion_consequence_report_parse",
                    "passed": False,
                }
            )
    record, role_verify_okay = execute(
        "role_confusion_consequence_independent_verifier",
        [sys.executable, "scripts/verify_role_confusion_consequence.py"],
    )
    steps.append(record)
    passed.append(role_verify_okay)

    continuation_command = [
        sys.executable,
        "-m",
        "olp_gate.cli",
        "evaluate-continuation",
        "benchmarks/verified_continuation",
        "--output",
        str(verified_continuation_output),
    ]
    record, continuation_okay = execute(
        "verified_continuation_synthetic_conformance",
        continuation_command,
    )
    steps.append(record)
    passed.append(continuation_okay)
    verified_continuation_summary: dict[str, Any] = {}
    continuation_report: dict[str, Any] = {}
    continuation_projection: dict[str, Any] = {}
    if continuation_okay:
        try:
            verified_continuation_summary = json.loads(record["stdout"])
            continuation_report = json.loads(
                (
                    verified_continuation_output / "continuation_report.json"
                ).read_text(encoding="utf-8")
            )
            continuation_projection = json.loads(
                (
                    verified_continuation_output / "dsm_projection.json"
                ).read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError, TypeError):
            continuation_okay = False
            passed.append(False)
            steps.append(
                {
                    "name": "verified_continuation_summary_parse",
                    "passed": False,
                }
            )

    model_swap_summary: dict[str, Any] = {}
    verified_commit_summary: dict[str, Any] = {}
    branch_authorization_summary: dict[str, Any] = {}
    if model_swap_info["supported"]:
        half_life_root = Path(str(model_swap_info["fixture_root"]))
        model_swap_command = [
            sys.executable,
            "-m",
            "olp_gate.cli",
            "demo-model-swap",
            "--half-life-output",
            str(half_life_root / "examples" / "demo_output"),
            "--succession-policy-key",
            str(half_life_root / "policy" / "succession_policy_public_key.hex"),
            "--compaction-policy-key",
            str(half_life_root / "policy" / "compaction_policy_public_key.hex"),
            "--source-model",
            "fixture/source-model",
            "--target-model",
            "fixture/target-model",
            "--output",
            str(model_swap_output),
        ]
        record, okay = execute("verified_model_swap_demo", model_swap_command)
        steps.append(record)
        passed.append(okay)
        if okay:
            try:
                model_swap_summary = json.loads(record["stdout"])
            except (json.JSONDecodeError, TypeError):
                model_swap_summary = {}
                okay = False
                passed.append(False)
                steps.append(
                    {
                        "name": "verified_model_swap_summary_parse",
                        "passed": False,
                    }
                )
        if okay:
            verify_command = [
                sys.executable,
                "-m",
                "olp_gate.cli",
                "verify-model-swap",
                str(model_swap_output),
                "--half-life-output",
                str(half_life_root / "examples" / "demo_output"),
                "--succession-policy-key",
                str(half_life_root / "policy" / "succession_policy_public_key.hex"),
                "--compaction-policy-key",
                str(half_life_root / "policy" / "compaction_policy_public_key.hex"),
                "--gate-key",
                str(model_swap_summary.get("gate_public_key", "")),
            ]
            record, okay = execute("verified_model_swap_receiver_regrade", verify_command)
            steps.append(record)
            passed.append(okay)

        verified_commit_command = [
            sys.executable,
            "-m",
            "olp_gate.cli",
            "demo-verified-commit",
            "--half-life-output",
            str(half_life_root / "examples" / "demo_output"),
            "--succession-policy-key",
            str(half_life_root / "policy" / "succession_policy_public_key.hex"),
            "--compaction-policy-key",
            str(half_life_root / "policy" / "compaction_policy_public_key.hex"),
            "--source-model",
            "fixture/model-a",
            "--target-model",
            "fixture/model-b",
            "--output",
            str(verified_commit_output),
        ]
        record, commit_okay = execute(
            "verified_commit_model_swap_and_action_demo",
            verified_commit_command,
        )
        steps.append(record)
        passed.append(commit_okay)
        if commit_okay:
            try:
                verified_commit_summary = json.loads(record["stdout"])
            except (json.JSONDecodeError, TypeError):
                verified_commit_summary = {}
                commit_okay = False
                passed.append(False)
                steps.append(
                    {
                        "name": "verified_commit_summary_parse",
                        "passed": False,
                    }
                )
        if commit_okay:
            verify_commit_command = [
                sys.executable,
                "-m",
                "olp_gate.cli",
                "verify-verified-commit",
                str(verified_commit_output),
                "--half-life-output",
                str(half_life_root / "examples" / "demo_output"),
                "--succession-policy-key",
                str(half_life_root / "policy" / "succession_policy_public_key.hex"),
                "--compaction-policy-key",
                str(half_life_root / "policy" / "compaction_policy_public_key.hex"),
                "--gate-key",
                str(verified_commit_summary.get("gate_public_key", "")),
            ]
            record, commit_okay = execute(
                "verified_commit_receiver_regrade",
                verify_commit_command,
            )
            steps.append(record)
            passed.append(commit_okay)
            record, node_commit_okay = execute(
                "verified_commit_node_decision_verifier",
                [
                    "node",
                    "verify-decision-node.mjs",
                    str(verified_commit_output / "decision_receipts.jsonl"),
                    "--gate-key",
                    str(verified_commit_summary.get("gate_public_key", "")),
                ],
            )
            steps.append(record)
            passed.append(node_commit_okay)

        branch_authorization_command = [
            sys.executable,
            "-m",
            "olp_gate.cli",
            "demo-continuation-authorization",
            "--half-life-output",
            str(half_life_root / "examples" / "demo_output"),
            "--succession-policy-key",
            str(half_life_root / "policy" / "succession_policy_public_key.hex"),
            "--compaction-policy-key",
            str(half_life_root / "policy" / "compaction_policy_public_key.hex"),
            "--source-model",
            "fixture/producer-model",
            "--target-model",
            "fixture/receiving-model",
            "--output",
            str(branch_authorization_output),
            "--trial-id",
            "verified-continuation-release",
        ]
        record, branch_okay = execute(
            "verified_continuation_exact_branch_authorization",
            branch_authorization_command,
        )
        steps.append(record)
        passed.append(branch_okay)
        if branch_okay:
            try:
                branch_authorization_summary = json.loads(record["stdout"])
            except (json.JSONDecodeError, TypeError):
                branch_authorization_summary = {}
                branch_okay = False
                passed.append(False)
                steps.append(
                    {
                        "name": "verified_continuation_authorization_parse",
                        "passed": False,
                    }
                )
        if branch_okay:
            branch_verify_command = [
                sys.executable,
                "-m",
                "olp_gate.cli",
                "verify-continuation-authorization",
                str(branch_authorization_output),
                "--half-life-output",
                str(half_life_root / "examples" / "demo_output"),
                "--succession-policy-key",
                str(half_life_root / "policy" / "succession_policy_public_key.hex"),
                "--compaction-policy-key",
                str(half_life_root / "policy" / "compaction_policy_public_key.hex"),
                "--gate-key",
                str(branch_authorization_summary.get("gate_public_key", "")),
            ]
            record, branch_okay = execute(
                "verified_continuation_authorization_receiver_regrade",
                branch_verify_command,
            )
            steps.append(record)
            passed.append(branch_okay)
            record, branch_node_okay = execute(
                "verified_continuation_authorization_node_decision_verifier",
                [
                    "node",
                    "verify-decision-node.mjs",
                    str(
                        branch_authorization_output
                        / "gate"
                        / "decision_receipts.jsonl"
                    ),
                    "--gate-key",
                    str(branch_authorization_summary.get("gate_public_key", "")),
                ],
            )
            steps.append(record)
            passed.append(branch_node_okay)

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
        ("compileall", [sys.executable, "-m", "compileall", "-q", "olp_gate", "benchmarks"]),
        (
            "warning_time_benchmark_verifier",
            [sys.executable, "scripts/verify_warning_time_benchmark.py"],
        ),
        (
            "x402_transaction_airlock_hostile_suite",
            [
                sys.executable,
                "benchmarks/x402_airlock/run_hostile_suite.py",
            ],
        ),
        (
            "x402_transaction_airlock_independent_verifier",
            [sys.executable, "scripts/verify_x402_airlock.py"],
        ),
        (
            "verified_continuation_independent_verifier",
            [sys.executable, "scripts/verify_verified_continuation.py"],
        ),
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

    try:
        x402_airlock_report = json.loads(
            (
                ROOT
                / "benchmarks"
                / "x402_airlock"
                / "results"
                / "hostile_report.json"
            ).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        x402_airlock_report = {}

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
            wheels = sorted(wheelhouse.glob(f"openline_receipt_gate-{VERSION}-*.whl"))
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
                record, role_cli_okay = execute(
                    "installed_role_confusion_cli_from_unrelated_cwd",
                    [sys.executable, "-m", "olp_gate.command", "role-confusion-suite"],
                    cwd=outside,
                    env=environment,
                )
                steps.append(record)
                passed.append(role_cli_okay)
                okay = okay and role_cli_okay
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
    release_assertions = {
        "proof_summary_passed": proof_summary.get("passed") is True,
        "handoff_check_demo_safe": (
            handoff_summary.get("disposition") == "SAFE_TO_CONTINUE"
            and handoff_summary.get("source") == "generic"
            and bool(handoff_summary.get("capsule_sha256"))
            and bool(handoff_summary.get("receipt_sha256"))
        ),
        "role_confusion_suite_passed": (
            role_confusion_summary.get("passed") is True
        ),
        "role_confusion_all_13_cases_passed": (
            role_confusion_summary.get("case_count") == 13
            and role_confusion_summary.get("cases_passed") == 13
        ),
        "role_confusion_authorization_valid_hostile_effects_blocked": (
            role_confusion_summary.get("authorization_valid_hostile_cases") == 6
            and role_confusion_summary.get(
                "authorization_valid_hostile_effects_blocked"
            )
            == 6
        ),
        "role_confusion_pre_effect_callback_boundary": (
            role_confusion_summary.get("protected_effect_callback_count") == 3
            and role_confusion_summary.get("blocked_rows_invoked_effect") is False
        ),
        "role_confusion_matched_legitimate_twin_committed": (
            role_confusion_summary.get("matched_legitimate_twin_committed") is True
        ),
        "role_confusion_not_generic_blocker": (
            role_confusion_summary.get("unrelated_untrusted_addition_committed") is True
        ),
        "role_confusion_detector_independent_input_surface": (
            role_confusion_summary.get("injection_text_visible_to_gate") is False
            and role_confusion_summary.get("attack_label_visible_to_gate") is False
        ),
        "proof_case_count_is_five": proof_summary.get(
            "decision_receipt_count"
        )
        == 5,
        "warning_time_profile_signature_valid": warning_time_report.get(
            "calibration_profile_signature_valid"
        ) is True,
        "warning_time_calibration_and_heldout_split": (
            warning_time_report.get("heldout", {}).get("calibration_clean_runs") == 40
            and warning_time_report.get("aggregate", {}).get("heldout_clean_runs_evaluated") == 20
            and warning_time_report.get("aggregate", {}).get("heldout_corruption_runs") == 40
        ),
        "warning_time_heldout_clean_false_alarms_zero": warning_time_report.get("aggregate", {}).get(
            "heldout_clean_run_false_alarms"
        ) == 0,
        "warning_time_missed_corruptions_zero": warning_time_report.get("aggregate", {}).get(
            "missed_corruptions"
        ) == 0,
        "warning_time_decisions_match": warning_time_report.get("aggregate", {}).get(
            "final_decision_counts"
        ) == {
            "control": {"COMMIT": 20},
            "dropped_counterevidence": {"QUARANTINE": 20},
            "unflagged_contradiction": {"DENY": 20},
        },
        "warning_time_positive_windows": all(
            warning_time_report.get("reference_cases", {}).get(case, {}).get("warning_time_steps", 0) > 0
            for case in ("dropped_counterevidence", "unflagged_contradiction")
        ),
        "warning_time_observable_state_only": warning_time_report.get(
            "metric_input_boundary"
        ) == "observable_state_and_previous_observable_state_only",
        "warning_time_label_swap_probe_passed": warning_time_report.get(
            "label_leak_probe", {}
        ).get("passed") is True,
        "warning_time_paired_heldout_seeds": warning_time_report.get(
            "paired_heldout_seeds"
        ) is True,
        "warning_time_external_custody_anchor_valid": (
            warning_time_report.get("external_freeze_anchor_valid") is True
            and warning_time_report.get("external_freeze_anchor", {}).get("service")
            == "chatgpt_file_library"
            and warning_time_report.get("external_freeze_anchor", {}).get("visibility")
            == "private_user_library"
        ),
        "warning_time_chronology_valid": (
            bool(warning_time_report.get("evaluation_started_at"))
            and bool(warning_time_report.get("external_freeze_anchor", {}).get("custody_created_at"))
            and warning_time_report.get("evaluation_started_at")
            > warning_time_report.get("external_freeze_anchor", {}).get("custody_created_at")
        ),
        "x402_airlock_report_valid": x402_airlock_report.get("valid")
        is True,
        "x402_airlock_all_56_cases_passed": (
            x402_airlock_report.get("case_count") == 56
            and x402_airlock_report.get("passed_cases") == 56
            and x402_airlock_report.get("failed_cases") == []
        ),
        "x402_airlock_covers_sr1_through_sr8": set(
            x402_airlock_report.get("rules_covered", [])
        )
        == {f"SR{index}" for index in range(1, 9)},
        "x402_airlock_falsifier_axes_blocked": (
            x402_airlock_report.get("required_falsifier_axes")
            == {
                "amount": True,
                "asset": True,
                "expiry": True,
                "network": True,
                "recipient": True,
                "replay": True,
                "verification_settlement_divergence": True,
            }
        ),
        "x402_upstream_consequence_passed": (
            x402_upstream_report.get("passed") is True
        ),
        "x402_upstream_native_failure_left_effect": (
            x402_upstream_report.get("observations", {})
            .get("native_settlement_failure", {})
            .get("durable_tool_effect_count")
            == 1
            and x402_upstream_report.get("observations", {})
            .get("native_settlement_failure", {})
            .get("returned_error")
            is True
        ),
        "x402_upstream_airlock_failure_withheld_release": (
            x402_upstream_report.get("observations", {})
            .get("airlock_settlement_failure", {})
            .get("protected_release_calls")
            == 0
            and x402_upstream_report.get("observations", {})
            .get("airlock_settlement_failure", {})
            .get("protected_effect_exists")
            is False
        ),
        "x402_upstream_airlock_legitimate_control_released": (
            x402_upstream_report.get("observations", {})
            .get("airlock_success_control", {})
            .get("protected_release_calls")
            == 1
            and x402_upstream_report.get("observations", {})
            .get("airlock_success_control", {})
            .get("resource_released")
            is True
        ),
        "pipelock_benchmark_passed": benchmark_report.get("passed") is True,
        "pipelock_strong_hypothesis_falsified": pipelock_summary.get(
            "flagship_finding", {}
        ).get("strong_hypothesis_falsified")
        is True,
        "assay_benchmark_passed": assay_benchmark_report.get("passed") is True,
        "assay_signing_uniqueness_hypothesis_falsified": assay_summary.get(
            "capability_control", {}
        ).get("strong_signing_uniqueness_hypothesis_falsified")
        is True,
        "model_swap_passed": model_swap_summary.get("passed") is True,
        "model_swap_committed": model_swap_summary.get("decision") == "COMMIT",
        "model_swap_capsule_matches_oracle": model_swap_summary.get(
            "capsule_matches_oracle"
        )
        is True,
        "model_swap_archive_matches_oracle": model_swap_summary.get(
            "archive_matches_oracle"
        )
        is True,
        "verified_commit_passed": verified_commit_summary.get("passed") is True,
        "verified_commit_committed": verified_commit_summary.get("decision")
        == "COMMIT",
        "verified_commit_mutation_count_is_nine": verified_commit_summary.get(
            "mutation_count"
        )
        == 9,
        "verified_commit_all_mutations_blocked": verified_commit_summary.get(
            "mutations_blocked_before_execution"
        )
        == 9,
        "verified_commit_one_simultaneous_authorized": verified_commit_summary.get(
            "simultaneous_authorized"
        )
        == 1,
        "verified_commit_one_simultaneous_blocked": verified_commit_summary.get(
            "simultaneous_blocked"
        )
        == 1,
        "verified_commit_replay_blocked": verified_commit_summary.get(
            "replay_blocked"
        )
        is True,
        "verified_continuation_harness_valid": (
            verified_continuation_summary.get("valid") is True
        ),
        "verified_continuation_synthetic_stays_undecidable": (
            verified_continuation_summary.get("continuation_disposition")
            == "UNDECIDABLE"
            and continuation_report.get("continuation_claim", {}).get(
                "external_evidence_sufficient"
            )
            is False
        ),
        "verified_continuation_mechanism_rule_reproduces": (
            verified_continuation_summary.get("mechanism_rule_passed") is True
        ),
        "verified_continuation_dsm_does_not_grade": (
            continuation_projection.get("display_only") is True
            and all(
                continuation_projection.get("coherence_dynamics", {})
                .get(metric, {})
                .get("status")
                == "UNDECIDABLE"
                for metric in ("kappa", "phi_star", "vkd")
            )
        ),
        "verified_continuation_authorization_passed": (
            branch_authorization_summary.get("passed") is True
        ),
        "verified_continuation_wrong_branch_blocked": (
            branch_authorization_summary.get("wrong_branch_blocked") is True
        ),
        "verified_continuation_mutated_target_blocked": (
            branch_authorization_summary.get("mutated_target_blocked") is True
        ),
        "verified_continuation_expired_blocked": (
            branch_authorization_summary.get("expired_blocked") is True
        ),
        "verified_continuation_replay_blocked": (
            branch_authorization_summary.get("replay_blocked") is True
        ),
        "verified_continuation_simultaneous_exactly_once": (
            branch_authorization_summary.get("simultaneous_authorized") == 1
            and branch_authorization_summary.get("simultaneous_blocked") == 1
        ),
    }
    release_assertions_okay = all(release_assertions.values())
    steps.append(
        {
            "name": "release_assertions",
            "passed": release_assertions_okay,
            "conditions": release_assertions,
            "failed_conditions": sorted(
                name for name, okay in release_assertions.items() if not okay
            ),
        }
    )
    passed.append(release_assertions_okay)
    release_passed = all(passed)
    live_pipelock_tests_passed = bool(
        pipelock_info["supported"]
        and unit_okay
        and unit_counts["skipped"]
        == (0 if assay_info["supported"] else ASSAY_INTEGRATION_TESTS)
        + (0 if model_swap_info["supported"] else MODEL_SWAP_INTEGRATION_TESTS)
        + (
            0
            if model_swap_info["supported"]
            else VERIFIED_CONTINUATION_INTEGRATION_TESTS
        )
    )
    live_assay_tests_passed = bool(
        assay_info["supported"]
        and unit_okay
        and unit_counts["skipped"]
        == (0 if pipelock_info["supported"] else PIPELOCK_INTEGRATION_TESTS)
        + (0 if model_swap_info["supported"] else MODEL_SWAP_INTEGRATION_TESTS)
        + (
            0
            if model_swap_info["supported"]
            else VERIFIED_CONTINUATION_INTEGRATION_TESTS
        )
    )
    live_model_swap_tests_passed = bool(
        model_swap_info["supported"]
        and unit_okay
        and unit_counts["skipped"]
        == (0 if pipelock_info["supported"] else PIPELOCK_INTEGRATION_TESTS)
        + (0 if assay_info["supported"] else ASSAY_INTEGRATION_TESTS)
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
        },
        "verified_model_swap": {
            **model_swap_info,
            "live_integration_tests_executed": model_swap_info["supported"],
            "live_integration_tests_passed": live_model_swap_tests_passed,
            "demo_executed": bool(model_swap_summary),
            "demo_passed": model_swap_summary.get("passed") is True,
            "verified_commit_demo_executed": bool(verified_commit_summary),
            "verified_commit_demo_passed": verified_commit_summary.get("passed")
            is True,
            "verified_continuation_authorization_executed": bool(
                branch_authorization_summary
            ),
            "verified_continuation_authorization_passed": (
                branch_authorization_summary.get("passed") is True
            ),
            "dependency_absent_suite_passed": absent_okay,
            "integration_test_count": MODEL_SWAP_INTEGRATION_TESTS,
            "verified_continuation_integration_test_count": (
                VERIFIED_CONTINUATION_INTEGRATION_TESTS
            ),
        },
    }
    from olp_gate.verified_continuation import build_experiment_summary

    experiment_summary = build_experiment_summary(
        continuation_report,
        branch_authorization_summary,
    )
    (
        ROOT / "results" / "verified_continuation_summary.json"
    ).write_text(
        json.dumps(experiment_summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
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
        "vendored_half_life_release_bundle": vendored_half_life_info,
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
        "handoff_check": handoff_summary,
        "role_confusion_consequence": role_confusion_summary,
        "verified_model_swap": model_swap_summary,
        "verified_commit": verified_commit_summary,
        "verified_continuation": {
            "summary": experiment_summary,
            "harness": verified_continuation_summary,
            "continuation_report": continuation_report,
            "dsm_projection": continuation_projection,
            "authorization": branch_authorization_summary,
        },
        "proof_to_policy_demo": proof_summary,
        "warning_time_benchmark": warning_time_report,
        "x402_transaction_airlock": x402_airlock_report,
        "x402_upstream_consequence": x402_upstream_report,
        "pipelock_head_to_head": pipelock_summary,
        "assay_head_to_head": assay_summary,
        "claim_boundary": "A passing deterministic release gate does not prove production safety, issuer honesty, complete capture, live provider execution, universal model portability, legal ownership, witness independence, rollback execution, or globally exactly-once side effects. The vendored Half-Life bundle makes the release gate runnable offline and is hash-checked locally; local hashes do not independently establish upstream provenance, so CI separately compares it byte-for-byte with the pinned upstream commit. Verified Model Swap is exact only over the disclosed receiver decision projection and pinned Half-Life fixture. Verified Commit proves receiver-side one-use authorization only when the destination tool enters through the disclosed checker and shares its atomic ledger; a crash after consumption fails closed. The Verified Continuation fixture proves harness conformance only and must remain UNDECIDABLE until matched outside provider runs are disclosed. Its exact-branch authorization result is separate and local. Handoff Check certifies fidelity only against explicit state in the supplied local history; it does not establish history completeness or real-agent success. The Role-Confusion Consequence Gate is a synthetic post-compromise mechanism test with a harmless callback; it does not establish that a live model or published attack was reproduced, and its standalone callback is not an atomic replay ledger. Production effects must compose appraisal with Verified Commit. The x402 Transaction Airlock hostile matrix is synthetic. Separately, the pinned official Python MCP wrapper comparison reproduces one real source-order consequence: a tool effect occurs before failed settlement, while the disclosed airlock withholds protected release. That result is limited to the exact pinned source and local effect; it is not a live-chain exploit or a claim about every x402 SDK.",
    }
    (ROOT / "RUN_REPORT.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_manifest(
        checks_passed=release_passed,
        proof_summary=proof_summary,
        model_swap_summary=model_swap_summary,
        verified_commit_summary=verified_commit_summary,
        verified_continuation_summary=verified_continuation_summary,
        branch_authorization_summary=branch_authorization_summary,
        handoff_summary=handoff_summary,
        pipelock_summary={
            "passed": benchmark_report.get("passed", False),
            "strong_hypothesis_falsified": pipelock_summary.get(
                "flagship_finding", {}
            ).get("strong_hypothesis_falsified"),
            "aggregate": pipelock_summary.get("aggregate", {}),
        },
        warning_time_summary=warning_time_report,
        x402_airlock_summary=x402_airlock_report,
        x402_upstream_summary=x402_upstream_report,
        role_confusion_summary=role_confusion_summary,
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
    failed_checks = []
    for step in steps:
        if step.get("passed") is not False:
            continue
        failure = {
            "name": step.get("name", "unnamed_check"),
            "returncode": step.get("returncode"),
        }
        if step.get("error"):
            failure["error"] = step["error"]
        if step.get("failed_conditions"):
            failure["failed_conditions"] = step["failed_conditions"]
        if step.get("stdout"):
            failure["stdout_tail"] = str(step["stdout"])[-4000:]
        if step.get("stderr"):
            failure["stderr_tail"] = str(step["stderr"])[-4000:]
        failed_checks.append(failure)
    print(json.dumps({
        "passed": release_passed and manifest_check.returncode == 0,
        "release_checks": len(steps),
        "failed_checks": failed_checks,
        "proof_to_policy_cases": proof_summary.get("decision_receipt_count", 0),
        "verified_commit_passed": verified_commit_summary.get("passed", False),
        "handoff_check_disposition": handoff_summary.get("disposition"),
        "role_confusion_consequence_passed": role_confusion_summary.get(
            "passed",
            False,
        ),
        "verified_continuation_disposition": (
            verified_continuation_summary.get("continuation_disposition")
        ),
        "verified_continuation_authorization_passed": (
            branch_authorization_summary.get("passed", False)
        ),
        "manifest": json.loads(manifest_check.stdout) if manifest_check.stdout else {"valid": False},
    }, indent=2, sort_keys=True))
    return 0 if release_passed and manifest_check.returncode == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
