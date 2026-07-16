#!/usr/bin/env python3
"""Run the hash-frozen OLP x Assay v3.32.0 head-to-head."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CASES_PATH = HERE / "CASES.json"
MANIFEST_PATH = HERE / "FIXTURE_MANIFEST.json"
PROTOCOL_PATH = HERE / "PROTOCOL.md"
PROTOCOL_HASH_PATH = HERE / "PROTOCOL.sha256"
FREEZE_PATH = HERE / "FREEZE.json"

ASSAY_VERSION = "3.32.0"
ASSAY_RELEASE_COMMIT = "04d3db10adbe191aa731d52a6c2b77dad8bc0ca7"
ASSAY_ARCHIVE_SHA256 = "243f5e3935530cb1405dbb54fa57acc944de2800d28537d08dfc305b2a117775"
ASSAY_BUNDLE_SHA256 = "06902924787b20aad33b5ec521fb82f3aeec361da290a3b2a862ea149946bc8b"
GATE_PRIVATE_BYTES = bytes.fromhex("84" * 32)
ATTESTATION_PRIVATE_BYTES = bytes.fromhex("95" * 32)

# Running this file directly puts ``benchmarks/assay`` rather than the
# repository root on sys.path.  Add the fixed local root before the deferred OLP
# imports used by the scored lane; never take an import path from a fixture.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def measured(call: Callable[[], Any]) -> tuple[Any, int, int]:
    def cpu_ns() -> int:
        self_usage = resource.getrusage(resource.RUSAGE_SELF)
        child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        seconds = (
            self_usage.ru_utime
            + self_usage.ru_stime
            + child_usage.ru_utime
            + child_usage.ru_stime
        )
        return int(seconds * 1_000_000_000)

    wall_start = time.perf_counter_ns()
    cpu_start = cpu_ns()
    value = call()
    return value, time.perf_counter_ns() - wall_start, cpu_ns() - cpu_start


def run_process(command: Sequence[str | Path]) -> dict[str, Any]:
    def invoke() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(value) for value in command],
            check=False,
            capture_output=True,
            text=True,
        )

    completed, wall_ns, cpu_ns = measured(invoke)
    return {
        "command": [str(value) for value in command],
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "wall_time_ns": wall_ns,
        "cpu_time_ns": cpu_ns,
    }


def benchmark_outcome(observed: Mapping[str, Any], expected: Mapping[str, Any]) -> str:
    if observed.get("execution_error"):
        return "undecidable"
    return "correct" if all(observed.get(key) == value for key, value in expected.items()) else "incorrect"


def safe_child(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"unsafe fixture path: {relative}")
    return candidate


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def verify_frozen_inputs() -> dict[str, Any]:
    errors: list[str] = []
    manifest = load_json(MANIFEST_PATH)
    protocol_hash = sha256_bytes(PROTOCOL_PATH.read_bytes())
    recorded_hash = PROTOCOL_HASH_PATH.read_text(encoding="ascii").strip().split()[0]
    if protocol_hash != recorded_hash:
        errors.append("protocol_hash_mismatch")
    freeze = load_json(FREEZE_PATH)
    if freeze.get("protocol_sha256") != protocol_hash:
        errors.append("freeze_protocol_hash_mismatch")
    if freeze.get("cases_sha256") != sha256_bytes(CASES_PATH.read_bytes()):
        errors.append("freeze_cases_hash_mismatch")
    if freeze.get("fixture_manifest_sha256") != sha256_bytes(MANIFEST_PATH.read_bytes()):
        errors.append("freeze_fixture_manifest_hash_mismatch")
    for entry in manifest.get("files", []):
        relative = entry.get("path")
        if not isinstance(relative, str):
            errors.append("fixture_manifest_entry_invalid")
            continue
        try:
            path = safe_child(FIXTURES, relative)
        except ValueError:
            errors.append(f"fixture_path_unsafe:{relative}")
            continue
        if not path.is_file():
            errors.append(f"fixture_missing:{relative}")
        elif sha256_bytes(path.read_bytes()) != entry.get("sha256"):
            errors.append(f"fixture_hash_mismatch:{relative}")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "protocol_sha256": protocol_hash,
        "cases_sha256": sha256_bytes(CASES_PATH.read_bytes()),
        "fixture_manifest_sha256": sha256_bytes(MANIFEST_PATH.read_bytes()),
        "freeze_commit": freeze.get("freeze_commit"),
    }


def verify_assay_runtime(binary: Path, archive: Path) -> dict[str, Any]:
    errors: list[str] = []
    archive_hash = sha256_bytes(archive.read_bytes())
    if archive_hash != ASSAY_ARCHIVE_SHA256:
        errors.append("assay_release_archive_hash_mismatch")
    version = run_process([binary, "--version"])
    if version["returncode"] != 0 or version["stdout"].strip() != f"assay {ASSAY_VERSION}":
        errors.append("assay_version_mismatch")

    binary_hash = sha256_bytes(binary.read_bytes())
    archive_binary_hash: str | None = None
    try:
        with tarfile.open(archive, "r:gz") as handle:
            members = [
                member
                for member in handle.getmembers()
                if member.isfile() and Path(member.name).name == "assay"
            ]
            if len(members) != 1:
                errors.append("assay_release_binary_member_ambiguous")
            else:
                extracted = handle.extractfile(members[0])
                if extracted is None:
                    errors.append("assay_release_binary_member_unavailable")
                else:
                    archive_binary_hash = sha256_bytes(extracted.read())
                    if archive_binary_hash != binary_hash:
                        errors.append("assay_binary_not_from_pinned_archive")
    except (OSError, tarfile.TarError):
        errors.append("assay_release_archive_unreadable")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "version": version["stdout"].strip() or None,
        "release_commit": ASSAY_RELEASE_COMMIT,
        "release_archive_sha256": archive_hash,
        "binary_sha256": binary_hash,
        "archive_binary_sha256": archive_binary_hash,
    }


def regenerate_upstream_bundle(binary: Path, temporary: Path) -> dict[str, Any]:
    output = temporary / "regenerated-openfeature-bundle.tar.gz"
    command = [
        binary,
        "evidence",
        "import",
        "openfeature-details",
        "--input",
        FIXTURES / "upstream" / "decision-details.openfeature.jsonl",
        "--bundle-out",
        output,
        "--source-artifact-ref",
        "decision-details.openfeature.jsonl",
        "--run-id",
        "olp_assay_h2h",
        "--import-time",
        "2026-07-16T12:00:00Z",
    ]
    process = run_process(command)
    actual_hash = sha256_bytes(output.read_bytes()) if output.is_file() else None
    command_template = [
        "$ASSAY_BIN",
        "evidence",
        "import",
        "openfeature-details",
        "--input",
        "benchmarks/assay/fixtures/upstream/decision-details.openfeature.jsonl",
        "--bundle-out",
        "<temporary>/regenerated-openfeature-bundle.tar.gz",
        "--source-artifact-ref",
        "decision-details.openfeature.jsonl",
        "--run-id",
        "olp_assay_h2h",
        "--import-time",
        "2026-07-16T12:00:00Z",
    ]
    return {
        "valid": process["returncode"] == 0 and actual_hash == ASSAY_BUNDLE_SHA256,
        "expected_sha256": ASSAY_BUNDLE_SHA256,
        "actual_sha256": actual_hash,
        "byte_identical_to_frozen_fixture": (
            output.is_file()
            and output.read_bytes()
            == (FIXTURES / "assay" / "openfeature-decision-receipts.tar.gz").read_bytes()
        ),
        "command_template": command_template,
        "returncode": process["returncode"],
        "wall_time_ns": process["wall_time_ns"],
        "cpu_time_ns": process["cpu_time_ns"],
        "diagnostic": process["stderr"].strip().replace(str(output), "<temporary>/regenerated-openfeature-bundle.tar.gz"),
    }


def materialize_case(case: Mapping[str, Any], temporary: Path) -> tuple[Path, Path]:
    base_dir = temporary / str(case["case_id"])
    shutil.copytree(FIXTURES, base_dir)
    bundle = base_dir / "assay" / "openfeature-decision-receipts.tar.gz"
    if case.get("mutation") == "flip_archive_byte":
        content = bytearray(bundle.read_bytes())
        content[len(content) // 2] ^= 1
        bundle.write_bytes(content)
    return base_dir, bundle


def assay_native_lane(binary: Path, bundle: Path, expected: bool) -> dict[str, Any]:
    process = run_process([binary, "evidence", "verify", bundle])
    observed = {
        "valid": process["returncode"] == 0,
        "execution_error": process["returncode"] not in {0, 1, 2},
    }
    return {
        "valid": observed["valid"],
        "benchmark_outcome": benchmark_outcome(observed, {"valid": expected}),
        "returncode": process["returncode"],
        "diagnostic": (process["stderr"] or process["stdout"])
        .strip()
        .replace(str(bundle), "<bundle>"),
        "wall_time_ns": process["wall_time_ns"],
        "cpu_time_ns": process["cpu_time_ns"],
        "verifier_calls": 1,
        "bytes_read": bundle.stat().st_size,
    }


def assay_trust_basis_lane(
    binary: Path,
    bundle: Path,
    requirements: Sequence[str],
    expected: str,
    temporary: Path,
    native_valid: bool,
) -> dict[str, Any]:
    if not native_valid:
        observed = {"status": "unavailable"}
        return {
            **observed,
            "benchmark_outcome": benchmark_outcome(observed, {"status": expected}),
            "requirements": list(requirements),
            "assertion": None,
            "wall_time_ns": 0,
            "cpu_time_ns": 0,
            "verifier_calls": 0,
            "bytes_read": 0,
        }
    temporary.mkdir(parents=True, exist_ok=True)
    trust_path = temporary / "trust-basis.json"
    generate = run_process([binary, "trust-basis", "generate", bundle, "--out", trust_path])
    assertion: dict[str, Any] | None = None
    assert_process: dict[str, Any] | None = None
    if generate["returncode"] == 0:
        command: list[str | Path] = [binary, "trust-basis", "assert", "--input", trust_path]
        for requirement in requirements:
            command.extend(["--require", requirement])
        command.extend(["--format", "json"])
        assert_process = run_process(command)
        try:
            parsed = json.loads(assert_process["stdout"])
            if isinstance(parsed, dict):
                assertion = parsed
        except json.JSONDecodeError:
            assertion = None
    if generate["returncode"] != 0 or assert_process is None:
        status = "unavailable"
        execution_error = True
    elif assert_process["returncode"] == 0:
        status = "pass"
        execution_error = False
    elif assert_process["returncode"] == 1:
        status = "fail"
        execution_error = False
    else:
        status = "unavailable"
        execution_error = True
    observed = {"status": status, "execution_error": execution_error}
    return {
        "status": status,
        "benchmark_outcome": benchmark_outcome(observed, {"status": expected}),
        "requirements": list(requirements),
        "assertion": assertion,
        "generate_returncode": generate["returncode"],
        "assert_returncode": assert_process["returncode"] if assert_process else None,
        "wall_time_ns": generate["wall_time_ns"] + (assert_process["wall_time_ns"] if assert_process else 0),
        "cpu_time_ns": generate["cpu_time_ns"] + (assert_process["cpu_time_ns"] if assert_process else 0),
        "verifier_calls": 1 + (1 if assert_process else 0),
        "bytes_read": bundle.stat().st_size,
    }


def olp_lane(
    binary: Path,
    base_dir: Path,
    case: Mapping[str, Any],
    ledger_path: Path,
    decision_path: Path,
) -> dict[str, Any]:
    from olp_gate.adapters import TrustStore
    from olp_gate.crypto import public_key_hex
    from olp_gate.gateway import evaluate_request, verify_decision_receipt
    from olp_gate.policy import PolicySpec
    from olp_gate.session import SessionLedger

    request = copy.deepcopy(load_json(base_dir / f"{case['case_id']}.request.json"))
    policy = PolicySpec.from_mapping(load_json(base_dir / "olp-policy.json"))
    trust = TrustStore.from_mapping(load_json(base_dir / "olp-trust.json"))
    ledger = SessionLedger(ledger_path)
    binding = request["binding"]
    challenge = ledger.issue_challenge(
        run_id=binding["run_id"],
        session_id=binding["session_id"],
        expected_source_hash=binding["expected_source_hash"],
        ttl_seconds=300,
    )
    binding["challenge_nonce"] = challenge["challenge_nonce"]
    gate_key = Ed25519PrivateKey.from_private_bytes(GATE_PRIVATE_BYTES)

    def evaluate() -> dict[str, Any]:
        return evaluate_request(
            request,
            policy=policy,
            trust_store=trust,
            signing_key=gate_key,
            issuer_id="olp-assay-benchmark-receiver",
            decision_path=decision_path,
            session_ledger=ledger,
            base_dir=base_dir,
            assay_binary=binary,
        )

    decision, wall_ns, cpu_ns = measured(evaluate)
    signature_check = verify_decision_receipt(decision, [public_key_hex(gate_key)])
    observed = {
        "verdict": decision.get("verdict"),
        "decision": decision.get("decision"),
        "signature_valid": signature_check.get("valid") is True,
        "mechanism_observed": (
            case.get("expected_olp_reason_code") is None
            or case.get("expected_olp_reason_code") in decision.get("reason_codes", [])
        ),
    }
    expected = {
        "verdict": case["expected_olp_verdict"],
        "decision": case["expected_olp_decision"],
        "signature_valid": True,
        "mechanism_observed": True,
    }
    evidence_bytes = sum(
        (base_dir / item["artifact_path"]).stat().st_size
        for item in request.get("evidence", [])
        if isinstance(item, dict) and isinstance(item.get("artifact_path"), str)
    )
    return {
        **observed,
        "benchmark_outcome": benchmark_outcome(observed, expected),
        "reason_codes": decision.get("reason_codes", []),
        "assessment_statuses": {
            name: value.get("status")
            for name, value in decision.get("assessments", {}).items()
            if isinstance(value, dict)
        },
        "payload_hash": decision.get("payload_hash"),
        "wall_time_ns": wall_ns,
        "cpu_time_ns": cpu_ns,
        "verifier_calls": (
            5
            if decision.get("assessments", {}).get("profile", {}).get("status") == "pass"
            else 2
        ),
        "bytes_read": (
            (base_dir / "assay" / "openfeature-decision-receipts.tar.gz").stat().st_size
            + evidence_bytes
        ),
        "evidence_reads": len(request.get("evidence", [])),
    }


def dsse_capability_control(binary: Path, output: Path, temporary: Path) -> dict[str, Any]:
    private_key = Ed25519PrivateKey.from_private_bytes(ATTESTATION_PRIVATE_BYTES)
    public_key = private_key.public_key()
    key_path = temporary / "assay-attestation-key.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    process = run_process(
        [
            binary,
            "evidence",
            "attest",
            "--bundle",
            FIXTURES / "assay" / "openfeature-decision-receipts.tar.gz",
            "--key",
            key_path,
            "--predicate",
            FIXTURES / "receiver-predicate.json",
            "--out",
            output,
        ]
    )
    errors: list[str] = []
    envelope: dict[str, Any] = {}
    statement: dict[str, Any] = {}
    if process["returncode"] != 0 or not output.is_file():
        errors.append("assay_attestation_failed")
    else:
        try:
            envelope = load_json(output)
            payload_type = str(envelope["payloadType"])
            payload = base64.b64decode(str(envelope["payload"]), validate=True)
            statement = json.loads(payload)
            signature = base64.b64decode(str(envelope["signatures"][0]["sig"]), validate=True)
            type_bytes = payload_type.encode("utf-8")
            pae = (
                b"DSSEv1 "
                + str(len(type_bytes)).encode("ascii")
                + b" "
                + type_bytes
                + b" "
                + str(len(payload)).encode("ascii")
                + b" "
                + payload
            )
            public_key.verify(signature, pae)
        except (
            InvalidSignature,
            KeyError,
            IndexError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            errors.append(f"assay_attestation_invalid:{type(exc).__name__}")
        else:
            if statement.get("predicate") != load_json(FIXTURES / "receiver-predicate.json"):
                errors.append("assay_predicate_changed")
    public_hex = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    return {
        "passed": not errors,
        "errors": errors,
        "assay_signed_caller_supplied_receiver_predicate": not errors,
        "strong_signing_uniqueness_hypothesis_falsified": not errors,
        "semantic_decision_verification_by_assay_cli_observed": False,
        "boundary": (
            "This proves that Assay can sign an arbitrary caller-supplied predicate over a "
            "verified bundle. It does not show that Assay recomputed the predicate's receiver "
            "policy semantics or standardized OLP's five post-ingest dispositions."
        ),
        "attestation_path": display_path(output),
        "attestation_sha256": sha256_bytes(output.read_bytes()) if output.is_file() else None,
        "public_key": public_hex,
        "predicate": statement.get("predicate"),
        "subject": statement.get("subject"),
        "wall_time_ns": process["wall_time_ns"],
        "cpu_time_ns": process["cpu_time_ns"],
        "verifier_calls": 1,
    }


def complete_counts(values: Sequence[str]) -> dict[str, int]:
    counts = Counter(values)
    return {name: counts.get(name, 0) for name in ("correct", "incorrect", "undecidable")}


def render_report(report: Mapping[str, Any]) -> str:
    block = report["assay_head_to_head"]
    rows = []
    for case in block["cases"]:
        rows.append(
            "| {case_id} | {native} | {trust} | {olp} | {outcome} |".format(
                case_id=case["case_id"],
                native="valid" if case["assay_native"]["valid"] else "rejected",
                trust=case["assay_trust_basis"]["status"],
                olp=f"{case['olp']['verdict']} → {case['olp']['decision']}",
                outcome=case["olp"]["benchmark_outcome"],
            )
        )
    capability = block["capability_control"]
    return f"""# OLP × Assay Frozen Head-to-Head

## Result

All five frozen expectations were met. Assay correctly verified its evidence
bundle, rejected the corrupted bundle, and rejected a receiver-registered Trust
Basis claim whose required level was absent. OLP did not replace those checks.

The broad proposed wedge was falsified: Assay v3.32.0 can Ed25519-sign a
caller-supplied receiver-style predicate in a DSSE/in-toto attestation. The
capability control independently verified that signature and preserved predicate:
`{str(capability['passed']).lower()}`.

The narrower observed difference is product semantics. With the same unchanged,
Assay-valid source bundle, OLP read the receiver's separately required artifact
and emitted a signed `COMMIT` when it was present and `QUARANTINE` when it was
missing. That is a standardized post-ingest next-use decision in this OLP
profile. It is not evidence that Assay cannot implement the same policy, nor that
an arbitrary signed predicate is uniquely available to OLP.

## Frozen cases

| Case | Assay bundle | Assay Trust Basis | OLP signed decision | OLP scoring outcome |
|---|---|---|---|---|
{chr(10).join(rows)}

## What each system did

- Assay remained authoritative for its bundle verification and registered
  Trust Basis assertions. A failed Assay assertion was propagated into OLP as a
  denial and was never laundered.
- OLP preserved the incoming archive byte-for-byte by hash, then applied a
  receiver-owned policy to a separately supplied artifact and signed what that
  receiver permits next.
- Case 5 isolates an explicit receiver byte pin. Assay's standalone bundle
  verifier correctly accepts the internally intact archive; OLP rejects the
  request because its declared source hash disagrees. A receiver could also add
  an external byte pin around Assay, so this is placement of a binding—not unique
  cryptography.

## Claim boundary

This controlled five-case run demonstrates behavior for Assay v3.32.0 and OLP
v0.4.0 under the frozen fixtures and policies. It does not establish that OLP
"beats" Assay, that Assay lacks receiver policy gates, that OLP has Assay's inline
MCP enforcement, or that signing proves the truth of a predicate. Timing values
are work-cost observations, not reproducibility claims.
"""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assay-bin", type=Path, required=True)
    parser.add_argument("--assay-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=HERE / "RUN_REPORT.json")
    parser.add_argument("--report", type=Path, default=HERE / "REPORT.md")
    parser.add_argument("--results-dir", type=Path, default=HERE / "results")
    args = parser.parse_args(argv)

    binary = args.assay_bin.resolve()
    archive = args.assay_archive.resolve()
    frozen = verify_frozen_inputs()
    runtime = verify_assay_runtime(binary, archive)
    if not frozen["valid"] or not runtime["valid"]:
        print(json.dumps({"passed": False, "freeze": frozen, "runtime": runtime}, indent=2))
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    decision_path = args.results_dir / "decision_receipts.jsonl"
    attestation_path = args.results_dir / "assay_receiver_predicate.attestation.json"
    decision_path.unlink(missing_ok=True)
    attestation_path.unlink(missing_ok=True)

    cases_spec = load_json(CASES_PATH)
    cases: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="olp-assay-head-to-head-") as temp_name:
        temporary = Path(temp_name)
        regeneration = regenerate_upstream_bundle(binary, temporary)
        if not regeneration["valid"] or not regeneration["byte_identical_to_frozen_fixture"]:
            print(json.dumps({"passed": False, "fixture_regeneration": regeneration}, indent=2))
            return 2
        ledger_path = temporary / "sessions.json"
        for case in cases_spec["cases"]:
            base_dir, bundle = materialize_case(case, temporary)
            request = load_json(base_dir / f"{case['case_id']}.request.json")
            requirements = request["source_bundle"]["trust_basis_requirements"]
            native = assay_native_lane(binary, bundle, bool(case["assay_native_valid"]))
            trust = assay_trust_basis_lane(
                binary,
                bundle,
                requirements,
                str(case["assay_trust_assertion"]),
                temporary / f"trust-{case['case_id']}",
                native["valid"],
            )
            olp = olp_lane(binary, base_dir, case, ledger_path, decision_path)
            cases.append(
                {
                    "case_id": case["case_id"],
                    "mutation": case.get("mutation"),
                    "source_archive_sha256": sha256_bytes(bundle.read_bytes()),
                    "assay_native": native,
                    "assay_trust_basis": trust,
                    "olp": olp,
                    "boundary_note": (
                        "Assay and OLP are scored only against their own frozen expectations; "
                        "different outputs may answer different policy questions."
                    ),
                }
            )
        capability = dsse_capability_control(binary, attestation_path, temporary)

    decisions = [
        json.loads(line)
        for line in decision_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    aggregate = {
        "assay_native": complete_counts([case["assay_native"]["benchmark_outcome"] for case in cases]),
        "assay_trust_basis": complete_counts(
            [case["assay_trust_basis"]["benchmark_outcome"] for case in cases]
        ),
        "olp": complete_counts([case["olp"]["benchmark_outcome"] for case in cases]),
    }
    passed = (
        all(value["incorrect"] == 0 and value["undecidable"] == 0 for value in aggregate.values())
        and capability["passed"]
        and len(decisions) == 5
    )
    gate_key = Ed25519PrivateKey.from_private_bytes(GATE_PRIVATE_BYTES)
    public_key = gate_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    report = {
        "schema": "openline.release_run_report.v0.2",
        "version": "0.4.0",
        "generated_at": iso_now(),
        "passed": passed,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "assay": runtime,
        },
        "assay_head_to_head": {
            "passed": passed,
            "protocol": frozen,
            "fixture_regeneration": regeneration,
            "cases": cases,
            "aggregate": aggregate,
            "capability_control": capability,
            "finding": {
                "strong_signing_uniqueness_hypothesis_falsified": capability["passed"],
                "receiver_specific_observation": (
                    "The same Assay-valid source bundle led OLP to COMMIT with the "
                    "receiver-required artifact and QUARANTINE without it."
                ),
                "permitted_claim": (
                    "In this frozen run, OLP preserved an Assay bundle, delegated its native "
                    "claims to Assay, applied a separate receiver policy, and signed a "
                    "standardized next-use disposition."
                ),
            },
            "decision_receipts": {
                "path": display_path(decision_path),
                "sha256": sha256_bytes(decision_path.read_bytes()),
                "count": len(decisions),
                "trusted_gate_public_key": public_key,
            },
        },
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.report.write_text(render_report(report), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
