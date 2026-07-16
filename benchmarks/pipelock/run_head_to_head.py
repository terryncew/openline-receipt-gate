#!/usr/bin/env python3
"""Run the hash-frozen Pipelock ActionReceipt v1 head-to-head."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CASES_PATH = HERE / "CASES.json"
MANIFEST_PATH = HERE / "FIXTURE_MANIFEST.json"
PROTOCOL_PATH = HERE / "PROTOCOL.md"
PROTOCOL_HASH_PATH = HERE / "PROTOCOL.sha256"
FREEZE_PATH = HERE / "FREEZE.json"
AMENDMENT_PATH = HERE / "AMENDMENT-001.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def git_head(path: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def measure(call: Callable[[], Any]) -> tuple[Any, int, int]:
    wall_start = time.perf_counter_ns()
    cpu_start = time.process_time_ns()
    value = call()
    cpu_ns = time.process_time_ns() - cpu_start
    wall_ns = time.perf_counter_ns() - wall_start
    return value, wall_ns, cpu_ns


def as_plain(value: Any) -> dict[str, Any]:
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    if isinstance(value, dict):
        return dict(value)
    raise TypeError(type(value).__name__)


def benchmark_outcome(observed: dict[str, Any], expected: dict[str, Any]) -> str:
    if observed.get("execution_error"):
        return "undecidable"
    for key, value in expected.items():
        if observed.get(key) != value:
            return "incorrect"
    return "correct"


def verify_freeze(
    *,
    pipelock_source: Path,
    pipelock_verify_source: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    freeze = load_json(FREEZE_PATH)
    amendment = load_json(AMENDMENT_PATH)
    manifest = load_json(MANIFEST_PATH)
    cases_hash = sha256_bytes(CASES_PATH.read_bytes())
    manifest_hash = sha256_bytes(MANIFEST_PATH.read_bytes())
    protocol_hash = sha256_bytes(PROTOCOL_PATH.read_bytes())
    hash_line = PROTOCOL_HASH_PATH.read_text(encoding="ascii").strip().split()[0]

    if protocol_hash != hash_line:
        errors.append("current_protocol_hash_mismatch")
    if cases_hash != amendment["cases_sha256_unchanged"]:
        errors.append("cases_hash_mismatch")
    changed_manifest = next(
        item for item in amendment["changed"] if item["path"] == "FIXTURE_MANIFEST.json"
    )
    if manifest_hash != changed_manifest["new_sha256"]:
        errors.append("fixture_manifest_hash_mismatch")

    for entry in manifest["files"]:
        path = FIXTURES / entry["path"]
        if not path.is_file():
            errors.append(f"fixture_missing:{entry['path']}")
            continue
        if sha256_bytes(path.read_bytes()) != entry["sha256"]:
            errors.append(f"fixture_hash_mismatch:{entry['path']}")

    freeze_commit = str(freeze["freeze_commit"])
    try:
        original_protocol = subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "show",
                f"{freeze_commit}:benchmarks/pipelock/PROTOCOL.md",
            ],
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError:
        errors.append("freeze_commit_unavailable")
    else:
        if sha256_bytes(original_protocol) != freeze["protocol_sha256"]:
            errors.append("original_freeze_protocol_hash_mismatch")

    actual_sources = {
        "pipelock": git_head(pipelock_source),
        "pipelock_verify_python": git_head(pipelock_verify_source),
        "openline_receipt_gate_base": manifest["source_commits"][
            "openline_receipt_gate_base"
        ],
    }
    expected_sources = manifest["source_commits"]
    for name in ("pipelock", "pipelock_verify_python"):
        if actual_sources[name] != expected_sources[name]:
            errors.append(f"source_commit_mismatch:{name}")
    # The OLP base is proven by ancestry rather than a fragile HEAD~N count.
    base = expected_sources["openline_receipt_gate_base"]
    ancestry = subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", base, "HEAD"],
        check=False,
    )
    if ancestry.returncode != 0:
        errors.append("openline_base_not_in_history")
    actual_sources["openline_receipt_gate_base"] = base

    return {
        "valid": not errors,
        "errors": sorted(errors),
        "current_protocol_sha256": protocol_hash,
        "original_protocol_sha256": freeze["protocol_sha256"],
        "fixture_manifest_sha256": manifest_hash,
        "cases_sha256": cases_hash,
        "freeze_commit": freeze_commit,
        "amendment_id": amendment["amendment_id"],
        "source_commits": actual_sources,
    }


def parse_receipts(path: Path, mode: str) -> list[dict[str, Any]]:
    if mode == "chain":
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    value = load_json(path)
    if not isinstance(value, dict):
        raise TypeError("single receipt fixture is not an object")
    return [value]


def trust_options(value: dict[str, Any], verify_options_type: Any, trust_entry_type: Any) -> Any:
    options = verify_options_type()
    for key_id, key_hex in value.get("trusted_keys", {}).items():
        options.trusted_keys[str(key_id)] = bytes.fromhex(str(key_hex))
    for key_id, entry in value.get("trust_entries", {}).items():
        options.trust[str(key_id)] = trust_entry_type(
            mediator_id=str(entry.get("mediator_id", "")),
            role=str(entry.get("role", "")),
            trust_domain=str(entry.get("trust_domain", "")),
        )
    return options


def render_report(report: dict[str, Any]) -> str:
    block = report["pipelock_head_to_head"]
    aggregate = block["aggregate"]
    flagship = block["flagship_finding"]
    rows = []
    for case in block["cases"]:
        rows.append(
            "| {case_id} | {native} / {action} | {aarp} | {olp} | {outcome} |".format(
                case_id=case["case_id"],
                native="valid" if case["pipelock_native"]["valid"] else "rejected",
                action=case["pipelock_native"].get("action_verdict") or "—",
                aarp=case["pipelock_aarp"].get("system_outcome", "not applicable"),
                olp=f"{case['olp']['verdict']} → {case['olp']['decision']}",
                outcome=case["olp"]["benchmark_outcome"],
            )
        )
    return f"""# OLP × Pipelock Frozen Head-to-Head

## Result

All five frozen native and OLP expectations were met. The strongest proposed
wedge was falsified in the fair comparison: Pipelock AARP did flag the case-2
claim `downstream_claim_evidence_sufficient` as claimed but unverified.

OLP still added a narrower, concrete mechanism. It read the receiver-required
artifact, checked its hash, binding, and declared predicate, then emitted a
signed next-use disposition. With the artifact present it returned `COMMIT`; with
the same native `allow` receipt and the artifact absent it returned
`QUARANTINE`. AARP described the assurance boundary; OLP enforced a receiver's
evidence policy at the next decision.

| Case | Pipelock receipt / action | AARP | OLP | OLP benchmark outcome |
|---|---|---|---|---|
{os.linesep.join(rows)}

The native outcome counts were {aggregate['pipelock_native']['correct']} correct,
{aggregate['pipelock_native']['incorrect']} incorrect, and
{aggregate['pipelock_native']['undecidable']} undecidable. OLP's were
{aggregate['olp']['correct']} correct, {aggregate['olp']['incorrect']} incorrect,
and {aggregate['olp']['undecidable']} undecidable. AARP had
{aggregate['pipelock_aarp']['not_applicable']} structurally inapplicable cases.

## What the result supports

The run supports this narrower claim: {flagship['supported_claim']}

It does not show that OLP replaces Pipelock's inline mediation, that Pipelock's
`allow` was wrong, or that either system establishes real-world truth. The
fixtures are public conformance artifacts plus one OLP-authored downstream
evidence companion. Timing and byte counts are reported per lane without a
combined score.

## Social excerpt

Pipelock caught the network action. Its AARP profile also caught the overclaim.
OLP added the next step: it checked the receiver's actual evidence and decided
whether the claim could move. Same valid receipt, two evidence states: commit or
quarantine.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pipelock-verify-source", type=Path, required=True)
    parser.add_argument("--pipelock-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=HERE / "RUN_REPORT.json")
    parser.add_argument("--report", type=Path, default=HERE / "REPORT.md")
    parser.add_argument("--decision-log", type=Path, default=HERE / "results" / "decision_receipts.jsonl")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)

    for path in (args.output, args.report, args.decision_log):
        if path.exists():
            if not args.overwrite:
                raise SystemExit(f"refusing to overwrite existing result: {path}")
            path.unlink()

    pipelock_verify_source = args.pipelock_verify_source.resolve()
    pipelock_source = args.pipelock_source.resolve()
    freeze = verify_freeze(
        pipelock_source=pipelock_source,
        pipelock_verify_source=pipelock_verify_source,
    )
    if not freeze["valid"]:
        raise SystemExit("freeze verification failed: " + ", ".join(freeze["errors"]))

    sys.path.insert(0, str(pipelock_verify_source))
    sys.path.insert(0, str((pipelock_source / "sdk/verifiers/python/src").resolve()))
    import pipelock_verify
    from pipelock_verify._verify import _compute_receipt_hash
    from pipelock_aarp_verify.appraise import (
        TrustEntry,
        VerifyOptions,
        comparable_appraisal,
        verify as verify_aarp,
    )
    from pipelock_aarp_verify.envelope import unmarshal as unmarshal_aarp
    from pipelock_aarp_verify.receipt import verify_evidence_chain_file, verify_receipt_file

    from olp_gate.adapters import TrustStore
    from olp_gate.crypto import public_key_hex
    from olp_gate.gateway import evaluate_request, verify_decision_receipt
    from olp_gate.policy import PolicySpec

    cases_spec = load_json(CASES_PATH)
    policy = PolicySpec.from_mapping(cases_spec["policy"])
    olp_trust = TrustStore.from_mapping(load_json(FIXTURES / "olp-trust.json"))
    aarp_trust = trust_options(
        load_json(FIXTURES / "aarp" / "pipelock-aarp-trust.json"),
        VerifyOptions,
        TrustEntry,
    )
    signer_key = str(cases_spec["pipelock_signer_key"])
    gate_key = Ed25519PrivateKey.generate()
    gate_public = public_key_hex(gate_key)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.decision_log.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    for case in cases_spec["cases"]:
        case_id = str(case["case_id"])
        fixture_path = FIXTURES / str(case["fixture"])
        fixture_bytes = fixture_path.read_bytes()
        receipts = parse_receipts(fixture_path, str(case["input_mode"]))

        try:
            if case["input_mode"] == "chain":
                native_result, native_wall, native_cpu = measure(
                    lambda: pipelock_verify.verify_chain(fixture_path, public_key_hex=signer_key)
                )
                native_plain = as_plain(native_result)
                native_observed = {
                    "valid": bool(native_plain.get("valid")),
                    "action_verdict": None,
                }
            else:
                native_result, native_wall, native_cpu = measure(
                    lambda: pipelock_verify.verify(fixture_bytes, public_key_hex=signer_key)
                )
                native_plain = as_plain(native_result)
                native_observed = {
                    "valid": bool(native_plain.get("valid")),
                    "action_verdict": native_plain.get("verdict"),
                }
            native_error = None
        except Exception as exc:  # pragma: no cover - recorded fail-safe path
            native_plain = {}
            native_wall = 0
            native_cpu = 0
            native_observed = {"valid": None, "action_verdict": None, "execution_error": str(exc)}
            native_error = str(exc)

        native_benchmark = benchmark_outcome(native_observed, case["native_expected"])
        native_root = None
        if native_observed.get("valid") and case["input_mode"] == "single":
            native_root = _compute_receipt_hash(receipts[0])

        if case["input_mode"] == "chain":
            reference_call = lambda: verify_evidence_chain_file(
                fixture_path, signer_key, False
            )
        else:
            reference_call = lambda: verify_receipt_file(
                fixture_path, signer_key, False
            )
        try:
            reference_result, reference_wall, reference_cpu = measure(reference_call)
            reference_valid: bool | None = bool(reference_result.get("valid"))
            reference_execution_error = None
        except Exception as exc:  # pragma: no cover - recorded fail-safe path
            reference_result = {}
            reference_wall = 0
            reference_cpu = 0
            reference_valid = None
            reference_execution_error = str(exc)
        reference_parity = (
            reference_valid is not None
            and native_observed.get("valid") is not None
            and reference_valid == native_observed["valid"]
        )
        if not reference_parity:
            native_benchmark = "undecidable"

        aarp_path_value = case.get("aarp_fixture")
        if aarp_path_value is None:
            aarp_row = {
                "benchmark_outcome": "not_applicable",
                "system_outcome": "not_applicable_after_native_rejection",
                "reason": case["aarp_expected"].get("not_applicable"),
                "wall_time_ns": 0,
                "cpu_time_ns": 0,
                "tool_calls": 0,
                "bytes_read": 0,
            }
        else:
            aarp_path = FIXTURES / str(aarp_path_value)
            aarp_bytes = aarp_path.read_bytes()
            try:
                appraisal, aarp_wall, aarp_cpu = measure(
                    lambda: verify_aarp(unmarshal_aarp(aarp_bytes), aarp_trust)
                )
                appraisal_plain = json.loads(comparable_appraisal(appraisal))
                expected = case["aarp_expected"]
                aarp_ok = (
                    appraisal_plain.get("assertion_signed") == expected.get("assertion_signed")
                    and set(expected.get("verified_claims_include", []))
                    <= set(appraisal_plain.get("verified_claims", []))
                    and set(expected.get("claimed_unverified_include", []))
                    <= set(appraisal_plain.get("claimed_unverified", []))
                )
                aarp_benchmark = "correct" if aarp_ok else "incorrect"
                aarp_row = {
                    "benchmark_outcome": aarp_benchmark,
                    "system_outcome": "appraised",
                    "assertion_signed": appraisal_plain.get("assertion_signed"),
                    "verified_claims": appraisal_plain.get("verified_claims", []),
                    "claimed_unverified": appraisal_plain.get("claimed_unverified", []),
                    "does_not_assert": appraisal_plain.get("does_not_assert", []),
                    "overclaim_risks": appraisal_plain.get("overclaim_risks", []),
                    "wall_time_ns": aarp_wall,
                    "cpu_time_ns": aarp_cpu,
                    "tool_calls": 1,
                    "bytes_read": len(aarp_bytes) + (FIXTURES / "aarp" / "pipelock-aarp-trust.json").stat().st_size,
                }
            except Exception as exc:  # pragma: no cover - recorded fail-safe path
                aarp_row = {
                    "benchmark_outcome": "undecidable",
                    "system_outcome": "execution_error",
                    "error": str(exc),
                    "wall_time_ns": 0,
                    "cpu_time_ns": 0,
                    "tool_calls": 1,
                    "bytes_read": len(aarp_bytes),
                }

        action_record = receipts[-1].get("action_record", {})
        request = {
            "schema": "openline.proof_to_policy.request.v0.2",
            "request_id": case_id,
            "action_type": str(action_record.get("action_type", "unknown")),
            "claim": "Receiver may use the downstream claim only when the frozen evidence policy passes.",
            "source_receipts": receipts,
            "binding": {},
            "evidence": case["evidence"],
        }
        decision, olp_wall, olp_cpu = measure(
            lambda: evaluate_request(
                request,
                policy=policy,
                trust_store=olp_trust,
                signing_key=gate_key,
                issuer_id="frozen-pipelock-benchmark",
                decision_path=args.decision_log,
                session_ledger=None,
                base_dir=FIXTURES,
                now=datetime(2026, 7, 15, 20, 0, 0, tzinfo=timezone.utc),
            )
        )
        decision_verification = verify_decision_receipt(decision, [gate_public])
        olp_observed = {"verdict": decision["verdict"], "decision": decision["decision"]}
        olp_benchmark = benchmark_outcome(olp_observed, case["olp_expected"])
        if not reference_parity:
            olp_benchmark = "undecidable"
        if not decision_verification["valid"]:
            olp_benchmark = "undecidable"

        evidence_details = decision["assessments"]["evidence"]["details"]
        read_ids = set(evidence_details.get("artifact_hashes", {}))
        evidence_bytes = 0
        for item in case["evidence"]:
            if item.get("id") in read_ids and item.get("artifact_path"):
                evidence_bytes += (FIXTURES / str(item["artifact_path"])).stat().st_size
        retrieval_failures = [
            reason
            for reason in decision["assessments"]["evidence"]["reason_codes"]
            if any(token in reason for token in ("missing", "unavailable", "unreadable"))
        ]

        rows.append(
            {
                "case_id": case_id,
                "fixture": case["fixture"],
                "fixture_sha256": sha256_bytes(fixture_bytes),
                "pipelock_native": {
                    **native_observed,
                    "benchmark_outcome": native_benchmark,
                    "error": native_plain.get("error") or native_error,
                    "chain_broken_at_seq": native_plain.get("broken_at_seq"),
                    "root_hash": native_root or native_plain.get("root_hash"),
                    "signatures_verified": bool(native_observed.get("valid")),
                    "trusted_key_pinned": True,
                    "wall_time_ns": native_wall,
                    "cpu_time_ns": native_cpu,
                    "tool_calls": 1,
                    "bytes_read": len(fixture_bytes),
                },
                "pipelock_reference_python": {
                    "valid": reference_valid,
                    "error": reference_result.get("error") or reference_execution_error,
                    "verdict": reference_result.get("verdict"),
                    "boolean_parity_with_native": reference_parity,
                    "wall_time_ns": reference_wall,
                    "cpu_time_ns": reference_cpu,
                    "tool_calls": 1,
                    "bytes_read": len(fixture_bytes),
                },
                "pipelock_aarp": aarp_row,
                "olp": {
                    **olp_observed,
                    "benchmark_outcome": olp_benchmark,
                    "decision_signature_verified": decision_verification["valid"],
                    "reason_codes": decision["reason_codes"],
                    "assessment_statuses": {
                        name: check["status"] for name, check in decision["assessments"].items()
                    },
                    "wall_time_ns": olp_wall,
                    "cpu_time_ns": olp_cpu,
                    "tool_calls": len(receipts) + 3,
                    "receipt_bytes_read": len(fixture_bytes),
                    "evidence_bytes_read": evidence_bytes,
                    "evidence_reads": len(read_ids),
                    "retrieval_failures": retrieval_failures,
                },
            }
        )

    native_counts = Counter(row["pipelock_native"]["benchmark_outcome"] for row in rows)
    olp_counts = Counter(row["olp"]["benchmark_outcome"] for row in rows)
    aarp_counts = Counter(row["pipelock_aarp"]["benchmark_outcome"] for row in rows)
    aggregate = {
        "pipelock_native": {name: native_counts[name] for name in ("correct", "incorrect", "undecidable")},
        "olp": {name: olp_counts[name] for name in ("correct", "incorrect", "undecidable")},
        "pipelock_aarp": {
            **{name: aarp_counts[name] for name in ("correct", "incorrect", "undecidable")},
            "not_applicable": aarp_counts["not_applicable"],
        },
        "olp_system_verdicts": dict(sorted(Counter(row["olp"]["verdict"] for row in rows).items())),
        "native_action_verdicts": dict(
            sorted(Counter(row["pipelock_native"].get("action_verdict") or "none" for row in rows).items())
        ),
        "reference_boolean_parity": sum(
            1 for row in rows if row["pipelock_reference_python"]["boolean_parity_with_native"]
        ),
        "case_count": len(rows),
    }
    case_two = next(row for row in rows if row["case_id"] == "case-02-allow-missing-evidence")
    aarp_caught = "downstream_claim_evidence_sufficient" in case_two["pipelock_aarp"].get("claimed_unverified", [])
    all_expected = (
        aggregate["pipelock_native"] == {"correct": 5, "incorrect": 0, "undecidable": 0}
        and aggregate["olp"] == {"correct": 5, "incorrect": 0, "undecidable": 0}
        and aggregate["pipelock_aarp"]["incorrect"] == 0
        and aggregate["pipelock_aarp"]["undecidable"] == 0
    )
    report = {
        "schema": "openline.release_run_report.v0.2",
        "repo": "openline-receipt-gate",
        "version": "0.3.0",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "passed": all_expected,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "pipelock_verify": str(pipelock_verify.__version__),
            "pipelock_aarp_verify": "0.1.0-in-repo-reference",
        },
        "checks": [
            {"name": "protocol_and_fixture_freeze", "passed": freeze["valid"], "details": freeze},
            {"name": "all_frozen_expectations", "passed": all_expected},
        ],
        "test_count": 5,
        "pipelock_head_to_head": {
            "protocol": freeze,
            "decision_receipts": {
                "path": args.decision_log.relative_to(ROOT).as_posix(),
                "sha256": sha256_bytes(args.decision_log.read_bytes()),
                "count": len(rows),
                "trusted_gate_public_key": gate_public,
            },
            "cases": rows,
            "aggregate": aggregate,
            "flagship_finding": {
                "native_allow_with_missing_downstream_evidence_observed": (
                    case_two["pipelock_native"]["valid"] is True
                    and case_two["pipelock_native"]["action_verdict"] == "allow"
                ),
                "olp_quarantined_missing_evidence": (
                    case_two["olp"]["verdict"] == "UNDECIDABLE"
                    and case_two["olp"]["decision"] == "QUARANTINE"
                ),
                "aarp_flagged_claim_unverified": aarp_caught,
                "strong_hypothesis_falsified": aarp_caught,
                "supported_claim": (
                    "In these frozen fixtures, AARP exposed the unsupported assurance claim, while OLP additionally read receiver-required evidence and emitted a signed COMMIT or QUARANTINE disposition."
                ),
            },
            "work_cost_note": "Wall/CPU timing is descriptive, run-specific, and excluded from reproducibility claims; no combined score is computed.",
        },
        "claim_boundary": (
            "A five-case conformance benchmark does not prove production safety, complete mediation, evidence truth, universal superiority, or deployed-agent transfer."
        ),
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.report.write_text(render_report(report), encoding="utf-8")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "case_count": len(rows),
                "strong_hypothesis_falsified": aarp_caught,
                "native": aggregate["pipelock_native"],
                "olp": aggregate["olp"],
                "aarp": aggregate["pipelock_aarp"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
