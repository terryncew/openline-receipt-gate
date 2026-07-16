#!/usr/bin/env python3
"""Offline consistency verifier for the frozen OLP x Assay benchmark."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks" / "assay"
FIXTURES = BENCH / "fixtures"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_child(root: Path, value: Any) -> Path | None:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        return None
    candidate = (root / value).resolve()
    return candidate if candidate.is_relative_to(root.resolve()) else None


def freeze_proof(freeze: Mapping[str, Any]) -> dict[str, Any]:
    expected = str(freeze.get("protocol_sha256", ""))
    snapshot = BENCH / "PROTOCOL-FROZEN-v0.4.0.md"
    snapshot_hash = digest(snapshot) if snapshot.is_file() else None
    errors: list[str] = []
    if snapshot_hash != expected:
        errors.append("embedded_frozen_protocol_hash_mismatch")
    commit = str(freeze.get("freeze_commit", ""))
    try:
        shown = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{commit}:benchmarks/assay/PROTOCOL.md"],
            check=False,
            capture_output=True,
        )
    except OSError:
        shown = None
    reachable = shown is not None and shown.returncode == 0
    commit_hash = digest_bytes(shown.stdout) if reachable and shown is not None else None
    if reachable and commit_hash != expected:
        errors.append("freeze_commit_protocol_hash_mismatch")
    if not reachable and snapshot_hash != expected:
        errors.append("freeze_proof_unavailable")
    return {
        "valid": not errors,
        "errors": errors,
        "mode": "git_commit" if reachable else "embedded_snapshot",
        "freeze_commit": commit,
        "freeze_commit_reachable": reachable,
        "commit_protocol_sha256": commit_hash,
        "embedded_protocol_sha256": snapshot_hash,
        "temporal_limit": (
            "A reachable Git commit establishes ancestry. The embedded snapshot proves exact "
            "bytes but does not independently timestamp the freeze."
        ),
    }


def verify_dsse(envelope: Mapping[str, Any], public_hex: str) -> tuple[bool, dict[str, Any] | None, str | None]:
    try:
        payload_type = str(envelope["payloadType"])
        payload = base64.b64decode(str(envelope["payload"]), validate=True)
        statement = json.loads(payload)
        signatures = envelope["signatures"]
        if not isinstance(signatures, list) or len(signatures) != 1:
            return False, None, "attestation_signature_count_invalid"
        signature = base64.b64decode(str(signatures[0]["sig"]), validate=True)
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
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(signature, pae)
    except (
        InvalidSignature,
        KeyError,
        IndexError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        return False, None, f"attestation_invalid:{type(exc).__name__}"
    return True, statement if isinstance(statement, dict) else None, None


def main() -> int:
    errors: list[str] = []
    try:
        freeze = load_json(BENCH / "FREEZE.json")
        amendment = load_json(BENCH / "AMENDMENT-001.json")
        amendment_2 = load_json(BENCH / "AMENDMENT-002.json")
        manifest = load_json(BENCH / "FIXTURE_MANIFEST.json")
        cases_spec = load_json(BENCH / "CASES.json")
        report = load_json(BENCH / "RUN_REPORT.json")
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "errors": [f"artifact_unreadable:{exc}"]}, indent=2))
        return 2

    protocol_hash = digest(BENCH / "PROTOCOL.md")
    recorded_hash = (BENCH / "PROTOCOL.sha256").read_text(encoding="ascii").split()[0]
    cases_hash = digest(BENCH / "CASES.json")
    manifest_hash = digest(BENCH / "FIXTURE_MANIFEST.json")
    if protocol_hash != recorded_hash or protocol_hash != freeze.get("protocol_sha256"):
        errors.append("protocol_hash_mismatch")
    if cases_hash != freeze.get("cases_sha256"):
        errors.append("cases_hash_mismatch")
    if manifest_hash != freeze.get("fixture_manifest_sha256"):
        errors.append("fixture_manifest_hash_mismatch")
    proof = freeze_proof(freeze)
    errors.extend(proof["errors"])

    if amendment.get("scored_run_had_started") is not True:
        errors.append("amendment_did_not_disclose_partial_scoring")
    for name in (
        "cases_changed",
        "commands_changed",
        "expected_outcomes_changed",
        "fixtures_changed",
        "results_changed",
        "scoring_rule_changed",
        "source_pins_changed",
    ):
        if amendment.get(name) is not False:
            errors.append(f"amendment_scope_invalid:{name}")
    change = amendment.get("implementation_change", {})
    changes_2 = {
        item.get("path"): item
        for item in amendment_2.get("implementation_changes", [])
        if isinstance(item, dict)
    }
    runner_change_2 = changes_2.get("benchmarks/assay/run_head_to_head.py", {})
    adapter_change_2 = changes_2.get("olp_gate/adapters_assay.py", {})
    if change.get("new_sha256") != runner_change_2.get("old_sha256"):
        errors.append("amendment_runner_chain_mismatch")
    if digest(BENCH / "run_head_to_head.py") != runner_change_2.get("new_sha256"):
        errors.append("current_amended_runner_hash_mismatch")
    if digest(ROOT / "olp_gate" / "adapters_assay.py") != adapter_change_2.get("new_sha256"):
        errors.append("current_amended_adapter_hash_mismatch")
    for name in (
        "cases_changed",
        "commands_changed",
        "expected_outcomes_changed",
        "fixtures_changed",
        "scoring_rule_changed",
        "source_pins_changed",
    ):
        if amendment_2.get(name) is not False:
            errors.append(f"amendment_2_scope_invalid:{name}")
    if amendment_2.get("results_changed") is not True:
        errors.append("amendment_2_result_change_not_disclosed")
    try:
        old_runner = subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "show",
                f"{freeze['freeze_commit']}:benchmarks/assay/run_head_to_head.py",
            ],
            check=False,
            capture_output=True,
        )
    except OSError:
        old_runner = None
    if old_runner is not None and old_runner.returncode == 0:
        if digest_bytes(old_runner.stdout) != change.get("old_sha256"):
            errors.append("pre_amendment_runner_hash_mismatch")
    try:
        frozen_adapter = subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "show",
                f"{freeze['freeze_commit']}:olp_gate/adapters_assay.py",
            ],
            check=False,
            capture_output=True,
        )
    except OSError:
        frozen_adapter = None
    if frozen_adapter is not None and frozen_adapter.returncode == 0:
        if digest_bytes(frozen_adapter.stdout) != adapter_change_2.get("old_sha256"):
            errors.append("pre_amendment_adapter_hash_mismatch")

    prior = amendment_2.get("preserved_prior_run", {})
    history = BENCH / "history" / "scored-run-001"
    for relative, field in (
        ("RUN_REPORT.json", "run_report_sha256"),
        ("REPORT.md", "report_md_sha256"),
        ("results/decision_receipts.jsonl", "signed_decisions_sha256"),
    ):
        path = history / relative
        if not path.is_file() or digest(path) != prior.get(field):
            errors.append(f"preserved_prior_run_mismatch:{relative}")

    for entry in manifest.get("files", []):
        path = safe_child(FIXTURES, entry.get("path"))
        if path is None or not path.is_file():
            errors.append(f"fixture_missing_or_unsafe:{entry.get('path')}")
            continue
        if digest(path) != entry.get("sha256"):
            errors.append(f"fixture_hash_mismatch:{entry.get('path')}")
        if path.stat().st_size != entry.get("bytes"):
            errors.append(f"fixture_size_mismatch:{entry.get('path')}")

    if report.get("schema") != "openline.release_run_report.v0.2":
        errors.append("report_schema_invalid")
    if report.get("version") != "0.4.0" or report.get("passed") is not True:
        errors.append("report_not_passing_v040")
    assay_runtime = report.get("environment", {}).get("assay", {})
    if assay_runtime.get("version") != "assay 3.32.0":
        errors.append("reported_assay_version_invalid")
    if assay_runtime.get("release_archive_sha256") != manifest.get("source_pins", {}).get("assay", {}).get("release_archive_sha256"):
        errors.append("reported_assay_archive_pin_invalid")
    if assay_runtime.get("binary_sha256") != assay_runtime.get("archive_binary_sha256"):
        errors.append("reported_assay_binary_not_bound_to_archive")

    block = report.get("assay_head_to_head", {})
    if block.get("passed") is not True:
        errors.append("benchmark_block_not_passing")
    aggregate = block.get("aggregate", {})
    expected_counts = {"correct": 5, "incorrect": 0, "undecidable": 0}
    for lane in ("assay_native", "assay_trust_basis", "olp"):
        if aggregate.get(lane) != expected_counts:
            errors.append(f"aggregate_mismatch:{lane}")
    protocol = block.get("protocol", {})
    if protocol.get("valid") is not True:
        errors.append("reported_protocol_invalid")
    for field, value in (
        ("protocol_sha256", protocol_hash),
        ("cases_sha256", cases_hash),
        ("fixture_manifest_sha256", manifest_hash),
        ("freeze_commit", freeze.get("freeze_commit")),
    ):
        if protocol.get(field) != value:
            errors.append(f"reported_protocol_field_mismatch:{field}")
    regeneration = block.get("fixture_regeneration", {})
    if (
        regeneration.get("valid") is not True
        or regeneration.get("byte_identical_to_frozen_fixture") is not True
        or regeneration.get("actual_sha256")
        != manifest.get("files", [])[0].get("sha256")
    ):
        errors.append("upstream_fixture_regeneration_not_proven")

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
            errors.append(f"case_missing:{case_id}")
            continue
        native = row.get("assay_native", {})
        trust = row.get("assay_trust_basis", {})
        olp = row.get("olp", {})
        if native.get("valid") is not case.get("assay_native_valid"):
            errors.append(f"native_expectation_mismatch:{case_id}")
        if trust.get("status") != case.get("assay_trust_assertion"):
            errors.append(f"trust_basis_expectation_mismatch:{case_id}")
        if olp.get("verdict") != case.get("expected_olp_verdict"):
            errors.append(f"olp_verdict_mismatch:{case_id}")
        if olp.get("decision") != case.get("expected_olp_decision"):
            errors.append(f"olp_decision_mismatch:{case_id}")
        if olp.get("signature_valid") is not True or olp.get("mechanism_observed") is not True:
            errors.append(f"olp_receipt_or_mechanism_invalid:{case_id}")
        for lane_name, lane in (
            ("native", native),
            ("trust_basis", trust),
            ("olp", olp),
        ):
            if lane.get("benchmark_outcome") != "correct":
                errors.append(f"lane_not_correct:{case_id}:{lane_name}")

    case_one = rows_by_id.get("case-01-clean-with-receiver-evidence", {})
    case_two = rows_by_id.get("case-02-receiver-evidence-missing", {})
    if case_one.get("source_archive_sha256") != case_two.get("source_archive_sha256"):
        errors.append("receiver_comparison_source_changed")
    if case_one.get("olp", {}).get("assessment_statuses", {}).get("evidence") != "pass":
        errors.append("clean_receiver_evidence_not_passed")
    if case_two.get("olp", {}).get("assessment_statuses", {}).get("evidence") != "unavailable":
        errors.append("missing_receiver_evidence_not_undecidable")
    case_four = rows_by_id.get("case-04-assay-registered-claim-missing", {})
    if (
        case_four.get("assay_trust_basis", {}).get("status") != "fail"
        or "source_signal:assay_trust_basis_requirement_failed"
        not in case_four.get("olp", {}).get("reason_codes", [])
    ):
        errors.append("assay_failed_claim_was_laundered")

    capability = block.get("capability_control", {})
    if (
        capability.get("passed") is not True
        or capability.get("assay_signed_caller_supplied_receiver_predicate") is not True
        or capability.get("strong_signing_uniqueness_hypothesis_falsified") is not True
    ):
        errors.append("assay_signing_capability_not_preserved")
    if block.get("finding", {}).get("strong_signing_uniqueness_hypothesis_falsified") is not True:
        errors.append("strong_hypothesis_not_marked_falsified")
    attestation_path = safe_child(ROOT, capability.get("attestation_path"))
    if attestation_path is None or not attestation_path.is_file():
        errors.append("attestation_missing_or_unsafe")
    else:
        if digest(attestation_path) != capability.get("attestation_sha256"):
            errors.append("attestation_hash_mismatch")
        envelope = load_json(attestation_path)
        valid_dsse, statement, dsse_error = verify_dsse(
            envelope, str(capability.get("public_key", ""))
        )
        if not valid_dsse:
            errors.append(dsse_error or "attestation_invalid")
        elif statement is None:
            errors.append("attestation_statement_invalid")
        else:
            if statement.get("predicate") != load_json(FIXTURES / "receiver-predicate.json"):
                errors.append("attestation_predicate_mismatch")
            if statement.get("predicate") != capability.get("predicate"):
                errors.append("reported_attestation_predicate_mismatch")

    decisions_meta = block.get("decision_receipts", {})
    decisions_path = safe_child(ROOT, decisions_meta.get("path"))
    public_key = decisions_meta.get("trusted_gate_public_key")
    if not isinstance(public_key, str) or re.fullmatch(r"[0-9a-f]{64}", public_key) is None:
        errors.append("decision_gate_key_invalid")
    if decisions_path is None or not decisions_path.is_file():
        errors.append("decision_log_missing_or_unsafe")
    else:
        if digest(decisions_path) != decisions_meta.get("sha256"):
            errors.append("decision_log_hash_mismatch")
        try:
            decisions = [
                json.loads(line)
                for line in decisions_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except json.JSONDecodeError:
            decisions = []
            errors.append("decision_log_invalid_json")
        if len(decisions) != 5 or decisions_meta.get("count") != 5:
            errors.append("decision_log_count_mismatch")
        if isinstance(public_key, str):
            from olp_gate.gateway import verify_decision_receipt

            for index, decision in enumerate(decisions):
                verified = verify_decision_receipt(decision, [public_key])
                if verified.get("valid") is not True:
                    errors.append(f"decision_receipt_invalid:{index}")
                integrity_details = (
                    decision.get("assessments", {})
                    .get("integrity", {})
                    .get("details", {})
                )
                if integrity_details.get("native_diagnostic_stored") is not False:
                    errors.append(f"native_diagnostic_storage_flag_invalid:{index}")
                if "native_stdout" in integrity_details or "native_stderr" in integrity_details:
                    errors.append(f"native_diagnostic_disclosed:{index}")

    for result_path in (attestation_path, decisions_path):
        if result_path is not None and result_path.is_file():
            if b"PRIVATE KEY" in result_path.read_bytes():
                errors.append(f"private_key_material_present:{result_path.name}")

    result = {
        "valid": not errors,
        "schema": report.get("schema"),
        "version": report.get("version"),
        "case_count": len(rows),
        "aggregate": aggregate,
        "strong_signing_uniqueness_hypothesis_falsified": capability.get(
            "strong_signing_uniqueness_hypothesis_falsified"
        ),
        "freeze_proof": proof,
        "errors": sorted(set(errors)),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
