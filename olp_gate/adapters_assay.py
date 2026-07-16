"""Assay Evidence Contract v1 bundle adapter.

The adapter deliberately delegates bundle verification and Trust Basis
compilation to the pinned Assay CLI.  It preserves the source archive as an
opaque artifact and records its byte hash; it does not reimplement Assay's tar,
JCS, event, or claim rules.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .adapters import FAIL, PARTIAL, PASS, UNAVAILABLE, Check, SourceAssessment


ASSAY_EVIDENCE_BUNDLE_V1 = "assay_evidence_bundle_v1"
SUPPORTED_ASSAY_VERSION = "3.32.0"
MAX_ASSAY_BUNDLE_BYTES = 100_000_000


class AssayAdapterError(ValueError):
    """A source-bundle reference cannot be evaluated safely."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def find_assay_binary(explicit: str | Path | None = None) -> Path | None:
    """Return an executable Assay CLI path without accepting a request-owned path."""

    if os.environ.get("OLP_TEST_DISABLE_ASSAY") == "1":
        return None
    candidate = str(explicit) if explicit is not None else os.environ.get("OLP_ASSAY_BIN")
    if not candidate:
        candidate = shutil.which("assay")
    if not candidate:
        return None
    path = Path(candidate).expanduser().resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        return None
    return path


def _resolve_bundle(reference: Mapping[str, Any], base_dir: str | Path | None) -> Path:
    if reference.get("format") != ASSAY_EVIDENCE_BUNDLE_V1:
        raise AssayAdapterError("assay_bundle_format_unsupported")
    raw_path = reference.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise AssayAdapterError("assay_bundle_path_missing")
    root = Path(base_dir or ".").resolve()
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise AssayAdapterError("assay_bundle_unavailable") from exc
    if not resolved.is_relative_to(root):
        raise AssayAdapterError("assay_bundle_path_escape")
    if not resolved.is_file():
        raise AssayAdapterError("assay_bundle_unavailable")
    if resolved.stat().st_size > MAX_ASSAY_BUNDLE_BYTES:
        raise AssayAdapterError("assay_bundle_too_large")
    return resolved


def _run(command: Sequence[str | Path], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [str(item) for item in command],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssayAdapterError("assay_verifier_execution_failed") from exc


def _claim_map(trust_basis: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    claims = trust_basis.get("claims")
    if not isinstance(claims, list):
        return {}
    return {
        str(claim.get("id")): dict(claim)
        for claim in claims
        if isinstance(claim, Mapping) and isinstance(claim.get("id"), str)
    }


def _requirements(reference: Mapping[str, Any]) -> list[str]:
    raw = reference.get("trust_basis_requirements", [])
    if not isinstance(raw, list) or not all(isinstance(item, str) and "=" in item for item in raw):
        raise AssayAdapterError("assay_trust_basis_requirements_invalid")
    return list(raw)


def _failure(
    reason: str,
    *,
    source_hash: str | None = None,
    integrity_status: str = UNAVAILABLE,
    details: Mapping[str, Any] | None = None,
) -> SourceAssessment:
    detail = dict(details or {})
    return SourceAssessment(
        source_format=ASSAY_EVIDENCE_BUNDLE_V1,
        receipt_hashes=[source_hash] if source_hash else [],
        primary_hash=source_hash,
        source_key_ids=[],
        source_binding={},
        source_timestamp=None,
        integrity=Check(integrity_status, [reason], detail),
        provenance=Check(UNAVAILABLE, [reason], detail),
        coverage=Check(UNAVAILABLE, [reason], detail),
        profile=Check(UNAVAILABLE, [reason], detail),
        source_signal=Check(UNAVAILABLE, [reason], detail),
    )


def assess_assay_bundle(
    reference: Mapping[str, Any],
    *,
    base_dir: str | Path | None,
    assay_binary: str | Path | None = None,
) -> SourceAssessment:
    """Verify one Assay bundle with the official CLI and map its bounded claims.

    ``trust_basis_requirements`` uses Assay's own exact-level assertion command.
    A failed native assertion is never upgraded by OLP; it becomes a failing
    source signal.  Passing the source signal only makes the bundle eligible as
    an evidence input and never selects ``COMMIT`` by itself.
    """

    try:
        bundle = _resolve_bundle(reference, base_dir)
        requirements = _requirements(reference)
    except AssayAdapterError as exc:
        return _failure(exc.reason_code, integrity_status=FAIL)

    source_bytes = bundle.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    declared_hash = str(reference.get("sha256", "")).removeprefix("sha256:").lower()
    binding_errors: list[str] = []
    if len(declared_hash) != 64 or any(character not in "0123456789abcdef" for character in declared_hash):
        binding_errors.append("assay_bundle_declared_hash_invalid")
    elif declared_hash != source_hash:
        binding_errors.append("assay_bundle_sha256_mismatch")

    binary = find_assay_binary(assay_binary)
    if binary is None:
        return _failure(
            "assay_verifier_unavailable",
            source_hash=source_hash,
            details={"expected_version": SUPPORTED_ASSAY_VERSION},
        )

    version_run = _run([binary, "--version"])
    version_text = version_run.stdout.strip()
    version_ok = version_run.returncode == 0 and version_text == f"assay {SUPPORTED_ASSAY_VERSION}"

    verify_run = _run([binary, "evidence", "verify", bundle])
    native_valid = verify_run.returncode == 0
    integrity_errors = list(binding_errors)
    if not version_ok:
        integrity_errors.append("assay_verifier_version_unsupported")
    if not native_valid:
        integrity_errors.append("assay_bundle_invalid")
    integrity_details = {
        "native_verifier": "assay evidence verify",
        "native_verifier_version": version_text or None,
        "expected_version": SUPPORTED_ASSAY_VERSION,
        "archive_sha256": source_hash,
        "declared_sha256": declared_hash or None,
        "archive_bytes": len(source_bytes),
        "native_returncode": verify_run.returncode,
        "native_diagnostic_stored": False,
        "source_preserved": not binding_errors,
    }
    integrity = (
        Check(FAIL, integrity_errors, integrity_details)
        if integrity_errors
        else Check(PASS, [], integrity_details)
    )
    if not native_valid or not version_ok:
        return SourceAssessment(
            source_format=ASSAY_EVIDENCE_BUNDLE_V1,
            receipt_hashes=[source_hash],
            primary_hash=source_hash,
            source_key_ids=[],
            source_binding={},
            source_timestamp=None,
            integrity=integrity,
            provenance=Check(UNAVAILABLE, ["assay_verified_manifest_unavailable"]),
            coverage=Check(UNAVAILABLE, ["assay_trust_basis_unavailable"]),
            profile=Check(UNAVAILABLE, ["assay_verified_manifest_unavailable"]),
            source_signal=Check(UNAVAILABLE, ["assay_source_signal_untrusted"]),
        )

    with tempfile.TemporaryDirectory(prefix="olp-assay-") as temporary:
        trust_path = Path(temporary) / "trust-basis.json"
        show_run = _run([binary, "evidence", "show", "--format", "json", bundle])
        trust_run = _run(
            [binary, "trust-basis", "generate", bundle, "--out", trust_path]
        )
        try:
            shown = json.loads(show_run.stdout) if show_run.returncode == 0 else {}
            trust_basis = (
                json.loads(trust_path.read_text(encoding="utf-8"))
                if trust_run.returncode == 0 and trust_path.is_file()
                else {}
            )
        except (OSError, json.JSONDecodeError):
            shown = {}
            trust_basis = {}

        assert_report: dict[str, Any] = {
            "schema": "assay.trust-basis.assert.report.v1",
            "summary": {
                "total_requirements": 0,
                "passed_requirements": 0,
                "failed_requirements": 0,
            },
            "requirements": [],
        }
        assert_returncode = 0
        if requirements and trust_basis:
            command: list[str | Path] = [
                binary,
                "trust-basis",
                "assert",
                "--input",
                trust_path,
            ]
            for requirement in requirements:
                command.extend(["--require", requirement])
            command.extend(["--format", "json"])
            assert_run = _run(command)
            assert_returncode = assert_run.returncode
            try:
                parsed = json.loads(assert_run.stdout)
                if isinstance(parsed, Mapping):
                    assert_report = dict(parsed)
            except json.JSONDecodeError:
                assert_report = {
                    "summary": {"total_requirements": len(requirements), "failed_requirements": len(requirements)},
                    "requirements": [],
                    "parse_error": True,
                }

    manifest = shown.get("manifest") if isinstance(shown, Mapping) else None
    events = shown.get("events") if isinstance(shown, Mapping) else None
    manifest = dict(manifest) if isinstance(manifest, Mapping) else {}
    events = list(events) if isinstance(events, list) else []
    claims = _claim_map(trust_basis if isinstance(trust_basis, Mapping) else {})

    profile_errors: list[str] = []
    if show_run.returncode != 0 or not manifest:
        profile_errors.append("assay_manifest_unavailable")
    if trust_run.returncode != 0 or not claims:
        profile_errors.append("assay_trust_basis_unavailable")
    if manifest.get("schema_version") != 1:
        profile_errors.append("assay_manifest_schema_unsupported")
    if manifest.get("bundle_id") != manifest.get("run_root"):
        profile_errors.append("assay_bundle_root_mismatch")
    algorithms = manifest.get("algorithms")
    if not isinstance(algorithms, Mapping) or algorithms.get("canon") != "jcs-rfc8785" or algorithms.get("hash") != "sha256":
        profile_errors.append("assay_algorithms_unsupported")
    if claims.get("bundle_verified", {}).get("level") != "verified":
        profile_errors.append("assay_bundle_verified_claim_missing")

    profile_details = {
        "manifest_schema_version": manifest.get("schema_version"),
        "bundle_id": manifest.get("bundle_id"),
        "run_root": manifest.get("run_root"),
        "event_count": manifest.get("event_count"),
        "trust_basis_claim_levels": {
            claim_id: claim.get("level") for claim_id, claim in sorted(claims.items())
        },
        "raw_events_stored_in_decision": False,
    }
    profile = Check(FAIL, profile_errors, profile_details) if profile_errors else Check(PASS, [], profile_details)

    signing_level = claims.get("signing_evidence_present", {}).get("level")
    if signing_level == "verified":
        provenance = Check(
            PARTIAL,
            ["assay_signing_evidence_present_without_receiver_trust_pin"],
            {"claim_level": signing_level},
        )
    else:
        provenance = Check(
            UNAVAILABLE,
            ["assay_bundle_signing_evidence_absent"],
            {"claim_level": signing_level},
        )

    summary = assert_report.get("summary", {}) if isinstance(assert_report, Mapping) else {}
    failed_requirements = int(summary.get("failed_requirements", len(requirements)) or 0)
    assertion_details = {
        "requirements": requirements,
        "native_assert_returncode": assert_returncode,
        "native_assert_report": assert_report,
        "claim_boundary": "Assay exact-level Trust Basis assertions over its registered claims",
    }
    if profile.status != PASS:
        coverage = Check(UNAVAILABLE, ["assay_trust_basis_unavailable"], assertion_details)
        source_signal = Check(UNAVAILABLE, ["assay_source_signal_untrusted"], assertion_details)
    elif failed_requirements or (requirements and assert_returncode == 0 and not assert_report):
        coverage = Check(FAIL, ["assay_trust_basis_requirement_failed"], assertion_details)
        source_signal = Check(FAIL, ["assay_trust_basis_requirement_failed"], assertion_details)
    elif not requirements:
        coverage = Check(
            PARTIAL,
            ["assay_no_receiver_claim_requirement_declared"],
            assertion_details,
        )
        source_signal = Check(
            PARTIAL,
            ["assay_source_signal_advisory_only"],
            assertion_details,
        )
    else:
        coverage = Check(
            PARTIAL,
            ["assay_registered_claims_satisfied_not_semantic_completeness"],
            assertion_details,
        )
        source_signal = Check(
            PASS,
            [],
            {**assertion_details, "mapping": "eligible_evidence_input_only"},
        )

    timestamps = [
        str(event.get("time"))
        for event in events
        if isinstance(event, Mapping) and isinstance(event.get("time"), str)
    ]
    sequences = [
        int(event.get("assayseq"))
        for event in events
        if isinstance(event, Mapping)
        and isinstance(event.get("assayseq"), int)
        and not isinstance(event.get("assayseq"), bool)
    ]
    source_digests = sorted(
        {
            str(event.get("data", {}).get("source_artifact_digest"))
            for event in events
            if isinstance(event, Mapping)
            and isinstance(event.get("data"), Mapping)
            and isinstance(event.get("data", {}).get("source_artifact_digest"), str)
        }
    )
    return SourceAssessment(
        source_format=ASSAY_EVIDENCE_BUNDLE_V1,
        receipt_hashes=[source_hash],
        primary_hash=source_hash,
        source_key_ids=[],
        source_binding={
            "run_id": manifest.get("run_id"),
            "session_id": None,
            "source_sequence": max(sequences) if sequences else None,
            "action_id": manifest.get("bundle_id"),
            "bundle_id": manifest.get("bundle_id"),
            "source_artifact_digests": source_digests,
        },
        source_timestamp=max(timestamps) if timestamps else None,
        integrity=integrity,
        provenance=provenance,
        coverage=coverage,
        profile=profile,
        source_signal=source_signal,
    )
