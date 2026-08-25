"""Verified foreign governance evidence -> source-neutral OpenLine support.

This module deliberately separates three jobs:

1. source-specific authenticity/integrity verification;
2. representation-only normalization;
3. downstream OpenLine standing and gate decisions.

The source verifiers may understand ACS or AIREP wire details. The normalized
support receipt may not carry source identity or source-specific verdict
vocabulary. OpenLine standing therefore cannot branch on the foreign producer.

This is an interoperability surface, not an authority oracle. A valid foreign
artifact proves only the verified assertions extracted from that artifact.
Receiver policy still decides whether those assertions are sufficient.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .crypto import (
    jcs_integer_canonical_json,
    public_key_hex,
    sha256_hex,
    sign_olp_body,
    verify_olp_signature,
)


NORMALIZED_FOREIGN_EVIDENCE_SCHEMA = "openline.foreign_verified_support.v1"
FOREIGN_VERIFICATION_RECEIPT_SCHEMA = "openline.foreign_verification_receipt.v1"
ACS_TEST_ARTIFACT_SCHEMA = "openline.foreign_standing_001.acs_offline_artifact.v1"
AIREP_INTEROP_PROFILE = "openline_foreign_standing_001"

_AIREP_TOP = {
    "airep_version",
    "subject",
    "input",
    "claim",
    "output",
    "evidence",
    "directive",
    "scope",
    "integrity",
    "profiles",
}
_AIREP_REQUIRED = _AIREP_TOP - {"profiles"}
_AIREP_VERBS = {"release", "block", "defer", "redact", "escalate_to_human", "kill"}
_HEX = frozenset("0123456789abcdef")


class ForeignEvidenceError(ValueError):
    """Raised when foreign evidence cannot be verified or safely normalized."""


@dataclass(frozen=True)
class VerifiedForeignEvidence:
    """Source-verifier output before source identity is erased by normalization."""

    source_kind: str
    source_artifact_hash: str
    source_outcome: str
    action_hash: str
    evidence_key: str
    assertion: str
    coverage: tuple[str, ...]
    policy_basis: tuple[str, ...]
    verified_at: str


@dataclass(frozen=True)
class NormalizedForeignEvidence:
    """Common support plus a separate audit-only source verification receipt."""

    support_receipt: Mapping[str, Any]
    verification_receipt: Mapping[str, Any]


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ForeignEvidenceError("foreign_verification_time_timezone_required")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _copy(value: Any) -> Any:
    try:
        return json.loads(
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        )
    except (TypeError, ValueError) as exc:
        raise ForeignEvidenceError("foreign_json_invalid") from exc


def _hash_hex(value: Any) -> str:
    return sha256_hex(jcs_integer_canonical_json(_copy(value)))


def _require_hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in _HEX for ch in value.lower()):
        raise ForeignEvidenceError(f"{name}_invalid")
    return value.lower()


def _normalize_strings(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ForeignEvidenceError(f"{name}_invalid")
    items = tuple(sorted({str(item) for item in value if isinstance(item, str) and item}))
    if not items:
        raise ForeignEvidenceError(f"{name}_empty")
    return items


def _semantic_fields(value: Mapping[str, Any]) -> tuple[str, str, str, tuple[str, ...], tuple[str, ...]]:
    try:
        action_hash = _require_hash(value["action_hash"], "foreign_action_hash")
        evidence_key = str(value["evidence_key"])
        assertion = str(value["assertion"])
        coverage = _normalize_strings(value["coverage"], "foreign_coverage")
        policy_basis = _normalize_strings(value["policy_basis"], "foreign_policy_basis")
    except KeyError as exc:
        raise ForeignEvidenceError(f"foreign_semantic_field_missing:{exc.args[0]}") from exc
    if not evidence_key:
        raise ForeignEvidenceError("foreign_evidence_key_invalid")
    if not assertion:
        raise ForeignEvidenceError("foreign_assertion_invalid")
    return action_hash, evidence_key, assertion, coverage, policy_basis


def verify_acs_offline_evidence(
    verdict: Mapping[str, Any],
    artifact: Mapping[str, Any],
    signature_bundle: Mapping[str, Any],
    *,
    trusted_public_key: str,
    expected_action_hash: str | None = None,
    now: datetime | None = None,
) -> VerifiedForeignEvidence:
    """Verify ACS-referenced offline evidence before OpenLine normalization.

    ACS itself treats ``verdict.evidence`` as opaque. This verifier therefore
    requires a separately supplied offline artifact and an AGT-style Ed25519
    artifact-signature bundle. The artifact payload used by this benchmark is an
    OpenLine interop fixture, not a Microsoft-defined evidence payload schema.
    """
    if not isinstance(verdict, Mapping) or verdict.get("decision") not in {"allow", "warn", "transform"}:
        raise ForeignEvidenceError("acs_verdict_not_proceeding")
    evidence = verdict.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ForeignEvidenceError("acs_evidence_object_missing")
    pointer = evidence.get("artefact")
    if not isinstance(pointer, str) or not pointer.startswith("sha256:"):
        raise ForeignEvidenceError("acs_evidence_artefact_pointer_invalid")

    if not isinstance(artifact, Mapping) or artifact.get("schema") != ACS_TEST_ARTIFACT_SCHEMA:
        raise ForeignEvidenceError("acs_offline_artifact_schema_invalid")
    artifact_bytes = jcs_integer_canonical_json(_copy(artifact))
    digest = hashlib.sha256(artifact_bytes).hexdigest()
    if pointer != f"sha256:{digest}":
        raise ForeignEvidenceError("acs_evidence_pointer_hash_mismatch")

    if not isinstance(signature_bundle, Mapping):
        raise ForeignEvidenceError("acs_signature_bundle_invalid")
    bundle_hash = _require_hash(signature_bundle.get("artifact_hash"), "acs_artifact_hash")
    if bundle_hash != digest:
        raise ForeignEvidenceError("acs_signature_bundle_hash_mismatch")
    observed_key = str(signature_bundle.get("public_key", "")).lower()
    expected_key = _require_hash(trusted_public_key, "acs_trusted_public_key")
    if observed_key != expected_key:
        raise ForeignEvidenceError("acs_signer_key_untrusted")
    signature_hex = str(signature_bundle.get("signature", ""))
    try:
        signature = bytes.fromhex(signature_hex)
        key_bytes = bytes.fromhex(expected_key)
        if len(signature) != 64 or len(key_bytes) != 32:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature, artifact_bytes)
    except (ValueError, InvalidSignature) as exc:
        raise ForeignEvidenceError("acs_artifact_signature_invalid") from exc

    action_hash, evidence_key, assertion, coverage, policy_basis = _semantic_fields(artifact)
    if expected_action_hash is not None and action_hash != expected_action_hash:
        raise ForeignEvidenceError("acs_action_binding_mismatch")

    check_time = now or _now()
    return VerifiedForeignEvidence(
        source_kind="ACS",
        source_artifact_hash=digest,
        source_outcome=str(verdict["decision"]),
        action_hash=action_hash,
        evidence_key=evidence_key,
        assertion=assertion,
        coverage=coverage,
        policy_basis=policy_basis,
        verified_at=_iso(check_time),
    )


def _airep_hash_body(record: Mapping[str, Any]) -> bytes:
    body = _copy(record)
    integrity = body.get("integrity")
    if not isinstance(integrity, dict):
        raise ForeignEvidenceError("airep_integrity_invalid")
    integrity.pop("current", None)
    integrity.pop("signature", None)
    return jcs_integer_canonical_json(body)


def verify_airep_record(
    record: Mapping[str, Any],
    *,
    trusted_public_key: str,
    expected_action_hash: str | None = None,
    now: datetime | None = None,
) -> VerifiedForeignEvidence:
    """Verify the AIREP v0.1 subset needed by FOREIGN-STANDING-001.

    The fixture remains inside AIREP's core constraints and carries exact-action
    interop semantics only under a namespaced profile. This verifier is not a
    replacement for AIREP's published full conformance kit.
    """
    if not isinstance(record, Mapping):
        raise ForeignEvidenceError("airep_record_invalid")
    item = _copy(record)
    keys = set(item)
    if not _AIREP_REQUIRED <= keys or not keys <= _AIREP_TOP:
        raise ForeignEvidenceError("airep_top_level_shape_invalid")
    if item.get("airep_version") != "0.1":
        raise ForeignEvidenceError("airep_version_invalid")

    directive = item.get("directive")
    if not isinstance(directive, Mapping) or directive.get("verb") not in _AIREP_VERBS:
        raise ForeignEvidenceError("airep_directive_invalid")
    if directive.get("verb") != "release":
        raise ForeignEvidenceError("airep_record_not_proceeding")

    evidence = item.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ForeignEvidenceError("airep_evidence_empty")
    # AIREP v0.1 explicitly forbids treating resolvable:false as verified evidence.
    if not any(isinstance(entry, Mapping) and entry.get("resolvable") is True for entry in evidence):
        raise ForeignEvidenceError("airep_no_resolvable_verified_evidence")

    scope = item.get("scope")
    if not isinstance(scope, Mapping):
        raise ForeignEvidenceError("airep_scope_invalid")
    if not isinstance(scope.get("covers"), list) or not isinstance(scope.get("does_not_cover"), list):
        raise ForeignEvidenceError("airep_scope_shape_invalid")

    integrity = item.get("integrity")
    if not isinstance(integrity, Mapping) or integrity.get("canonical_json") is not True:
        raise ForeignEvidenceError("airep_integrity_canonicalization_invalid")
    previous = integrity.get("previous")
    if previous != "sha256:" + "0" * 64:
        raise ForeignEvidenceError("airep_genesis_chain_invalid")
    expected_current = "sha256:" + sha256_hex(_airep_hash_body(item))
    if integrity.get("current") != expected_current:
        raise ForeignEvidenceError("airep_current_hash_mismatch")
    signature = integrity.get("signature")
    if not isinstance(signature, Mapping) or signature.get("alg") != "Ed25519":
        raise ForeignEvidenceError("airep_signature_algorithm_invalid")
    expected_key = _require_hash(trusted_public_key, "airep_trusted_public_key")
    try:
        sig_bytes = bytes.fromhex(str(signature.get("value", "")))
        key_bytes = bytes.fromhex(expected_key)
        if len(sig_bytes) != 64 or len(key_bytes) != 32:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(
            sig_bytes, str(expected_current).encode("utf-8")
        )
    except (ValueError, InvalidSignature) as exc:
        raise ForeignEvidenceError("airep_signature_invalid") from exc

    profiles = item.get("profiles")
    if not isinstance(profiles, Mapping):
        raise ForeignEvidenceError("airep_interop_profile_missing")
    profile = profiles.get(AIREP_INTEROP_PROFILE)
    if not isinstance(profile, Mapping):
        raise ForeignEvidenceError("airep_interop_profile_missing")
    action_hash, evidence_key, assertion, coverage, policy_basis = _semantic_fields(profile)
    if expected_action_hash is not None and action_hash != expected_action_hash:
        raise ForeignEvidenceError("airep_action_binding_mismatch")
    if not set(coverage) <= {str(value) for value in scope.get("covers", [])}:
        raise ForeignEvidenceError("airep_scope_does_not_cover_normalized_claim")

    check_time = now or _now()
    return VerifiedForeignEvidence(
        source_kind="AIREP",
        source_artifact_hash=expected_current.removeprefix("sha256:"),
        source_outcome=str(directive["verb"]),
        action_hash=action_hash,
        evidence_key=evidence_key,
        assertion=assertion,
        coverage=coverage,
        policy_basis=policy_basis,
        verified_at=_iso(check_time),
    )


def normalize_verified_evidence(
    verified: VerifiedForeignEvidence,
    *,
    receiver_key: Ed25519PrivateKey,
    normalized_at: datetime | None = None,
) -> NormalizedForeignEvidence:
    """Erase source identity from the support object after successful verification.

    Source provenance is retained in a separate signed verification receipt. The
    support receipt consumed by standing contains no ACS/AIREP discriminator and
    is byte-identical for semantically equivalent verified inputs when the same
    receiver key and normalization time are used.
    """
    if not isinstance(verified, VerifiedForeignEvidence):
        raise ForeignEvidenceError("foreign_verified_input_required")
    when = normalized_at or _now()
    common_body = {
        "schema": NORMALIZED_FOREIGN_EVIDENCE_SCHEMA,
        "action_hash": verified.action_hash,
        "evidence_key": verified.evidence_key,
        "assertion": verified.assertion,
        "coverage": list(verified.coverage),
        "policy_basis": list(verified.policy_basis),
        "receiver_verification_status": "VERIFIED",
        "normalized_at": _iso(when),
    }
    support = sign_olp_body(common_body, receiver_key)
    audit = sign_olp_body(
        {
            "schema": FOREIGN_VERIFICATION_RECEIPT_SCHEMA,
            "source_kind": verified.source_kind,
            "source_artifact_hash": verified.source_artifact_hash,
            "source_outcome": verified.source_outcome,
            "normalized_support_hash": _hash_hex(support),
            "verified_at": verified.verified_at,
            "normalized_at": _iso(when),
        },
        receiver_key,
    )
    return NormalizedForeignEvidence(support_receipt=support, verification_receipt=audit)


def verify_normalized_support(
    support: Mapping[str, Any],
    *,
    trusted_receiver_key: str,
    expected_action_hash: str | None = None,
) -> dict[str, Any]:
    """Verify the common support object without any knowledge of its source format."""
    if not isinstance(support, Mapping) or support.get("schema") != NORMALIZED_FOREIGN_EVIDENCE_SCHEMA:
        raise ForeignEvidenceError("normalized_support_schema_invalid")
    valid, reason = verify_olp_signature(support)
    if valid is not True:
        raise ForeignEvidenceError(f"normalized_support_signature_invalid:{reason or 'unknown'}")
    signature = support.get("signature")
    if not isinstance(signature, Mapping):
        raise ForeignEvidenceError("normalized_support_signature_shape_invalid")
    expected_key = _require_hash(trusted_receiver_key, "normalized_receiver_key")
    if str(signature.get("public_key", "")).lower() != expected_key:
        raise ForeignEvidenceError("normalized_support_receiver_key_mismatch")
    action_hash = _require_hash(support.get("action_hash"), "normalized_action_hash")
    if expected_action_hash is not None and action_hash != expected_action_hash:
        raise ForeignEvidenceError("normalized_support_action_mismatch")
    if support.get("receiver_verification_status") != "VERIFIED":
        raise ForeignEvidenceError("normalized_support_not_verified")
    return _copy(dict(support))


__all__ = [
    "ACS_TEST_ARTIFACT_SCHEMA",
    "AIREP_INTEROP_PROFILE",
    "FOREIGN_VERIFICATION_RECEIPT_SCHEMA",
    "NORMALIZED_FOREIGN_EVIDENCE_SCHEMA",
    "ForeignEvidenceError",
    "NormalizedForeignEvidence",
    "VerifiedForeignEvidence",
    "normalize_verified_evidence",
    "verify_acs_offline_evidence",
    "verify_airep_record",
    "verify_normalized_support",
]
