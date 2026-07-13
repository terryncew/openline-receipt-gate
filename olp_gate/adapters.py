"""Input adapters and trust assessments for OLP and Agent Receipts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .crypto import (
    jcs_integer_canonical_json,
    olp_canonical_json,
    sha256_hex,
    verify_agent_receipt_signature,
    verify_olp_signature,
)
from .receipts import sha256_json


PASS = "pass"
FAIL = "fail"
PARTIAL = "partial"
UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class KeyRecord:
    public_key: str | None = None
    roles: frozenset[str] = frozenset()
    independence: str = "unspecified"
    controller: str = "unknown"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "KeyRecord":
        roles = value.get("roles", [])
        if not isinstance(roles, (list, tuple, set, frozenset)):
            raise ValueError("trust-store roles must be an array")
        public_key = value.get("public_key")
        if public_key is not None and not isinstance(public_key, str):
            raise ValueError("trust-store public_key must be a string")
        return cls(
            public_key=public_key,
            roles=frozenset(str(role) for role in roles),
            independence=str(value.get("independence", "unspecified")),
            controller=str(value.get("controller", "unknown")),
        )


@dataclass
class TrustStore:
    keys: dict[str, KeyRecord] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "TrustStore":
        raw = (value or {}).get("keys", value or {})
        if not isinstance(raw, Mapping):
            raise ValueError("trust store keys must be an object")
        if not all(isinstance(record, Mapping) for record in raw.values()):
            raise ValueError("each trust-store key record must be an object")
        return cls({str(key_id): KeyRecord.from_mapping(record) for key_id, record in raw.items()})

    def get(self, key_id: str) -> KeyRecord | None:
        return self.keys.get(key_id)


@dataclass
class Check:
    status: str
    reason_codes: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_codes": sorted(set(self.reason_codes)),
            "details": self.details,
        }


@dataclass
class SourceAssessment:
    source_format: str
    receipt_hashes: list[str]
    primary_hash: str | None
    source_key_ids: list[str]
    source_binding: dict[str, Any]
    source_timestamp: str | None
    integrity: Check
    provenance: Check
    coverage: Check
    profile: Check

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_format": self.source_format,
            "receipt_hashes": self.receipt_hashes,
            "primary_hash": self.primary_hash,
            "source_key_ids": self.source_key_ids,
            "source_binding": self.source_binding,
            "source_timestamp": self.source_timestamp,
            "integrity": self.integrity.as_dict(),
            "provenance": self.provenance.as_dict(),
            "coverage": self.coverage.as_dict(),
            "profile": self.profile.as_dict(),
        }


def parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value:
        return None
    if "T" not in value or not (value.endswith("Z") or "+" in value[10:] or "-" in value[10:]):
        return None
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def detect_source_format(receipt: Mapping[str, Any]) -> str:
    if receipt.get("canonicalization_id") == "olp-canonical-json-int-v1" and "signature" in receipt:
        return "olp_wire_canon"
    types = receipt.get("type", [])
    if isinstance(types, str):
        types = [types]
    if "AgentReceipt" in types and "credentialSubject" in receipt and "proof" in receipt:
        return "agent_receipts"
    if str(receipt.get("schema", "")).startswith("openline.receipt_gate.v0.1"):
        return "receipt_gate_legacy"
    return "unknown"


def _trusted_provenance(
    key_ids: Sequence[str],
    trust_store: TrustStore,
    *,
    required_role: str = "source",
) -> Check:
    if not key_ids:
        return Check(UNAVAILABLE, ["source_key_unavailable"])
    missing: list[str] = []
    independence: list[str] = []
    controllers: list[str] = []
    for key_id in key_ids:
        record = trust_store.get(key_id)
        if record is None or required_role not in record.roles:
            missing.append(key_id)
            continue
        independence.append(record.independence)
        controllers.append(record.controller)
    if missing:
        return Check(
            UNAVAILABLE,
            ["source_key_not_trusted"],
            {"untrusted_key_ids": sorted(set(missing))},
        )
    return Check(
        PASS,
        [],
        {
            "independence": sorted(set(independence)),
            "controllers": sorted(set(controllers)),
        },
    )


def _validate_olp_profile(receipt: Mapping[str, Any]) -> list[str]:
    common = {
        "kind",
        "receipt_version",
        "algorithm_id",
        "canonicalization_id",
        "spec_uri",
        "attestation",
        "capture_status",
        "payload_hash",
        "signature",
    }
    trace = {
        "trace_id", "capture_loss", "dropped_span_count", "observed_span_count",
        "trace_root", "tree_algorithm", "completion_policy", "seal_reason",
    }
    amendment = {"trace_id", "amendment_sequence", "previous_receipt_hash", "late_span_hash", "reason"}
    loss = {
        "trace_id", "amendment_sequence", "previous_receipt_hash",
        "new_dropped_span_count", "cumulative_dropped_span_count", "reason",
    }
    try:
        # Canonicalization validation catches floats, unsafe integers, non-ASCII
        # keys, and unsupported Python values before profile checks.
        olp_canonical_json(receipt)
        if receipt.get("receipt_version") != "0.1":
            raise ValueError("unsupported_olp_version")
        if receipt.get("canonicalization_id") != "olp-canonical-json-int-v1":
            raise ValueError("unsupported_canonicalization")
        if receipt.get("attestation") != "self":
            raise ValueError("unsupported_attestation_profile")
        if receipt.get("capture_status") != "provisional":
            raise ValueError("unsupported_capture_status")
        if not isinstance(receipt.get("algorithm_id"), str) or not receipt.get("algorithm_id"):
            raise ValueError("algorithm_id_invalid")
        if not isinstance(receipt.get("spec_uri"), str) or not str(receipt.get("spec_uri")).startswith(("https://", "urn:")):
            raise ValueError("spec_uri_invalid")
        if not isinstance(receipt.get("payload_hash"), str) or len(str(receipt.get("payload_hash"))) != 64:
            raise ValueError("payload_hash_invalid")
        signature = receipt.get("signature")
        if not isinstance(signature, Mapping) or set(signature) != {"algorithm", "public_key", "value"}:
            raise ValueError("signature_shape_invalid")
        if signature.get("algorithm") != "Ed25519" or len(str(signature.get("public_key", ""))) != 64 or len(str(signature.get("value", ""))) != 128:
            raise ValueError("signature_encoding_invalid")

        kind = receipt.get("kind")
        if kind == "trace_receipt":
            allowed = common | trace | {"semantic_claims", "typed_event_status", "typed_event_error"}
            required = common | trace
            if missing := required - set(receipt):
                raise ValueError("missing_fields:" + ",".join(sorted(missing)))
            if unknown := set(receipt) - allowed:
                raise ValueError("unknown_fields:" + ",".join(sorted(unknown)))
            if "semantic_claims" in receipt and receipt.get("semantic_claims") is not False:
                raise ValueError("trace_semantic_claim_invalid")
            if "typed_event_status" in receipt or "typed_event_error" in receipt:
                if receipt.get("typed_event_status") != "invalid" or not receipt.get("typed_event_error"):
                    raise ValueError("typed_event_error_invalid")
        elif kind == "coherence_input_receipt":
            coherence = trace | {
                "semantic_claims", "typed_event_status", "semantic_graph_hash",
                "signal_schema_id", "signal_points_micros", "state_cap",
            }
            if set(receipt) != common | coherence:
                raise ValueError("coherence_field_set_invalid")
            if receipt.get("semantic_claims") is not True or receipt.get("typed_event_status") != "valid":
                raise ValueError("coherence_semantics_invalid")
            if not isinstance(receipt.get("semantic_graph_hash"), str) or len(str(receipt.get("semantic_graph_hash"))) != 64:
                raise ValueError("semantic_graph_hash_invalid")
            points = receipt.get("signal_points_micros")
            if not isinstance(points, list) or not all(isinstance(point, int) and not isinstance(point, bool) for point in points):
                raise ValueError("signal_points_invalid")
            if points and (not isinstance(receipt.get("signal_schema_id"), str) or not receipt.get("signal_schema_id")):
                raise ValueError("signal_schema_missing")
            if not points and receipt.get("signal_schema_id") is not None:
                raise ValueError("signal_schema_unexpected")
            if receipt.get("state_cap") != "white":
                raise ValueError("state_cap_invalid")
        elif kind == "amendment_receipt":
            if set(receipt) != common | amendment:
                raise ValueError("amendment_field_set_invalid")
            if receipt.get("reason") != "span_arrived_after_provisional_seal":
                raise ValueError("amendment_reason_invalid")
        elif kind == "capture_loss_amendment":
            if set(receipt) != common | loss:
                raise ValueError("capture_loss_field_set_invalid")
            if receipt.get("reason") != "processor_queue_overflow_after_provisional_seal":
                raise ValueError("capture_loss_reason_invalid")
            if int(receipt.get("cumulative_dropped_span_count", -1)) < int(receipt.get("new_dropped_span_count", 0)):
                raise ValueError("capture_loss_count_invalid")
        else:
            raise ValueError("unsupported_olp_kind")

        if kind in {"trace_receipt", "coherence_input_receipt"}:
            trace_id = str(receipt.get("trace_id", ""))
            if len(trace_id) != 32 or any(char not in "0123456789abcdef" for char in trace_id):
                raise ValueError("trace_id_invalid")
            for field_name in ("dropped_span_count", "observed_span_count"):
                value = receipt.get(field_name)
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError(f"{field_name}_invalid")
            if receipt.get("capture_loss") is not (receipt.get("dropped_span_count", 0) > 0):
                raise ValueError("capture_loss_flag_mismatch")
            if receipt.get("tree_algorithm") != "rfc6962-mth-sha256-promote-odd-v1":
                raise ValueError("tree_algorithm_invalid")
            completion = receipt.get("completion_policy")
            if not isinstance(completion, Mapping) or set(completion) != {"type", "grace_millis", "semconv_schema_id"}:
                raise ValueError("completion_policy_invalid")
            if completion.get("type") != "root_close_plus_grace":
                raise ValueError("completion_policy_type_invalid")
            if receipt.get("seal_reason") not in {"grace_elapsed", "shutdown_before_grace_elapsed"}:
                raise ValueError("seal_reason_invalid")
        else:
            sequence = receipt.get("amendment_sequence")
            if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
                raise ValueError("amendment_sequence_invalid")
    except (TypeError, ValueError) as exc:
        return [str(exc)]
    return []


def _assess_olp(receipts: Sequence[Mapping[str, Any]], trust_store: TrustStore) -> SourceAssessment:
    integrity_errors: list[str] = []
    profile_errors: list[str] = []
    hashes: list[str] = []
    key_ids: list[str] = []

    for receipt in receipts:
        valid, reason = verify_olp_signature(receipt)
        if not valid:
            integrity_errors.append(reason or "signature_invalid")
        profile_errors.extend(_validate_olp_profile(receipt))
        if isinstance(receipt.get("payload_hash"), str):
            hashes.append(str(receipt["payload_hash"]))
        signature = receipt.get("signature", {})
        if isinstance(signature, Mapping) and isinstance(signature.get("public_key"), str):
            key_ids.append(str(signature["public_key"]))

    chain_errors: list[str] = []
    loss = False
    initial = receipts[0] if receipts else {}
    if receipts:
        if initial.get("kind") not in {"trace_receipt", "coherence_input_receipt"}:
            chain_errors.append("initial_receipt_kind_invalid")
        previous_hash = initial.get("payload_hash")
        expected_sequence = 1
        loss = bool(initial.get("capture_loss")) or int(initial.get("dropped_span_count", 0) or 0) > 0
        for amendment in receipts[1:]:
            if amendment.get("kind") not in {"amendment_receipt", "capture_loss_amendment"}:
                chain_errors.append("non_amendment_after_initial")
                continue
            if amendment.get("amendment_sequence") != expected_sequence:
                chain_errors.append("amendment_sequence_gap")
            if amendment.get("previous_receipt_hash") != previous_hash:
                chain_errors.append("amendment_parent_mismatch")
            if amendment.get("kind") == "capture_loss_amendment":
                loss = True
            expected_sequence += 1
            previous_hash = amendment.get("payload_hash")

    if integrity_errors:
        integrity = Check(FAIL, integrity_errors)
    else:
        integrity = Check(PASS)
    profile = Check(FAIL, profile_errors) if profile_errors else Check(PASS)

    if chain_errors or loss:
        reasons = chain_errors + (["capture_loss_reported"] if loss else [])
        coverage = Check(FAIL, reasons, {"claim": "declared receipt-chain coverage only"})
    else:
        coverage = Check(
            PARTIAL,
            ["olp_capture_is_provisional"],
            {"claim": "chain continuity verified; event completeness remains unproved"},
        )

    return SourceAssessment(
        source_format="olp_wire_canon",
        receipt_hashes=hashes,
        primary_hash=hashes[-1] if hashes else None,
        source_key_ids=sorted(set(key_ids)),
        source_binding={
            "run_id": initial.get("trace_id"),
            "session_id": initial.get("trace_id"),
            "source_sequence": len(receipts),
        },
        source_timestamp=None,
        integrity=integrity,
        provenance=_trusted_provenance(sorted(set(key_ids)), trust_store),
        coverage=coverage,
        profile=profile,
    )


def _validate_agent_profile(receipt: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {"@context", "id", "type", "version", "issuer", "issuanceDate", "credentialSubject", "proof"}
    if missing := required - set(receipt):
        errors.append("missing_fields:" + ",".join(sorted(missing)))
    types = receipt.get("type", [])
    if isinstance(types, str):
        types = [types]
    if "VerifiableCredential" not in types or "AgentReceipt" not in types:
        errors.append("agent_receipt_type_missing")
    if not isinstance(receipt.get("id"), str) or not receipt.get("id"):
        errors.append("agent_receipt_id_invalid")
    version = str(receipt.get("version"))
    if version not in {"0.1.0", "0.2.0", "0.2.1", "0.3.0", "0.4.0", "0.5.0"}:
        errors.append("unsupported_agent_receipt_version")
    contexts = receipt.get("@context")
    if not isinstance(contexts, list) or "https://www.w3.org/ns/credentials/v2" not in contexts:
        errors.append("vc_v2_context_missing")
    expected_context = "https://agentreceipts.ai/context/v2" if version == "0.5.0" else "https://agentreceipts.ai/context/v1"
    if isinstance(contexts, list) and expected_context not in contexts:
        errors.append("agent_receipts_context_mismatch")
    if parse_timestamp(receipt.get("issuanceDate")) is None:
        errors.append("issuance_date_invalid")
    issuer = receipt.get("issuer")
    if not isinstance(issuer, Mapping) or not issuer.get("id"):
        errors.append("issuer_invalid")
    subject = receipt.get("credentialSubject")
    if not isinstance(subject, Mapping):
        errors.append("credential_subject_invalid")
    else:
        for field_name in ("principal", "action", "outcome", "chain"):
            if not isinstance(subject.get(field_name), Mapping):
                errors.append(f"{field_name}_missing")
        principal = subject.get("principal", {})
        if isinstance(principal, Mapping) and not principal.get("id"):
            errors.append("principal_identity_invalid")
        action = subject.get("action", {})
        if isinstance(action, Mapping):
            if not action.get("id") or not action.get("type"):
                errors.append("action_identity_invalid")
            if action.get("risk_level") not in {"low", "medium", "high", "critical"}:
                errors.append("action_risk_invalid")
            if parse_timestamp(action.get("timestamp")) is None:
                errors.append("action_timestamp_invalid")
        chain = subject.get("chain", {})
        outcome = subject.get("outcome", {})
        if isinstance(outcome, Mapping) and (
            not isinstance(outcome.get("status"), str) or not outcome.get("status")
        ):
            errors.append("outcome_status_invalid")
        if isinstance(chain, Mapping):
            if not isinstance(chain.get("sequence"), int) or isinstance(chain.get("sequence"), bool) or chain.get("sequence", 0) < 1:
                errors.append("chain_sequence_invalid")
            if not chain.get("chain_id"):
                errors.append("chain_id_invalid")
            if "previous_receipt_hash" not in chain:
                errors.append("chain_parent_missing")
            parent = chain.get("previous_receipt_hash")
            if parent is not None and (
                not isinstance(parent, str)
                or len(parent.removeprefix("sha256:")) != 64
                or any(char not in "0123456789abcdef" for char in parent.removeprefix("sha256:"))
            ):
                errors.append("chain_parent_hash_invalid")
            if "terminal" in chain and not isinstance(chain.get("terminal"), bool):
                errors.append("chain_terminal_invalid")
    proof = receipt.get("proof")
    if not isinstance(proof, Mapping):
        errors.append("proof_invalid")
    else:
        if proof.get("type") != "Ed25519Signature2020":
            errors.append("proof_type_unsupported")
        if (
            not proof.get("verificationMethod")
            or proof.get("proofPurpose") != "assertionMethod"
            or not isinstance(proof.get("proofValue"), str)
            or parse_timestamp(proof.get("created")) is None
        ):
            errors.append("proof_fields_invalid")
    return errors


def _agent_receipt_hash(receipt: Mapping[str, Any]) -> str:
    # Agent Receipts signs the canonical receipt fields excluding ``proof``;
    # the protocol uses the same canonical bytes for chain linkage.
    body = dict(receipt)
    body.pop("proof", None)
    return sha256_hex(jcs_integer_canonical_json(body))


def _assess_agent(receipts: Sequence[Mapping[str, Any]], trust_store: TrustStore) -> SourceAssessment:
    integrity_failures: list[str] = []
    integrity_unknown: list[str] = []
    profile_errors: list[str] = []
    hashes: list[str] = []
    key_ids: list[str] = []

    for receipt in receipts:
        proof = receipt.get("proof", {})
        method = str(proof.get("verificationMethod", "")) if isinstance(proof, Mapping) else ""
        record = trust_store.get(method)
        trusted_key = record.public_key if record else None
        valid, reason, resolved_method = verify_agent_receipt_signature(receipt, trusted_key)
        if resolved_method:
            key_ids.append(resolved_method)
        if valid is False:
            integrity_failures.append(reason or "signature_invalid")
        elif valid is None:
            integrity_unknown.append(reason or "signature_unavailable")
        profile_errors.extend(_validate_agent_profile(receipt))
        try:
            hashes.append(_agent_receipt_hash(receipt))
        except ValueError:
            integrity_unknown.append("canonicalization_unsupported")

    if integrity_failures:
        integrity = Check(FAIL, integrity_failures)
    elif integrity_unknown:
        integrity = Check(UNAVAILABLE, integrity_unknown)
    else:
        integrity = Check(PASS)

    chain_errors: list[str] = []
    terminal = False
    initial = receipts[0] if receipts else {}
    chain_id: str | None = None
    issuer_id: str | None = None
    expected_sequence = 1
    previous_hash: str | None = None
    for index, receipt in enumerate(receipts):
        subject = receipt.get("credentialSubject", {})
        chain = subject.get("chain", {}) if isinstance(subject, Mapping) else {}
        issuer = receipt.get("issuer", {})
        current_chain_id = chain.get("chain_id") if isinstance(chain, Mapping) else None
        current_issuer = issuer.get("id") if isinstance(issuer, Mapping) else issuer
        if index == 0:
            chain_id = current_chain_id
            issuer_id = current_issuer
        if current_chain_id != chain_id:
            chain_errors.append("chain_id_changed")
        if current_issuer != issuer_id:
            chain_errors.append("issuer_changed")
        if chain.get("sequence") != expected_sequence:
            chain_errors.append("agent_receipt_sequence_gap")
        declared_parent = chain.get("previous_receipt_hash")
        if isinstance(declared_parent, str):
            declared_parent = declared_parent.removeprefix("sha256:")
        if declared_parent != previous_hash:
            chain_errors.append("agent_receipt_parent_mismatch")
        current_terminal = chain.get("terminal") is True
        if current_terminal and index != len(receipts) - 1:
            chain_errors.append("receipt_after_terminal")
        terminal = current_terminal
        expected_sequence += 1
        try:
            previous_hash = _agent_receipt_hash(receipt)
        except ValueError:
            previous_hash = None

    if chain_errors:
        coverage = Check(FAIL, chain_errors, {"claim": "declared receipt-chain coverage only"})
    elif not terminal:
        coverage = Check(
            PARTIAL,
            ["terminal_receipt_missing"],
            {"claim": "present sequence verified; tail completeness remains unknown"},
        )
    else:
        coverage = Check(
            PASS,
            [],
            {"claim": "declared chain from sequence 1 through terminal verified; action omission remains out of scope"},
        )

    issuer = initial.get("issuer", {}) if isinstance(initial, Mapping) else {}
    subject = initial.get("credentialSubject", {}) if isinstance(initial, Mapping) else {}
    last_subject = receipts[-1].get("credentialSubject", {}) if receipts else {}
    last_chain = last_subject.get("chain", {}) if isinstance(last_subject, Mapping) else {}
    action = last_subject.get("action", {}) if isinstance(last_subject, Mapping) else {}
    timestamp = action.get("timestamp") if isinstance(action, Mapping) else None

    return SourceAssessment(
        source_format="agent_receipts",
        receipt_hashes=hashes,
        primary_hash=hashes[-1] if hashes else None,
        source_key_ids=sorted(set(key_ids)),
        source_binding={
            "run_id": chain_id,
            "session_id": issuer.get("session_id", chain_id) if isinstance(issuer, Mapping) else chain_id,
            "source_sequence": last_chain.get("sequence") if isinstance(last_chain, Mapping) else None,
            "action_id": action.get("id") if isinstance(action, Mapping) else None,
        },
        source_timestamp=str(timestamp) if timestamp is not None else None,
        integrity=integrity,
        provenance=_trusted_provenance(sorted(set(key_ids)), trust_store),
        coverage=coverage,
        profile=Check(FAIL, profile_errors) if profile_errors else Check(PASS),
    )


def _assess_legacy(receipts: Sequence[Mapping[str, Any]], trust_store: TrustStore) -> SourceAssessment:
    del trust_store
    errors: list[str] = []
    hashes: list[str] = []
    previous: str | None = None
    for receipt in receipts:
        if receipt.get("parent_hash") != previous:
            errors.append("parent_hash_mismatch")
        expected = sha256_json({key: value for key, value in receipt.items() if key != "receipt_hash"})
        if receipt.get("receipt_hash") != expected:
            errors.append("receipt_hash_mismatch")
        previous = receipt.get("receipt_hash")
        if isinstance(previous, str):
            hashes.append(previous)
    last = receipts[-1] if receipts else {}
    return SourceAssessment(
        source_format="receipt_gate_legacy",
        receipt_hashes=hashes,
        primary_hash=hashes[-1] if hashes else None,
        source_key_ids=[],
        source_binding={
            "run_id": last.get("receipt_id"),
            "session_id": None,
            "source_sequence": len(receipts),
        },
        source_timestamp=str(last.get("timestamp")) if last.get("timestamp") is not None else None,
        integrity=Check(FAIL, errors) if errors else Check(PASS),
        provenance=Check(UNAVAILABLE, ["legacy_chain_is_unsigned"]),
        coverage=Check(PARTIAL, ["legacy_tail_completeness_unproved"]),
        profile=Check(PASS),
    )


def assess_source_bundle(
    receipts: Sequence[Mapping[str, Any]],
    trust_store: TrustStore | Mapping[str, Any] | None = None,
) -> SourceAssessment:
    store = trust_store if isinstance(trust_store, TrustStore) else TrustStore.from_mapping(trust_store)
    if not receipts:
        return SourceAssessment(
            source_format="unknown",
            receipt_hashes=[],
            primary_hash=None,
            source_key_ids=[],
            source_binding={},
            source_timestamp=None,
            integrity=Check(FAIL, ["source_receipt_missing"]),
            provenance=Check(UNAVAILABLE, ["source_key_unavailable"]),
            coverage=Check(FAIL, ["source_receipt_missing"]),
            profile=Check(FAIL, ["source_receipt_missing"]),
        )
    formats = {detect_source_format(receipt) for receipt in receipts}
    if len(formats) != 1:
        return SourceAssessment(
            source_format="mixed",
            receipt_hashes=[],
            primary_hash=None,
            source_key_ids=[],
            source_binding={},
            source_timestamp=None,
            integrity=Check(FAIL, ["mixed_source_formats"]),
            provenance=Check(UNAVAILABLE, ["mixed_source_formats"]),
            coverage=Check(FAIL, ["mixed_source_formats"]),
            profile=Check(FAIL, ["mixed_source_formats"]),
        )
    source_format = next(iter(formats))
    if source_format == "olp_wire_canon":
        return _assess_olp(receipts, store)
    if source_format == "agent_receipts":
        return _assess_agent(receipts, store)
    if source_format == "receipt_gate_legacy":
        return _assess_legacy(receipts, store)
    return SourceAssessment(
        source_format="unknown",
        receipt_hashes=[],
        primary_hash=None,
        source_key_ids=[],
        source_binding={},
        source_timestamp=None,
        integrity=Check(UNAVAILABLE, ["unknown_source_format"]),
        provenance=Check(UNAVAILABLE, ["unknown_source_format"]),
        coverage=Check(UNAVAILABLE, ["unknown_source_format"]),
        profile=Check(FAIL, ["unknown_source_format"]),
    )
