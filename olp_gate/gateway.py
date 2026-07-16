"""Proof-to-policy evaluation and signed decision receipts."""

from __future__ import annotations

import json
import os
import fcntl
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .adapters import (
    Check,
    FAIL,
    PARTIAL,
    PASS,
    UNAVAILABLE,
    SourceAssessment,
    TrustStore,
    assess_source_bundle,
    parse_timestamp,
)
from .crypto import (
    DuplicateKeyError,
    olp_canonical_json,
    sha256_hex,
    sign_olp_body,
    strict_json_loads,
    verify_olp_signature,
)
from .evidence import assess_evidence, assess_outcome, normalize_hash
from .policy import PolicySpec
from .session import SessionLedger


VERIFIED = "VERIFIED"
REJECTED = "REJECTED"
UNDECIDABLE = "UNDECIDABLE"

COMMIT = "COMMIT"
QUARANTINE = "QUARANTINE"
DENY = "DENY"
NO_BADGE = "NO_BADGE"
ROLLBACK_REQUEST = "ROLLBACK_REQUEST"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _action_fields(
    receipts: Sequence[Mapping[str, Any]],
    request: Mapping[str, Any],
) -> tuple[str, str | None, str | None, str | None]:
    requested_action_type = str(request.get("action_type", ""))
    action_type = ""
    signed_action_type: str | None = None
    action_id: str | None = None
    risk_level: str | None = None
    if receipts:
        source = receipts[-1]
        pipelock_action = source.get("action_record")
        if isinstance(pipelock_action, Mapping):
            signed_action_type = str(pipelock_action.get("action_type", "")) or None
            action_type = signed_action_type or action_type
            action_id = (
                str(pipelock_action.get("action_id"))
                if pipelock_action.get("action_id") is not None
                else None
            )
        subject = source.get("credentialSubject")
        if isinstance(subject, Mapping):
            action = subject.get("action")
            if isinstance(action, Mapping):
                signed_action_type = str(action.get("type", "")) or None
                action_type = signed_action_type or action_type
                action_id = str(action.get("id")) if action.get("id") is not None else None
                risk_level = str(action.get("risk_level")) if action.get("risk_level") is not None else None
        source_type = str(source.get("action_type", "")) or None
        signed_action_type = signed_action_type or source_type
        action_type = action_type or source_type or str(source.get("kind", "unknown"))
        action_id = action_id or (str(source.get("receipt_id")) if source.get("receipt_id") else None)
    return action_type or requested_action_type or "unknown", action_id, risk_level, signed_action_type


def _assess_freshness(
    *,
    source: SourceAssessment,
    binding: Mapping[str, Any],
    policy: PolicySpec,
    ledger: SessionLedger | None,
    now: datetime,
) -> Check:
    errors: list[str] = []
    unavailable: list[str] = []
    details: dict[str, Any] = {}
    source_binding = source.source_binding

    if policy.require_replay_guard:
        for field in ("run_id", "session_id"):
            source_value = source_binding.get(field)
            expected = binding.get(field)
            if source_value is not None and expected != source_value:
                errors.append(f"source_{field}_mismatch")

        expected_source = binding.get("expected_source_hash")
        if expected_source != source.primary_hash:
            errors.append("expected_source_hash_mismatch")

    if policy.max_source_age_seconds is not None:
        timestamp = parse_timestamp(source.source_timestamp)
        if timestamp is None:
            unavailable.append("source_timestamp_unavailable")
        else:
            age = (now - timestamp).total_seconds()
            details["source_age_seconds"] = max(0, int(age))
            if age < -5:
                errors.append("source_timestamp_in_future")
            elif age > policy.max_source_age_seconds:
                errors.append("source_receipt_stale")

    if policy.require_replay_guard:
        if ledger is None:
            unavailable.append("replay_guard_unavailable")
        else:
            replay = ledger.check(binding, source_hash=source.primary_hash, now=now)
            details["replay_guard"] = replay.as_dict()
            if replay.status == FAIL:
                errors.extend(replay.reason_codes)

    if errors:
        return Check(FAIL, errors, details)
    if unavailable:
        return Check(UNAVAILABLE, unavailable, details)
    return Check(PASS, [], details)


def _independence_check(source: SourceAssessment, policy: PolicySpec) -> Check:
    if not policy.require_independent_source:
        return Check(PASS, [], {"required": False})
    values = set(source.provenance.details.get("independence", []))
    if values & {"orthogonal", "receiver", "independent"}:
        return Check(PASS, [], {"required": True, "observed": sorted(values)})
    return Check(
        UNAVAILABLE,
        ["independent_source_witness_missing"],
        {"required": True, "observed": sorted(values)},
    )


def _collect_reasons(assessments: Mapping[str, Check]) -> list[str]:
    reasons: list[str] = []
    for name, check in assessments.items():
        reasons.extend(f"{name}:{reason}" for reason in check.reason_codes)
    return sorted(set(reasons))


def _choose_decision(
    *,
    action_type: str,
    risk_level: str | None,
    policy: PolicySpec,
    assessments: Mapping[str, Check],
) -> tuple[str, str]:
    no_badge = action_type in set(policy.no_badge_action_types)
    outcome_details = assessments["outcome"].details
    harmful = assessments["outcome"].status == PASS and outcome_details.get("harmful") is True
    rollback_supported = outcome_details.get("rollback_supported") is True

    if harmful:
        if policy.rollback_on_harm and rollback_supported:
            return REJECTED, ROLLBACK_REQUEST
        return REJECTED, DENY

    hard_fail_names = {"integrity", "profile", "freshness", "source_signal"}
    if any(assessments[name].status == FAIL for name in hard_fail_names):
        return REJECTED, NO_BADGE if no_badge else DENY

    if risk_level is not None and risk_level in set(policy.deny_risk_levels):
        return REJECTED, DENY

    if assessments["evidence"].status == FAIL or assessments["outcome"].status == FAIL:
        return REJECTED, NO_BADGE if no_badge else DENY

    required: list[str] = ["integrity", "profile", "freshness", "source_signal"]
    if policy.require_trusted_source:
        required.append("provenance")
    if policy.require_independent_source:
        required.append("independence")
    if policy.require_declared_coverage:
        required.append("coverage")
    if policy.require_evidence:
        required.append("evidence")
    if policy.require_outcome_witness:
        required.append("outcome")

    if any(assessments[name].status != PASS for name in required):
        return UNDECIDABLE, NO_BADGE if no_badge else QUARANTINE
    return VERIFIED, COMMIT


def _append_jsonl(path: str | Path, value: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_suffix(target.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        descriptor = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            payload = (
                json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short write while appending decision receipt")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def evaluate_request(
    request: Mapping[str, Any],
    *,
    policy: PolicySpec | Mapping[str, Any],
    trust_store: TrustStore | Mapping[str, Any] | None,
    signing_key: Ed25519PrivateKey,
    issuer_id: str,
    decision_path: str | Path,
    session_ledger: SessionLedger | None = None,
    base_dir: str | Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate one request and emit a signed, parent-linked decision receipt."""

    if request.get("schema") != "openline.proof_to_policy.request.v0.2":
        raise ValueError("unsupported proof-to-policy request schema")
    spec = policy if isinstance(policy, PolicySpec) else PolicySpec.from_mapping(policy)
    store = trust_store if isinstance(trust_store, TrustStore) else TrustStore.from_mapping(trust_store)
    raw_receipts = request.get("source_receipts")
    if raw_receipts is None and request.get("source_receipt") is not None:
        raw_receipts = [request["source_receipt"]]
    if not isinstance(raw_receipts, list) or not all(isinstance(item, Mapping) for item in raw_receipts):
        raw_receipts = []
    receipts: list[Mapping[str, Any]] = list(raw_receipts)
    source = assess_source_bundle(receipts, store)
    binding = request.get("binding", {})
    if not isinstance(binding, Mapping):
        binding = {}
    current_time = now or _now()
    action_type, action_id, risk_level, signed_action_type = _action_fields(receipts, request)

    evidence_items = request.get("evidence", [])
    if not isinstance(evidence_items, list):
        evidence_items = []
    disclosure = request.get("source_disclosure")
    if not isinstance(disclosure, Mapping):
        disclosure = None

    assessments: dict[str, Check] = {
        "integrity": source.integrity,
        "profile": source.profile,
        "provenance": source.provenance,
        "independence": _independence_check(source, spec),
        "coverage": source.coverage,
        "source_signal": source.source_signal,
        "freshness": _assess_freshness(
            source=source,
            binding=binding,
            policy=spec,
            ledger=session_ledger,
            now=current_time,
        ),
        "evidence": assess_evidence(
            source_receipts=receipts,
            source_receipt_hashes=source.receipt_hashes,
            source_format=source.source_format,
            evidence_items=evidence_items,
            required_evidence_ids=spec.required_evidence_ids,
            required_claim_ids=spec.required_claim_ids or ((action_id,) if action_id else ()),
            require_source_binding=spec.require_source_bound_evidence,
            assertions=spec.evidence_assertions,
            disclosure=disclosure,
            base_dir=base_dir,
            max_evidence_bytes=spec.max_evidence_bytes,
        ) if spec.require_evidence else Check(PASS, [], {"required": False}),
        "outcome": assess_outcome(
            outcome_receipt=request.get("outcome_receipt") if isinstance(request.get("outcome_receipt"), Mapping) else None,
            source_hash=source.primary_hash,
            trust_store=store,
        ) if spec.require_outcome_witness or isinstance(request.get("outcome_receipt"), Mapping)
        else Check(PASS, [], {"required": False}),
    }

    requested_action_type = request.get("action_type")
    if (
        signed_action_type is not None
        and isinstance(requested_action_type, str)
        and requested_action_type
        and requested_action_type != signed_action_type
    ):
        assessments["profile"] = Check(
            FAIL,
            assessments["profile"].reason_codes + ["request_action_type_mismatch"],
            {**assessments["profile"].details, "signed_action_type": signed_action_type},
        )

    if (
        assessments["outcome"].status == PASS
        and "evidence_hash" in assessments["outcome"].details
    ):
        artifact_hashes = set(assessments["evidence"].details.get("artifact_hashes", {}).values())
        outcome_evidence_hash = normalize_hash(assessments["outcome"].details.get("evidence_hash"))
        if artifact_hashes and outcome_evidence_hash not in artifact_hashes:
            assessments["outcome"] = Check(
                FAIL,
                assessments["outcome"].reason_codes + ["outcome_evidence_binding_mismatch"],
                assessments["outcome"].details,
            )

    verdict, decision = _choose_decision(
        action_type=action_type,
        risk_level=risk_level,
        policy=spec,
        assessments=assessments,
    )
    reasons = _collect_reasons(assessments)
    replay_status = assessments["freshness"].details.get("replay_guard", {}).get("status")
    chain_accepted = spec.require_replay_guard and replay_status == PASS
    claim = request.get("claim")
    claim_hash = sha256_hex(str(claim).encode("utf-8")) if claim is not None else None
    body = {
        "kind": "proof_to_policy_decision_receipt",
        "receipt_version": "0.3",
        "algorithm_id": "openline-proof-to-policy-gate-0.3",
        "canonicalization_id": "olp-canonical-json-int-v1",
        "spec_uri": "https://github.com/terryncew/openline-receipt-gate",
        "issuer": {"id": issuer_id},
        "created_at": _iso(current_time),
        "request_id": str(request.get("request_id", "")),
        "action": {
            "type": action_type,
            "id": action_id,
            "risk_level": risk_level,
            "claim_hash": claim_hash,
        },
        "source": {
            "format": source.source_format,
            "receipt_hashes": source.receipt_hashes,
            "primary_hash": source.primary_hash,
            "source_key_ids": source.source_key_ids,
        },
        "binding": {
            "run_id": binding.get("run_id"),
            "session_id": binding.get("session_id"),
            "sequence": binding.get("sequence"),
            "challenge_nonce": binding.get("challenge_nonce"),
            "parent_decision_hash": binding.get("parent_decision_hash"),
            "expected_source_hash": binding.get("expected_source_hash"),
        },
        "policy": {
            "id": spec.policy_id,
            "version": spec.version,
            "hash": spec.policy_hash,
            "snapshot": spec.as_dict(),
        },
        "assessments": {name: check.as_dict() for name, check in assessments.items()},
        "verdict": verdict,
        "decision": decision,
        "chain_accepted": chain_accepted,
        "reason_codes": reasons,
        "privacy": {
            "raw_evidence_stored": False,
            "raw_source_disclosure_stored": False,
        },
    }
    receipt = sign_olp_body(body, signing_key)

    if (
        session_ledger is not None
        and spec.require_replay_guard
        and source.primary_hash is not None
        and chain_accepted
    ):
        # The challenge is consumed before publication.  If publication later
        # fails, replay remains blocked and the returned signed receipt can be
        # recovered by the caller.
        session_ledger.consume(
            binding,
            source_hash=source.primary_hash,
            decision_hash=receipt["payload_hash"],
        )
    _append_jsonl(decision_path, receipt)
    return receipt


def verify_decision_receipt(
    receipt: Mapping[str, Any],
    trusted_gate_keys: Sequence[str],
) -> dict[str, Any]:
    errors: list[str] = []
    valid, reason = verify_olp_signature(receipt)
    if not valid:
        errors.append(reason or "signature_invalid")
    signature = receipt.get("signature")
    embedded_key = signature.get("public_key") if isinstance(signature, Mapping) else None
    key_set = {str(key).removeprefix("ed25519:") for key in trusted_gate_keys}
    if not key_set or embedded_key not in key_set:
        errors.append("gate_key_not_trusted")
    if receipt.get("kind") != "proof_to_policy_decision_receipt":
        errors.append("decision_profile_invalid")
    decision_version = receipt.get("receipt_version")
    if decision_version not in {"0.2", "0.3"}:
        errors.append("decision_version_unsupported")
    if receipt.get("canonicalization_id") != "olp-canonical-json-int-v1":
        errors.append("decision_canonicalization_unsupported")
    expected_algorithm = {
        "0.2": "openline-proof-to-policy-gate-0.2",
        "0.3": "openline-proof-to-policy-gate-0.3",
    }.get(str(decision_version))
    if receipt.get("algorithm_id") != expected_algorithm:
        errors.append("decision_algorithm_unsupported")
    if parse_timestamp(receipt.get("created_at")) is None:
        errors.append("decision_timestamp_invalid")
    if not isinstance(receipt.get("issuer"), Mapping) or not receipt.get("issuer", {}).get("id"):
        errors.append("decision_issuer_invalid")
    if not isinstance(receipt.get("request_id"), str) or not receipt.get("request_id"):
        errors.append("decision_request_id_invalid")
    if receipt.get("verdict") not in {VERIFIED, REJECTED, UNDECIDABLE}:
        errors.append("decision_verdict_invalid")
    if receipt.get("decision") not in {COMMIT, QUARANTINE, DENY, NO_BADGE, ROLLBACK_REQUEST}:
        errors.append("decision_action_invalid")
    policy_value = receipt.get("policy")
    assessments_value = receipt.get("assessments")
    action = receipt.get("action")
    source = receipt.get("source")
    binding = receipt.get("binding")
    privacy = receipt.get("privacy")
    if not isinstance(source, Mapping) or not isinstance(binding, Mapping):
        errors.append("decision_binding_inputs_missing")
    else:
        primary_hash = source.get("primary_hash")
        expected_source_hash = binding.get("expected_source_hash")
        for name, value in (("primary", primary_hash), ("expected", expected_source_hash)):
            if value is not None and (
                not isinstance(value, str)
                or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)
            ):
                errors.append(f"decision_source_{name}_hash_invalid")
    if not isinstance(privacy, Mapping) or privacy.get("raw_evidence_stored") is not False or privacy.get("raw_source_disclosure_stored") is not False:
        errors.append("decision_privacy_profile_invalid")
    if not isinstance(policy_value, Mapping) or not isinstance(policy_value.get("snapshot"), Mapping):
        errors.append("policy_snapshot_missing")
    elif not isinstance(assessments_value, Mapping) or not isinstance(action, Mapping):
        errors.append("decision_semantic_inputs_missing")
    else:
        try:
            spec = PolicySpec.from_mapping(policy_value["snapshot"])
            if spec.policy_hash != policy_value.get("hash"):
                errors.append("policy_hash_mismatch")
            if spec.policy_id != policy_value.get("id") or spec.version != policy_value.get("version"):
                errors.append("policy_identity_mismatch")
            checks: dict[str, Check] = {}
            assessment_names = [
                "integrity", "profile", "provenance", "independence",
                "coverage", "freshness", "evidence", "outcome",
            ]
            if decision_version == "0.3":
                assessment_names.append("source_signal")
            for name in assessment_names:
                raw = assessments_value.get(name)
                if not isinstance(raw, Mapping):
                    raise ValueError(f"assessment_missing:{name}")
                if raw.get("status") not in {PASS, FAIL, PARTIAL, UNAVAILABLE}:
                    raise ValueError(f"assessment_status_invalid:{name}")
                if (
                    not isinstance(raw.get("reason_codes"), list)
                    or not all(isinstance(code, str) for code in raw.get("reason_codes", []))
                    or not isinstance(raw.get("details"), Mapping)
                ):
                    raise ValueError(f"assessment_shape_invalid:{name}")
                checks[name] = Check(
                    status=str(raw.get("status", "")),
                    reason_codes=list(raw.get("reason_codes", [])),
                    details=dict(raw.get("details", {})),
                )
            if decision_version == "0.2":
                checks["source_signal"] = Check(PASS, [], {"required": False})
            expected_verdict, expected_decision = _choose_decision(
                action_type=str(action.get("type", "unknown")),
                risk_level=str(action.get("risk_level")) if action.get("risk_level") is not None else None,
                policy=spec,
                assessments=checks,
            )
            if (receipt.get("verdict"), receipt.get("decision")) != (expected_verdict, expected_decision):
                errors.append("decision_recompute_mismatch")
            if receipt.get("reason_codes") != _collect_reasons(checks):
                errors.append("reason_codes_recompute_mismatch")
            replay_status = checks["freshness"].details.get("replay_guard", {}).get("status")
            expected_chain_accepted = spec.require_replay_guard and replay_status == PASS
            if receipt.get("chain_accepted") is not expected_chain_accepted:
                errors.append("chain_acceptance_recompute_mismatch")
        except (TypeError, ValueError, KeyError) as exc:
            errors.append(f"decision_semantic_recompute_error:{exc}")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "payload_hash": receipt.get("payload_hash"),
        "gate_public_key": embedded_key,
        "gate_key_trusted": embedded_key in key_set,
    }


def verify_decision_log(path: str | Path, trusted_gate_keys: Sequence[str]) -> dict[str, Any]:
    target = Path(path)
    if not target.exists() or not target.read_text(encoding="utf-8").strip():
        return {"valid": False, "count": 0, "errors": ["decision_log_missing_or_empty"]}
    receipts: list[dict[str, Any]] = []
    errors: list[str] = []
    for line_number, line in enumerate(target.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            receipt = strict_json_loads(line)
            if not isinstance(receipt, Mapping):
                raise ValueError("decision receipt is not an object")
        except (json.JSONDecodeError, DuplicateKeyError, ValueError):
            errors.append(f"json_parse_error:{line_number}")
            continue
        result = verify_decision_receipt(receipt, trusted_gate_keys)
        errors.extend(f"receipt_{line_number}:{error}" for error in result["errors"])
        receipts.append(receipt)

    sessions: dict[tuple[Any, Any], tuple[int, str | None]] = {}
    for index, receipt in enumerate(receipts, start=1):
        binding = receipt.get("binding", {})
        key = (binding.get("run_id"), binding.get("session_id"))
        expected_sequence, expected_parent = sessions.get(key, (1, None))
        if receipt.get("chain_accepted") is True:
            if binding.get("sequence") != expected_sequence:
                errors.append(f"receipt_{index}:decision_sequence_mismatch")
            if binding.get("parent_decision_hash") != expected_parent:
                errors.append(f"receipt_{index}:decision_parent_mismatch")
            sessions[key] = (expected_sequence + 1, receipt.get("payload_hash"))
    return {
        "valid": not errors,
        "count": len(receipts),
        "errors": sorted(set(errors)),
        "last_hashes": {f"{run_id}/{session_id}": parent for (run_id, session_id), (_, parent) in sessions.items()},
    }
