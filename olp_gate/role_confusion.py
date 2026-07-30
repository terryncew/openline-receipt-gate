"""Receiver-side consequence appraisal for role-confusion experiments.

This module deliberately does *not* detect prompt injection.  It assumes the
model may already have been fooled and asks a narrower question: does the
receiver possess trusted, action-bound evidence that justifies the requested
protected effect?

Trust anchors live only in the receiver policy.  Evidence cannot promote its
own origin to trusted status.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, TypeVar

from .adapters import parse_timestamp
from .crypto import (
    MAX_SAFE_INTEGER,
    UnsupportedCanonicalValue,
    olp_canonical_json,
    sha256_hex,
    verify_olp_signature,
)


REQUEST_SCHEMA = "openline.role_confusion_consequence.request.v0.1"
POLICY_SCHEMA = "openline.role_confusion_consequence.policy.v0.1"
EVIDENCE_SCHEMA = "openline.evidence_origin_receipt.v0.1"
RESULT_SCHEMA = "openline.role_confusion_consequence.result.v0.1"

COMMIT = "COMMIT"
QUARANTINE = "QUARANTINE"
DENY = "DENY"
UNDECIDABLE = "UNDECIDABLE"
PASS = "PASS"
FAIL = "FAIL"
UNAVAILABLE = "UNAVAILABLE"

_ACTION_KEYS = {"tool", "target", "settings_hash", "run_id", "nonce", "expires_at"}
_REQUEST_KEYS = {"schema", "request_id", "action", "evidence"}
_POLICY_KEYS = {
    "schema",
    "policy_id",
    "version",
    "action_template",
    "trusted_origins",
    "required_claim",
    "max_evidence_age_seconds",
}
_ACTION_TEMPLATE_KEYS = {"tool", "target", "settings_hash", "run_id", "max_ttl_seconds"}
_ORIGIN_KEYS = {"origin_id", "public_key_hex"}
_EVIDENCE_BODY_KEYS = {
    "schema",
    "evidence_id",
    "origin_id",
    "issued_at",
    "action_hash",
    "claim",
    "value",
}
_EVIDENCE_KEYS = _EVIDENCE_BODY_KEYS | {"payload_hash", "signature"}
_SIGNATURE_KEYS = {"algorithm", "public_key", "value"}
_CASES_DOCUMENT_KEYS = {"schema", "frozen_now", "cases"}
_CASE_KEYS = {
    "case_id",
    "class",
    "consumed_nonces",
    "expected",
    "model_compromise_assumed",
    "request",
    "stimulus",
}
_EXPECTED_KEYS = {
    "authorization_status",
    "decision",
    "protected_effect_authorized",
    "protected_effect_executed",
}
_CASE_DOCUMENT_SCHEMA = "openline.role_confusion_consequence.cases.v0.1"
_ALLOWED_DECISIONS = (COMMIT, QUARANTINE, DENY, UNDECIDABLE)
_ALLOWED_ASSESSMENT_STATUSES = (PASS, FAIL, UNAVAILABLE)

T = TypeVar("T")


class ConsequenceGateError(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_hash(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return value == value.lower()


def _require_nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConsequenceGateError(f"{name}_invalid")
    return value


def _require_safe_nonnegative_integer(
    value: Any,
    name: str,
    *,
    minimum: int = 0,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > MAX_SAFE_INTEGER
    ):
        raise ConsequenceGateError(f"{name}_invalid")
    return value


def _require_hex_bytes(value: Any, name: str, length: int) -> str:
    if not isinstance(value, str) or value != value.lower():
        raise ConsequenceGateError(f"{name}_invalid")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ConsequenceGateError(f"{name}_invalid") from exc
    if len(raw) != length:
        raise ConsequenceGateError(f"{name}_invalid")
    return value


def _validate_action(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ConsequenceGateError("action_invalid")
    action = dict(value)
    if set(action) != _ACTION_KEYS:
        raise ConsequenceGateError("action_shape_invalid")
    for name in ("tool", "target", "run_id", "nonce", "expires_at"):
        _require_nonempty_string(action.get(name), f"action_{name}")
    if not _is_hash(action.get("settings_hash")):
        raise ConsequenceGateError("action_settings_hash_invalid")
    if parse_timestamp(action["expires_at"]) is None:
        raise ConsequenceGateError("action_expiry_invalid")
    return action


def consequence_action_hash(action: Mapping[str, Any]) -> str:
    normalized = _validate_action(action)
    return sha256_hex(olp_canonical_json(normalized))


def _validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ConsequenceGateError("receiver_policy_invalid")
    policy = dict(value)
    if set(policy) != _POLICY_KEYS:
        raise ConsequenceGateError("receiver_policy_shape_invalid")
    if policy.get("schema") != POLICY_SCHEMA:
        raise ConsequenceGateError("receiver_policy_schema_invalid")
    _require_nonempty_string(policy.get("policy_id"), "receiver_policy_id")
    _require_nonempty_string(policy.get("version"), "receiver_policy_version")
    template = policy.get("action_template")
    if not isinstance(template, Mapping) or set(template) != _ACTION_TEMPLATE_KEYS:
        raise ConsequenceGateError("action_template_invalid")
    for name in ("tool", "target", "run_id"):
        _require_nonempty_string(template.get(name), f"action_template_{name}")
    if not _is_hash(template.get("settings_hash")):
        raise ConsequenceGateError("action_template_settings_hash_invalid")
    _require_safe_nonnegative_integer(
        template.get("max_ttl_seconds"),
        "action_template_max_ttl",
        minimum=1,
    )
    _require_safe_nonnegative_integer(
        policy.get("max_evidence_age_seconds"),
        "max_evidence_age",
    )
    required_claim = _require_nonempty_string(policy.get("required_claim"), "required_claim")
    origins = policy.get("trusted_origins")
    if not isinstance(origins, list) or not origins:
        raise ConsequenceGateError("trusted_origins_invalid")
    seen: set[str] = set()
    for item in origins:
        if not isinstance(item, Mapping) or set(item) != _ORIGIN_KEYS:
            raise ConsequenceGateError("trusted_origin_shape_invalid")
        origin_id = _require_nonempty_string(item.get("origin_id"), "trusted_origin_id")
        _require_hex_bytes(
            item.get("public_key_hex"),
            "trusted_origin_public_key",
            32,
        )
        if origin_id in seen:
            raise ConsequenceGateError("trusted_origin_duplicate")
        seen.add(origin_id)
    return {**policy, "required_claim": required_claim}


def _validate_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ConsequenceGateError("request_invalid")
    request = dict(value)
    if set(request) != _REQUEST_KEYS:
        raise ConsequenceGateError("request_shape_invalid")
    if request.get("schema") != REQUEST_SCHEMA:
        raise ConsequenceGateError("request_schema_invalid")
    _require_nonempty_string(request.get("request_id"), "request_id")
    request["action"] = _validate_action(request.get("action"))
    evidence = request.get("evidence")
    if not isinstance(evidence, list):
        raise ConsequenceGateError("evidence_list_invalid")
    seen_evidence_ids: set[str] = set()
    for item in evidence:
        if not isinstance(item, Mapping) or set(item) != _EVIDENCE_KEYS:
            raise ConsequenceGateError("evidence_item_shape_invalid")
        if item.get("schema") != EVIDENCE_SCHEMA:
            raise ConsequenceGateError("evidence_item_schema_invalid")
        for name in ("evidence_id", "origin_id", "issued_at", "action_hash", "claim"):
            _require_nonempty_string(item.get(name), f"evidence_{name}")
        evidence_id = str(item["evidence_id"])
        if evidence_id in seen_evidence_ids:
            raise ConsequenceGateError("evidence_id_duplicate")
        seen_evidence_ids.add(evidence_id)
        if not isinstance(item.get("value"), bool):
            raise ConsequenceGateError("evidence_value_invalid")
        if not _is_hash(item.get("action_hash")):
            raise ConsequenceGateError("evidence_action_hash_invalid")
        if not _is_hash(item.get("payload_hash")):
            raise ConsequenceGateError("evidence_payload_hash_invalid")
        if parse_timestamp(item.get("issued_at")) is None:
            raise ConsequenceGateError("evidence_issued_at_invalid")
        signature = item.get("signature")
        if not isinstance(signature, Mapping) or set(signature) != _SIGNATURE_KEYS:
            raise ConsequenceGateError("evidence_signature_shape_invalid")
        if signature.get("algorithm") != "Ed25519":
            raise ConsequenceGateError("evidence_signature_algorithm_invalid")
        _require_hex_bytes(
            signature.get("public_key"),
            "evidence_signature_public_key",
            32,
        )
        _require_hex_bytes(
            signature.get("value"),
            "evidence_signature_value",
            64,
        )
    return request



def _validate_now(value: datetime | None) -> datetime:
    if value is None:
        return _now()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ConsequenceGateError("receiver_time_invalid")
    return value.astimezone(timezone.utc)


def _validate_consumed_nonces(value: Any) -> set[str]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ConsequenceGateError("consumed_nonces_invalid")
    normalized: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item:
            raise ConsequenceGateError("consumed_nonce_invalid")
        if item in normalized:
            raise ConsequenceGateError("consumed_nonce_duplicate")
        normalized.add(item)
    return normalized

def _assessment(status: str, reasons: Sequence[str], details: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "reason_codes": sorted(set(str(item) for item in reasons)),
        "details": dict(details or {}),
    }


def appraise_consequence(
    request: Mapping[str, Any],
    receiver_policy: Mapping[str, Any],
    *,
    now: datetime | None = None,
    consumed_nonces: Sequence[str] = (),
) -> dict[str, Any]:
    """Appraise execution consequence without inspecting injection text.

    ``request`` intentionally contains no prompt, model reasoning, attack label,
    or detector output.  The receiver evaluates only exact-action structure and
    receiver-pinned evidence provenance/support.
    """

    try:
        current = _validate_now(now)
        consumed_nonce_set = _validate_consumed_nonces(consumed_nonces)
        policy = _validate_policy(receiver_policy)
        normalized = _validate_request(request)
    except ConsequenceGateError as exc:
        return {
            "schema": RESULT_SCHEMA,
            "request_id": str(request.get("request_id", "")) if isinstance(request, Mapping) else "",
            "decision": UNDECIDABLE,
            "protected_effect_authorized": False,
            "assessments": {
                "input": _assessment(FAIL, [str(exc)]),
                "authorization": _assessment(UNAVAILABLE, ["input_invalid"]),
                "evidence_origin": _assessment(UNAVAILABLE, ["input_invalid"]),
                "evidence_support": _assessment(UNAVAILABLE, ["input_invalid"]),
            },
            "boundary": "No prompt-injection classification was performed.",
        }

    action = normalized["action"]
    template = policy["action_template"]
    authorization_reasons: list[str] = []
    for name in ("tool", "target", "settings_hash", "run_id"):
        if action.get(name) != template.get(name):
            authorization_reasons.append(f"action_{name}_mismatch")
    expiry = parse_timestamp(action["expires_at"])
    assert expiry is not None
    ttl = (expiry - current).total_seconds()
    if ttl <= 0:
        authorization_reasons.append("action_expired")
    elif ttl > template["max_ttl_seconds"]:
        authorization_reasons.append("action_ttl_exceeds_policy")
    if action["nonce"] in consumed_nonce_set:
        authorization_reasons.append("action_nonce_replayed")
    authorization = _assessment(
        FAIL if authorization_reasons else PASS,
        authorization_reasons,
        {
            "exact_action_valid": not authorization_reasons,
            "tool": action["tool"],
            "target": action["target"],
            "run_id": action["run_id"],
        },
    )

    expected_action_hash = consequence_action_hash(action)
    trusted = {item["origin_id"]: item["public_key_hex"] for item in policy["trusted_origins"]}
    origin_reasons: list[str] = []
    support_reasons: list[str] = []
    trusted_valid_ids: list[str] = []
    untrusted_ids: list[str] = []
    stale_ids: list[str] = []
    wrong_action_ids: list[str] = []
    invalid_trusted_proof_ids: list[str] = []
    valid_support_ids: list[str] = []
    negative_support_ids: list[str] = []

    for raw in normalized["evidence"]:
        item = dict(raw)
        evidence_id = str(item["evidence_id"])
        origin_id = str(item["origin_id"])
        is_valid_signature, signature_reason = verify_olp_signature(item)
        signature = item.get("signature", {})
        observed_key = signature.get("public_key") if isinstance(signature, Mapping) else None
        pinned_key = trusted.get(origin_id)
        if pinned_key is None:
            untrusted_ids.append(evidence_id)
            continue
        if observed_key != pinned_key or not is_valid_signature:
            invalid_trusted_proof_ids.append(evidence_id)
            origin_reasons.append(
                f"trusted_origin_proof_invalid:{evidence_id}:{signature_reason or 'key_mismatch'}"
            )
            continue
        trusted_valid_ids.append(evidence_id)
        if item["action_hash"] != expected_action_hash:
            wrong_action_ids.append(evidence_id)
            support_reasons.append(f"evidence_action_binding_mismatch:{evidence_id}")
            continue
        issued = parse_timestamp(item["issued_at"])
        assert issued is not None
        age = (current - issued).total_seconds()
        if age < -5:
            support_reasons.append(f"evidence_timestamp_in_future:{evidence_id}")
            continue
        if age > policy["max_evidence_age_seconds"]:
            stale_ids.append(evidence_id)
            support_reasons.append(f"evidence_stale:{evidence_id}")
            continue
        if item["claim"] == policy["required_claim"]:
            if item["value"] is True:
                valid_support_ids.append(evidence_id)
            else:
                negative_support_ids.append(evidence_id)

    if invalid_trusted_proof_ids:
        origin_status = FAIL
    elif trusted_valid_ids:
        origin_status = PASS
    elif normalized["evidence"]:
        origin_status = UNAVAILABLE
        origin_reasons.append("no_receiver_trusted_evidence_origin")
    else:
        origin_status = UNAVAILABLE
        origin_reasons.append("evidence_missing")

    # A receiver-trusted, cryptographically valid receipt for a different
    # exact action is not harmless noise. Its presence makes the trusted bundle
    # internally action-incoherent, so fail closed even if another trusted
    # receipt positively supports the current action. Untrusted unrelated
    # evidence remains ignorable and is covered by a separate control.
    if wrong_action_ids:
        support_status = FAIL
    elif negative_support_ids:
        support_reasons.extend(
            f"trusted_negative_action_support:{evidence_id}"
            for evidence_id in negative_support_ids
        )
        if valid_support_ids:
            support_reasons.append("trusted_action_support_conflict")
        support_status = UNAVAILABLE
    elif not valid_support_ids:
        if not support_reasons:
            support_reasons.append("required_trusted_action_support_missing")
        support_status = UNAVAILABLE if not invalid_trusted_proof_ids else FAIL
    else:
        support_status = PASS

    evidence_origin = _assessment(
        origin_status,
        origin_reasons,
        {
            "trusted_valid_evidence_ids": sorted(trusted_valid_ids),
            "untrusted_evidence_ids": sorted(untrusted_ids),
            "invalid_trusted_proof_ids": sorted(invalid_trusted_proof_ids),
        },
    )
    evidence_support = _assessment(
        support_status,
        support_reasons,
        {
            "required_claim": policy["required_claim"],
            "valid_support_ids": sorted(valid_support_ids),
            "negative_support_ids": sorted(negative_support_ids),
            "stale_evidence_ids": sorted(stale_ids),
            "wrong_action_evidence_ids": sorted(wrong_action_ids),
            "expected_action_hash": expected_action_hash,
        },
    )

    if authorization["status"] == FAIL:
        decision = DENY
    elif evidence_origin["status"] == FAIL or evidence_support["status"] == FAIL:
        decision = DENY
    elif evidence_support["status"] != PASS:
        decision = QUARANTINE
    else:
        decision = COMMIT

    return {
        "schema": RESULT_SCHEMA,
        "request_id": normalized["request_id"],
        "decision": decision,
        "protected_effect_authorized": decision == COMMIT,
        "assessments": {
            "input": _assessment(PASS, []),
            "authorization": authorization,
            "evidence_origin": evidence_origin,
            "evidence_support": evidence_support,
        },
        "receiver_policy": {
            "policy_id": policy["policy_id"],
            "version": policy["version"],
            "policy_hash": sha256_hex(olp_canonical_json(policy)),
        },
        "action_hash": expected_action_hash,
        "boundary": "No prompt, attack label, model reasoning, or injection detector output entered appraisal.",
    }


def execute_appraised_consequence(
    request: Mapping[str, Any],
    receiver_policy: Mapping[str, Any],
    *,
    executor: Callable[[], T],
    now: datetime | None = None,
    consumed_nonces: Sequence[str] = (),
) -> dict[str, Any]:
    """Invoke a harmless receiver tool only after evidence appraisal commits.

    This is a pre-effect demonstration boundary, not a general exactly-once
    executor. Production callers should compose appraisal with Verified Commit
    so nonce consumption and execution reservation share the receiver's atomic
    ledger.
    """

    result = appraise_consequence(
        request,
        receiver_policy,
        now=now,
        consumed_nonces=consumed_nonces,
    )
    if result["decision"] != COMMIT:
        return {
            **result,
            "protected_effect_executed": False,
            "execution": {
                "status": "BLOCKED_BEFORE_EFFECT",
                "tool_invoked": False,
                "tool_result_hash": None,
            },
        }
    if not callable(executor):
        return {
            **result,
            "decision": UNDECIDABLE,
            "protected_effect_authorized": False,
            "protected_effect_executed": False,
            "execution": {
                "status": "EXECUTOR_INVALID",
                "tool_invoked": False,
                "tool_result_hash": None,
            },
        }
    # As in Verified Commit, executor failures propagate because a callback may
    # have partially effected its target before raising. Returning a clean
    # "not executed" result here would be a false claim.
    tool_result = executor()
    try:
        tool_result_hash = sha256_hex(olp_canonical_json(tool_result))
    except (TypeError, UnsupportedCanonicalValue):
        tool_result_hash = None
    return {
        **result,
        "protected_effect_executed": True,
        "execution": {
            "status": "EXECUTED",
            "tool_invoked": True,
            "tool_result_hash": tool_result_hash,
        },
    }


def _validate_expected(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _EXPECTED_KEYS:
        raise ConsequenceGateError("case_expected_shape_invalid")
    expected = dict(value)
    if expected.get("decision") not in _ALLOWED_DECISIONS:
        raise ConsequenceGateError("case_expected_decision_invalid")
    if expected.get("authorization_status") not in _ALLOWED_ASSESSMENT_STATUSES:
        raise ConsequenceGateError("case_expected_authorization_status_invalid")
    if not isinstance(expected.get("protected_effect_authorized"), bool):
        raise ConsequenceGateError("case_expected_authorized_invalid")
    if not isinstance(expected.get("protected_effect_executed"), bool):
        raise ConsequenceGateError("case_expected_executed_invalid")
    if expected["protected_effect_authorized"] != (expected["decision"] == COMMIT):
        raise ConsequenceGateError("case_expected_authorization_inconsistent")
    if expected["protected_effect_executed"] != (expected["decision"] == COMMIT):
        raise ConsequenceGateError("case_expected_execution_inconsistent")
    return expected


def run_case_matrix(
    cases_document: Mapping[str, Any],
    receiver_policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Run a frozen case matrix without exposing case labels to appraisal."""
    if (
        not isinstance(cases_document, Mapping)
        or set(cases_document) != _CASES_DOCUMENT_KEYS
        or cases_document.get("schema") != _CASE_DOCUMENT_SCHEMA
    ):
        raise ConsequenceGateError("case_matrix_shape_invalid")
    frozen_now = parse_timestamp(cases_document.get("frozen_now"))
    cases = cases_document.get("cases")
    if frozen_now is None or not isinstance(cases, list) or not cases:
        raise ConsequenceGateError("case_matrix_invalid")
    rows: list[dict[str, Any]] = []
    seen_case_ids: set[str] = set()
    for case in cases:
        if not isinstance(case, Mapping) or set(case) != _CASE_KEYS:
            raise ConsequenceGateError("case_shape_invalid")
        case_id = _require_nonempty_string(case.get("case_id"), "case_id")
        if case_id in seen_case_ids:
            raise ConsequenceGateError("case_id_duplicate")
        seen_case_ids.add(case_id)
        _require_nonempty_string(case.get("class"), "case_class")
        _require_nonempty_string(case.get("stimulus"), "case_stimulus")
        if not isinstance(case.get("model_compromise_assumed"), bool):
            raise ConsequenceGateError("case_model_compromise_invalid")
        expected = _validate_expected(case.get("expected"))
        effects: list[str] = []

        def execute_fixture() -> dict[str, Any]:
            effects.append(case_id)
            return {
                "schema": "openline.role_confusion_consequence.fixture-effect.v1",
                "case_id": case_id,
                "released": True,
            }

        result = execute_appraised_consequence(
            case.get("request", {}),
            receiver_policy,
            executor=execute_fixture,
            now=frozen_now,
            consumed_nonces=case.get("consumed_nonces", ()),
        )
        observed = {
            "decision": result["decision"],
            "authorization_status": result["assessments"]["authorization"]["status"],
            "protected_effect_authorized": result["protected_effect_authorized"],
            "protected_effect_executed": result["protected_effect_executed"],
        }
        rows.append(
            {
                "case_id": case_id,
                "class": str(case.get("class", "")),
                "model_compromise_assumed": case.get("model_compromise_assumed") is True,
                "expected": expected,
                "observed": observed,
                "passed": observed == expected,
                "effect_invocation_count": len(effects),
                "result": result,
            }
        )
    required_controls = {
        "matched_legitimate_twin",
        "unrelated_untrusted_addition_does_not_block",
    }
    missing_controls = sorted(required_controls - seen_case_ids)
    if missing_controls:
        raise ConsequenceGateError(
            "case_matrix_required_controls_missing:" + ",".join(missing_controls)
        )
    hostile = [row for row in rows if row["model_compromise_assumed"]]
    authorization_valid_hostile = [
        row for row in hostile if row["observed"]["authorization_status"] == PASS
    ]
    return {
        "schema": "openline.role_confusion_consequence.report.v0.1",
        "profile": "role-confusion-consequence-v1",
        "case_count": len(rows),
        "passed": all(row["passed"] for row in rows),
        "cases_passed": sum(row["passed"] for row in rows),
        "assumed_model_compromise_cases": len(hostile),
        "authorization_valid_hostile_cases": len(authorization_valid_hostile),
        "authorization_valid_hostile_effects_blocked": sum(
            not row["observed"]["protected_effect_executed"]
            for row in authorization_valid_hostile
        ),
        "protected_effect_callback_count": sum(
            row["effect_invocation_count"] for row in rows
        ),
        "matched_legitimate_twin_committed": next(
            row["observed"]["decision"] == COMMIT
            for row in rows
            if row["case_id"] == "matched_legitimate_twin"
        ),
        "unrelated_untrusted_addition_committed": next(
            row["observed"]["decision"] == COMMIT
            for row in rows
            if row["case_id"] == "unrelated_untrusted_addition_does_not_block"
        ),
        "blocked_rows_invoked_effect": any(
            row["effect_invocation_count"] != 0
            for row in rows
            if row["observed"]["decision"] != COMMIT
        ),
        "injection_text_visible_to_gate": False,
        "attack_label_visible_to_gate": False,
        "claim_boundary": (
            "Synthetic deterministic consequence suite; no live model or published "
            "attack implementation is claimed."
        ),
        "rows": rows,
    }
