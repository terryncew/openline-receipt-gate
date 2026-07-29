"""Receiver-owned x402 settlement checks for Verified Commit.

This module is a narrow transaction adapter, not an x402 facilitator and not a
new receipt family.  The existing COMMIT authorization binds the complete
normalized settings object.  The airlock then applies the signed receiver
policy, obtains a fresh receiver-owned state snapshot immediately before the
settlement callback, and withholds resource release until a matching settlement
confirmation is supplied.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, TypeVar

from .adapters import parse_timestamp
from .crypto import (
    UnsupportedCanonicalValue,
    olp_canonical_json,
    sha256_hex,
)
from .verified_commit import VerifiedCommitError, VerifiedCommitLedger


X402_AIRLOCK_PROFILE = "x402_transaction_airlock/v1"
X402_POLICY_PROFILE = "x402_receiver_policy/v1"
X402_SNAPSHOT_PROFILE = "x402_receiver_snapshot/v1"
X402_CONFIRMATION_PROFILE = "x402_settlement_confirmation/v1"
X402_RELEASE_REQUEST_PROFILE = "x402_resource_release_request/v1"
X402_RELEASE_RESULT_PROFILE = "x402_resource_release_result/v1"

_SETTINGS_KEYS = {
    "profile",
    "requirements",
    "payment",
    "execution",
    "verification",
}
_REQUIREMENT_KEYS = {
    "scheme",
    "network",
    "asset",
    "amount_atomic",
    "pay_to",
    "resource",
}
_PAYMENT_KEYS = {
    "scheme",
    "network",
    "asset",
    "amount_atomic",
    "recipient",
    "payer",
    "signature_model",
    "authorization_hash",
    "valid_after",
    "valid_before",
    "nonce",
}
_EXECUTION_KEYS = {
    "template_id",
    "program",
    "instructions",
    "accounts",
    "signers",
    "fee_atomic",
    "gas",
    "compute_units",
}
_VERIFICATION_KEYS = {"context_hash", "verified_at"}
_POLICY_KEYS = {
    "profile",
    "allowed_schemes",
    "allowed_networks",
    "allowed_assets",
    "allowed_recipients",
    "allowed_signature_models",
    "allowed_templates",
    "min_amount_atomic",
    "max_amount_atomic",
    "max_fee_atomic",
    "max_gas",
    "max_compute_units",
    "min_remaining_validity_seconds",
    "max_snapshot_age_seconds",
}
_TEMPLATE_KEYS = {
    "template_id",
    "program",
    "instructions",
    "accounts",
    "signers",
}
_SNAPSHOT_KEYS = {
    "profile",
    "checked_at",
    "verification_context_hash",
    "requirements_hash",
    "payment_hash",
    "authorization_hash",
    "authorization_authentic",
    "nonce_unused",
    "payer_balance_atomic",
    "settleable",
}
_CONFIRMATION_KEYS = {
    "profile",
    "confirmed",
    "transaction_hash",
    "network",
    "asset",
    "amount_atomic",
    "recipient",
    "nonce",
}
_RELEASE_RESULT_KEYS = {
    "profile",
    "released",
    "target",
    "transaction_hash",
}
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
T = TypeVar("T")


class X402AirlockError(VerifiedCommitError):
    """Raised when an x402 transaction adapter input is malformed."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _is_int(value: Any, *, minimum: int = 0) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= minimum
    )


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and _HEX_256.fullmatch(value) is not None


def _string_list(
    value: Any,
    *,
    allow_empty: bool = False,
) -> tuple[list[str], bool]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or not all(isinstance(item, str) and item for item in value)
        or len(set(value)) != len(value)
    ):
        return [], False
    return list(value), True


def _canonical_hash(value: Mapping[str, Any]) -> str:
    return sha256_hex(olp_canonical_json(dict(value)))


def requirements_hash(settings: Mapping[str, Any]) -> str:
    requirements = settings.get("requirements")
    if not isinstance(requirements, Mapping):
        raise X402AirlockError("x402_requirements_invalid")
    return _canonical_hash(requirements)


def payment_hash(settings: Mapping[str, Any]) -> str:
    payment = settings.get("payment")
    if not isinstance(payment, Mapping):
        raise X402AirlockError("x402_payment_invalid")
    return _canonical_hash(payment)


def payment_replay_scope_hash(settings: Mapping[str, Any]) -> str:
    """Hash the receiver-owned nonce namespace for atomic replay defense."""

    payment = settings.get("payment")
    if not isinstance(payment, Mapping):
        raise X402AirlockError("x402_payment_invalid")
    scope = {
        "profile": X402_AIRLOCK_PROFILE,
        "scheme": payment.get("scheme"),
        "network": payment.get("network"),
        "asset": payment.get("asset"),
        "payer": payment.get("payer"),
        "signature_model": payment.get("signature_model"),
        "nonce": payment.get("nonce"),
    }
    if not all(isinstance(value, str) and value for value in scope.values()):
        raise X402AirlockError("x402_payment_replay_scope_invalid")
    return _canonical_hash(scope)


def verification_context_hash(
    settings: Mapping[str, Any],
    *,
    verified_at: str,
) -> str:
    return _canonical_hash(
        {
            "profile": X402_AIRLOCK_PROFILE,
            "requirements_hash": requirements_hash(settings),
            "payment_hash": payment_hash(settings),
            "verified_at": verified_at,
        }
    )


def _validated_policy(
    value: Any,
) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(value, Mapping):
        return None, ["x402_policy_missing"]
    policy = dict(value)
    errors: list[str] = []
    if set(policy) != _POLICY_KEYS:
        errors.append("x402_policy_shape_invalid")
    if policy.get("profile") != X402_POLICY_PROFILE:
        errors.append("x402_policy_profile_invalid")
    for name in (
        "allowed_schemes",
        "allowed_networks",
        "allowed_assets",
        "allowed_recipients",
        "allowed_signature_models",
    ):
        normalized, valid = _string_list(policy.get(name))
        if not valid:
            errors.append(f"x402_policy_{name}_invalid")
        policy[name] = normalized

    templates = policy.get("allowed_templates")
    normalized_templates: list[dict[str, Any]] = []
    if not isinstance(templates, list) or not templates:
        errors.append("x402_policy_allowed_templates_invalid")
    else:
        for template in templates:
            if not isinstance(template, Mapping):
                errors.append("x402_policy_template_invalid")
                continue
            item = dict(template)
            if set(item) != _TEMPLATE_KEYS:
                errors.append("x402_policy_template_shape_invalid")
            for name in ("template_id", "program"):
                if not isinstance(item.get(name), str) or not item.get(name):
                    errors.append(f"x402_policy_template_{name}_invalid")
            for name in ("instructions", "accounts", "signers"):
                normalized, valid = _string_list(item.get(name))
                if not valid:
                    errors.append(
                        f"x402_policy_template_{name}_invalid"
                    )
                item[name] = normalized
            normalized_templates.append(item)
    policy["allowed_templates"] = normalized_templates

    for name in (
        "min_amount_atomic",
        "max_amount_atomic",
        "max_fee_atomic",
        "max_gas",
        "max_compute_units",
        "min_remaining_validity_seconds",
        "max_snapshot_age_seconds",
    ):
        if not _is_int(policy.get(name)):
            errors.append(f"x402_policy_{name}_invalid")
    if (
        _is_int(policy.get("min_amount_atomic"))
        and _is_int(policy.get("max_amount_atomic"))
        and policy["max_amount_atomic"] < policy["min_amount_atomic"]
    ):
        errors.append("x402_policy_amount_range_invalid")
    return policy, sorted(set(errors))


def _template_view(execution: Mapping[str, Any]) -> dict[str, Any]:
    return {name: execution.get(name) for name in _TEMPLATE_KEYS}


def validate_x402_issue(
    settings_value: Any,
    policy_value: Any,
    *,
    now: datetime,
) -> list[str]:
    """Validate the frozen transaction shape and signed receiver policy."""

    errors: list[str] = []
    policy, policy_errors = _validated_policy(policy_value)
    errors.extend(policy_errors)
    if policy_errors:
        policy = None
    if not isinstance(settings_value, Mapping):
        return sorted(set(errors + ["x402_settings_invalid"]))
    settings = dict(settings_value)
    if set(settings) != _SETTINGS_KEYS:
        errors.append("x402_settings_shape_invalid")
    if settings.get("profile") != X402_AIRLOCK_PROFILE:
        errors.append("x402_settings_profile_invalid")

    requirements_value = settings.get("requirements")
    payment_value = settings.get("payment")
    execution_value = settings.get("execution")
    verification_value = settings.get("verification")
    if not isinstance(requirements_value, Mapping):
        errors.append("x402_requirements_invalid")
        requirements: dict[str, Any] = {}
    else:
        requirements = dict(requirements_value)
        if set(requirements) != _REQUIREMENT_KEYS:
            errors.append("x402_requirements_shape_invalid")
    if not isinstance(payment_value, Mapping):
        errors.append("x402_payment_invalid")
        payment: dict[str, Any] = {}
    else:
        payment = dict(payment_value)
        if set(payment) != _PAYMENT_KEYS:
            errors.append("x402_payment_shape_invalid")
    if not isinstance(execution_value, Mapping):
        errors.append("x402_execution_invalid")
        execution: dict[str, Any] = {}
    else:
        execution = dict(execution_value)
        if set(execution) != _EXECUTION_KEYS:
            errors.append("x402_execution_shape_invalid")
    if not isinstance(verification_value, Mapping):
        errors.append("x402_verification_invalid")
        verification: dict[str, Any] = {}
    else:
        verification = dict(verification_value)
        if set(verification) != _VERIFICATION_KEYS:
            errors.append("x402_verification_shape_invalid")

    for name in ("scheme", "network", "asset", "pay_to", "resource"):
        if not isinstance(requirements.get(name), str) or not requirements.get(
            name
        ):
            errors.append(f"x402_requirement_{name}_invalid")
    if not _is_int(requirements.get("amount_atomic"), minimum=1):
        errors.append("sr5_amount_not_positive")

    for name in (
        "scheme",
        "network",
        "asset",
        "recipient",
        "payer",
        "signature_model",
        "nonce",
    ):
        if not isinstance(payment.get(name), str) or not payment.get(name):
            errors.append(f"x402_payment_{name}_invalid")
    if not _is_hash(payment.get("authorization_hash")):
        errors.append("x402_payment_authorization_hash_invalid")
    if not _is_int(payment.get("amount_atomic"), minimum=1):
        errors.append("sr5_amount_not_positive")

    comparisons = {
        "scheme": ("scheme", "scheme"),
        "network": ("network", "network"),
        "asset": ("asset", "asset"),
        "amount": ("amount_atomic", "amount_atomic"),
        "recipient": ("pay_to", "recipient"),
    }
    for label, (requirement_name, payment_name) in comparisons.items():
        if requirements.get(requirement_name) != payment.get(payment_name):
            errors.append(f"sr1_{label}_mismatch")

    for name in ("template_id", "program"):
        if not isinstance(execution.get(name), str) or not execution.get(name):
            errors.append(f"x402_execution_{name}_invalid")
    for name in ("instructions", "accounts", "signers"):
        normalized, valid = _string_list(execution.get(name))
        if not valid:
            errors.append(f"x402_execution_{name}_invalid")
        execution[name] = normalized
    for name in ("fee_atomic", "gas", "compute_units"):
        if not _is_int(execution.get(name)):
            errors.append(f"x402_execution_{name}_invalid")

    valid_after = parse_timestamp(payment.get("valid_after"))
    valid_before = parse_timestamp(payment.get("valid_before"))
    verified_at = parse_timestamp(verification.get("verified_at"))
    if valid_after is None or valid_before is None:
        errors.append("sr3_validity_window_invalid")
    else:
        if valid_after > now:
            errors.append("sr3_authorization_not_yet_valid")
        if valid_before <= now:
            errors.append("sr3_authorization_expired")
        if valid_before <= valid_after:
            errors.append("sr3_validity_window_invalid")
    if verified_at is None or verified_at > now:
        errors.append("x402_verification_time_invalid")
    try:
        expected_context = verification_context_hash(
            settings,
            verified_at=str(verification.get("verified_at", "")),
        )
    except (TypeError, X402AirlockError, UnsupportedCanonicalValue):
        expected_context = ""
        errors.append("x402_verification_context_uncomputable")
    if (
        not _is_hash(verification.get("context_hash"))
        or verification.get("context_hash") != expected_context
    ):
        errors.append("sr7_verification_context_mismatch")

    if policy is not None:
        membership = {
            "sr1_scheme_not_allowed": (
                requirements.get("scheme"),
                policy["allowed_schemes"],
            ),
            "sr1_network_not_allowed": (
                requirements.get("network"),
                policy["allowed_networks"],
            ),
            "sr1_asset_not_allowed": (
                requirements.get("asset"),
                policy["allowed_assets"],
            ),
            "sr1_recipient_not_allowed": (
                requirements.get("pay_to"),
                policy["allowed_recipients"],
            ),
            "sr2_signature_model_not_allowed": (
                payment.get("signature_model"),
                policy["allowed_signature_models"],
            ),
        }
        for reason, (observed, allowed) in membership.items():
            if observed not in allowed:
                errors.append(reason)
        amount = requirements.get("amount_atomic")
        if _is_int(amount):
            if amount < policy["min_amount_atomic"]:
                errors.append("sr5_amount_below_receiver_minimum")
            if amount > policy["max_amount_atomic"]:
                errors.append("sr5_amount_above_receiver_maximum")
        cost_bounds = {
            "fee_atomic": (
                policy["max_fee_atomic"],
                "sr6_fee_limit_exceeded",
            ),
            "gas": (policy["max_gas"], "sr6_gas_limit_exceeded"),
            "compute_units": (
                policy["max_compute_units"],
                "sr6_compute_limit_exceeded",
            ),
        }
        for name, (limit, reason) in cost_bounds.items():
            observed = execution.get(name)
            if _is_int(observed) and observed > limit:
                errors.append(reason)
        if _template_view(execution) not in policy["allowed_templates"]:
            errors.append("sr8_execution_template_not_allowed")
        if valid_before is not None:
            remaining = (valid_before - now).total_seconds()
            if remaining < policy["min_remaining_validity_seconds"]:
                errors.append("sr5_freshness_bound_too_short")
    return sorted(set(errors))


def evaluate_x402_preflight(
    settings_value: Any,
    policy_value: Any,
    snapshot_value: Any,
    *,
    now: datetime,
) -> dict[str, Any]:
    """Revalidate mutable conditions at the receiver's settlement boundary."""

    errors = validate_x402_issue(settings_value, policy_value, now=now)
    policy, policy_errors = _validated_policy(policy_value)
    errors.extend(policy_errors)
    if policy_errors:
        policy = None
    if not isinstance(settings_value, Mapping):
        settings: dict[str, Any] = {}
    else:
        settings = dict(settings_value)
    if not isinstance(snapshot_value, Mapping):
        snapshot: dict[str, Any] = {}
        errors.append("sr7_receiver_snapshot_missing")
    else:
        snapshot = dict(snapshot_value)
        if set(snapshot) != _SNAPSHOT_KEYS:
            errors.append("sr7_receiver_snapshot_shape_invalid")
    if snapshot.get("profile") != X402_SNAPSHOT_PROFILE:
        errors.append("sr7_receiver_snapshot_profile_invalid")
    checked_at = parse_timestamp(snapshot.get("checked_at"))
    if checked_at is None:
        errors.append("sr7_receiver_snapshot_time_invalid")
    elif checked_at > now:
        errors.append("sr7_receiver_snapshot_from_future")
    elif (
        policy is not None
        and (now - checked_at).total_seconds()
        > policy["max_snapshot_age_seconds"]
    ):
        errors.append("sr7_receiver_snapshot_stale")

    verification = settings.get("verification", {})
    payment = settings.get("payment", {})
    if not isinstance(verification, Mapping):
        verification = {}
    if not isinstance(payment, Mapping):
        payment = {}
    try:
        expected_requirements_hash = requirements_hash(settings)
        expected_payment_hash = payment_hash(settings)
    except (TypeError, X402AirlockError, UnsupportedCanonicalValue):
        expected_requirements_hash = ""
        expected_payment_hash = ""
        errors.append("sr7_revalidation_binding_uncomputable")
    bindings = {
        "verification_context_hash": (
            verification.get("context_hash"),
            "sr7_verification_context_diverged",
        ),
        "requirements_hash": (
            expected_requirements_hash,
            "sr7_requirements_context_diverged",
        ),
        "payment_hash": (
            expected_payment_hash,
            "sr7_payment_context_diverged",
        ),
        "authorization_hash": (
            payment.get("authorization_hash"),
            "sr2_authorization_hash_mismatch",
        ),
    }
    for name, (expected, reason) in bindings.items():
        if snapshot.get(name) != expected:
            errors.append(reason)
    for name, reason in (
        ("authorization_authentic", "sr2_authorization_not_authentic"),
        ("nonce_unused", "sr5_nonce_already_used"),
        ("settleable", "sr5_payment_not_settleable"),
    ):
        value = snapshot.get(name)
        if not isinstance(value, bool):
            errors.append(f"sr7_{name}_invalid")
        elif value is not True:
            errors.append(reason)
    balance = snapshot.get("payer_balance_atomic")
    amount = payment.get("amount_atomic")
    if not _is_int(balance):
        errors.append("sr7_payer_balance_invalid")
    elif _is_int(amount) and balance < amount:
        errors.append("sr5_insufficient_balance")

    evidence = {
        "profile": X402_SNAPSHOT_PROFILE,
        "checked_at": snapshot.get("checked_at"),
        "verification_context_hash": snapshot.get(
            "verification_context_hash"
        ),
        "requirements_hash": snapshot.get("requirements_hash"),
        "payment_hash": snapshot.get("payment_hash"),
        "authorization_hash": snapshot.get("authorization_hash"),
        "authorization_authentic": snapshot.get(
            "authorization_authentic"
        ),
        "nonce_unused": snapshot.get("nonce_unused"),
        "payer_balance_atomic": snapshot.get("payer_balance_atomic"),
        "settleable": snapshot.get("settleable"),
    }
    return {
        "allowed": not errors,
        "reason_codes": sorted(set(errors)),
        "evidence": evidence,
    }


def _policy_from_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    policy = receipt.get("policy")
    snapshot = policy.get("snapshot") if isinstance(policy, Mapping) else None
    metadata = (
        snapshot.get("metadata") if isinstance(snapshot, Mapping) else None
    )
    raw = (
        metadata.get("x402_airlock")
        if isinstance(metadata, Mapping)
        else None
    )
    validated, errors = _validated_policy(raw)
    if errors or validated is None:
        raise X402AirlockError(
            "x402_policy_invalid:" + ",".join(sorted(set(errors)))
        )
    return validated


def _confirmation_result(
    settings: Mapping[str, Any],
    value: Any,
    settlement_result: Any,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return {}, ["sr4_settlement_confirmation_missing"]
    raw_confirmation = dict(value)
    confirmation = {
        name: raw_confirmation.get(name) for name in _CONFIRMATION_KEYS
    }
    if set(raw_confirmation) != _CONFIRMATION_KEYS:
        errors.append("sr4_settlement_confirmation_shape_invalid")
    if confirmation.get("profile") != X402_CONFIRMATION_PROFILE:
        errors.append("sr4_settlement_confirmation_profile_invalid")
    if confirmation.get("confirmed") is not True:
        errors.append("sr4_settlement_not_confirmed")
    if not _is_hash(confirmation.get("transaction_hash")):
        errors.append("sr4_transaction_hash_invalid")
    if not isinstance(settlement_result, Mapping):
        settlement_transaction_hash = None
        errors.append("sr4_settlement_result_invalid")
    else:
        settlement_transaction_hash = settlement_result.get(
            "transaction_hash"
        )
        if not _is_hash(settlement_transaction_hash):
            errors.append("sr4_settlement_result_transaction_hash_invalid")
    if (
        _is_hash(confirmation.get("transaction_hash"))
        and _is_hash(settlement_transaction_hash)
        and confirmation.get("transaction_hash")
        != settlement_transaction_hash
    ):
        errors.append("sr4_settlement_transaction_hash_mismatch")
    payment = settings.get("payment")
    if not isinstance(payment, Mapping):
        payment = {}
    for name in ("network", "asset", "amount_atomic", "recipient", "nonce"):
        if confirmation.get(name) != payment.get(name):
            errors.append(f"sr4_settlement_{name}_mismatch")
    return confirmation, sorted(set(errors))


def _release_confirmation(
    action: Mapping[str, Any],
    confirmation: Mapping[str, Any],
    value: Any,
) -> tuple[dict[str, Any], list[str]]:
    if not isinstance(value, Mapping):
        return {}, ["resource_release_result_missing"]
    raw_release = dict(value)
    release = {name: raw_release.get(name) for name in _RELEASE_RESULT_KEYS}
    errors: list[str] = []
    if set(raw_release) != _RELEASE_RESULT_KEYS:
        errors.append("resource_release_result_shape_invalid")
    if release.get("profile") != X402_RELEASE_RESULT_PROFILE:
        errors.append("resource_release_result_profile_invalid")
    if release.get("released") is not True:
        errors.append("resource_release_not_confirmed")
    if release.get("target") != action.get("target"):
        errors.append("resource_release_target_mismatch")
    if (
        release.get("transaction_hash")
        != confirmation.get("transaction_hash")
    ):
        errors.append("resource_release_transaction_hash_mismatch")
    return release, sorted(set(errors))


def execute_x402_once(
    ledger: VerifiedCommitLedger,
    receipt: Mapping[str, Any],
    action: Mapping[str, Any],
    *,
    one_use_code: str,
    trusted_gate_keys: Sequence[str],
    snapshot_provider: Callable[[], Mapping[str, Any]],
    settlement_executor: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    confirmation_provider: Callable[
        [Mapping[str, Any]], Mapping[str, Any]
    ],
    release_executor: Callable[[Mapping[str, Any]], T] | None = None,
    now: datetime | None = None,
    attempt_label: str | None = None,
) -> dict[str, Any]:
    """Authorize, freshly revalidate, settle, confirm, then optionally release."""

    check_time = now or _utc_now()
    settings_value = action.get("settings")
    if isinstance(settings_value, Mapping):
        try:
            settings = json.loads(json.dumps(settings_value))
        except (TypeError, ValueError):
            settings = {}
    else:
        settings = {}
    try:
        replay_scope_hash = payment_replay_scope_hash(settings)
    except (TypeError, X402AirlockError, UnsupportedCanonicalValue):
        # Supplying an invalid digest makes the atomic ledger reject the
        # attempt even if an independently malformed receipt reached here.
        replay_scope_hash = ""
    try:
        policy = _policy_from_receipt(receipt)
    except X402AirlockError as exc:
        # The generic decision verifier will independently reject a tampered
        # policy.  Supplying a deterministic denied preflight keeps the
        # destination effect fail closed if the policy is merely malformed.
        policy = {}
        policy_error = str(exc)
    else:
        policy_error = None

    def preflight() -> Mapping[str, Any]:
        if policy_error is not None:
            return {
                "allowed": False,
                "reason_codes": [policy_error],
                "evidence": {"policy_valid": False},
            }
        snapshot = snapshot_provider()
        appraisal_time = check_time if now is not None else _utc_now()
        return evaluate_x402_preflight(
            settings,
            policy,
            snapshot,
            now=appraisal_time,
        )

    settlement_calls = 0

    def settle() -> Mapping[str, Any]:
        nonlocal settlement_calls
        settlement_calls += 1
        result = settlement_executor(json.loads(json.dumps(settings)))
        if not isinstance(result, Mapping):
            raise X402AirlockError("settlement_result_invalid")
        return dict(result)

    result = ledger.execute_once(
        receipt,
        action,
        one_use_code=one_use_code,
        trusted_gate_keys=trusted_gate_keys,
        executor=settle,
        preflight=preflight,
        replay_scope_hash=replay_scope_hash,
        now=check_time,
        attempt_label=attempt_label,
    )
    if not result.get("authorized"):
        return {
            **result,
            "settlement_executed": settlement_calls == 1,
            "settlement_confirmed": False,
            "resource_released": False,
        }

    settlement_result = result.get("tool_result")
    try:
        raw_confirmation = confirmation_provider(settlement_result)
        confirmation, confirmation_errors = _confirmation_result(
            settings,
            raw_confirmation,
            settlement_result,
        )
    except BaseException as exc:
        confirmation: dict[str, Any] = {}
        confirmation_errors = [
            f"sr4_confirmation_provider_error:{type(exc).__name__}"
        ]
    postcondition = {
        "confirmation_valid": not confirmation_errors,
        "confirmation_transaction_hash": (
            confirmation.get("transaction_hash")
            if _is_hash(confirmation.get("transaction_hash"))
            else None
        ),
        "settlement_result_hash": result.get("tool_result_hash"),
    }
    postcondition_hash = ledger.record_postcondition(
        str(result["attempt_id"]),
        status=(
            "settlement_confirmed"
            if not confirmation_errors
            else "settlement_unconfirmed"
        ),
        evidence=postcondition,
        reason_codes=confirmation_errors,
    )
    if confirmation_errors:
        return {
            **result,
            "reason_codes": confirmation_errors,
            "settlement_executed": True,
            "settlement_confirmed": False,
            "resource_released": False,
            "postcondition_evidence_hash": postcondition_hash,
        }

    if release_executor is None:
        release_result = None
        released = False
        release_errors: list[str] = []
    else:
        release_request = {
            "profile": X402_RELEASE_REQUEST_PROFILE,
            "target": action.get("target"),
            "confirmation": json.loads(json.dumps(confirmation)),
        }
        try:
            raw_release_result = release_executor(release_request)
            release_result, release_errors = _release_confirmation(
                action,
                confirmation,
                raw_release_result,
            )
        except BaseException as exc:
            release_result = None
            release_errors = [
                f"resource_release_error:{type(exc).__name__}"
            ]
        released = not release_errors
        release_postcondition = {
            "confirmation_transaction_hash": confirmation.get(
                "transaction_hash"
            ),
            "settlement_result_hash": result.get("tool_result_hash"),
            "release_result_valid": released,
            "release_reason_codes": release_errors,
        }
        postcondition_hash = ledger.record_postcondition(
            str(result["attempt_id"]),
            status=(
                "resource_release_confirmed"
                if released
                else "resource_release_unconfirmed"
            ),
            evidence=release_postcondition,
            reason_codes=release_errors,
        )
    return {
        **result,
        "reason_codes": release_errors,
        "settlement_executed": True,
        "settlement_confirmed": True,
        "resource_released": released,
        "release_result": release_result,
        "postcondition_evidence_hash": postcondition_hash,
    }


__all__ = [
    "X402_AIRLOCK_PROFILE",
    "X402_POLICY_PROFILE",
    "X402_SNAPSHOT_PROFILE",
    "X402_CONFIRMATION_PROFILE",
    "X402_RELEASE_REQUEST_PROFILE",
    "X402_RELEASE_RESULT_PROFILE",
    "X402AirlockError",
    "evaluate_x402_preflight",
    "execute_x402_once",
    "payment_hash",
    "payment_replay_scope_hash",
    "requirements_hash",
    "validate_x402_issue",
    "verification_context_hash",
]
