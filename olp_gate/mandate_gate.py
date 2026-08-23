"""Consequence-time enforcement for principal_mandate/v1.

This is a thin composition layer over Mandate Gate 001 and Verified Commit.
It does not issue a new receipt family.

The wrapper re-evaluates the reusable principal mandate immediately before
VerifiedCommitLedger invokes the executor. That makes the mandate receiver-owned
at consequence time rather than trusting the producer to have called the
Mandate Gate compiler correctly.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence, TypeVar

from .mandate import (
    MandateSpec,
    assess_effect,
    validate_effect,
)
from .verified_commit import VerifiedCommitLedger, VerifiedCommitError

MANDATED_EFFECT_PROFILE = "principal_mandate_effect/v1"
T = TypeVar("T")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def mandate_preflight(
    mandate_value: MandateSpec | Mapping[str, Any],
    settings: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Recompute mandate fit from the exact settings about to execute."""
    if not isinstance(settings, Mapping):
        return {
            "allowed": False,
            "reason_codes": ["mandate_settings_invalid"],
            "evidence": {"profile": MANDATED_EFFECT_PROFILE},
        }
    if settings.get("profile") != MANDATED_EFFECT_PROFILE:
        return {
            "allowed": False,
            "reason_codes": ["mandate_settings_profile_invalid"],
            "evidence": {"profile": str(settings.get("profile"))},
        }

    raw_effect = settings.get("effect")
    if not isinstance(raw_effect, Mapping):
        return {
            "allowed": False,
            "reason_codes": ["mandate_effect_missing"],
            "evidence": {"profile": MANDATED_EFFECT_PROFILE},
        }

    try:
        mandate = (
            mandate_value
            if isinstance(mandate_value, MandateSpec)
            else MandateSpec.from_mapping(mandate_value)
        )
        effect = validate_effect(raw_effect)
        assessment = assess_effect(
            mandate,
            effect,
            now=now or _utc_now(),
        )
    except (TypeError, ValueError) as exc:
        return {
            "allowed": False,
            "reason_codes": [f"mandate_validation_error:{type(exc).__name__}"],
            "evidence": {"profile": MANDATED_EFFECT_PROFILE},
        }

    reasons = list(assessment["reason_codes"])
    if settings.get("mandate_hash") != assessment["mandate_hash"]:
        reasons.append("mandate_hash_mismatch")
    if settings.get("effect_hash") != assessment["effect_hash"]:
        reasons.append("effect_hash_mismatch")

    allowed = assessment["allowed"] is True and not reasons
    return {
        "allowed": allowed,
        "reason_codes": sorted(set(reasons)),
        "evidence": {
            "profile": MANDATED_EFFECT_PROFILE,
            "mandate_hash": assessment["mandate_hash"],
            "effect_hash": assessment["effect_hash"],
            "principal_id": effect["principal_id"],
            "mandate_id": effect["mandate_id"],
        },
    }


def execute_mandated_once(
    ledger: VerifiedCommitLedger,
    receipt: Mapping[str, Any],
    action: Mapping[str, Any],
    *,
    mandate: MandateSpec | Mapping[str, Any],
    one_use_code: str,
    trusted_gate_keys: Sequence[str],
    executor: Callable[[], T],
    now: datetime | None = None,
    attempt_label: str | None = None,
) -> dict[str, Any]:
    """Consume exact Verified Commit permission and re-check mandate before effect.

    VerifiedCommitLedger consumes the one-use authorization before it invokes
    this receiver-owned preflight. A failed mandate check therefore cannot be
    retried with the same authorization.
    """
    settings = action.get("settings")
    if not isinstance(settings, Mapping):
        raise VerifiedCommitError("mandate_execution_settings_invalid")

    check_time = now or _utc_now()

    return ledger.execute_once(
        receipt,
        action,
        one_use_code=one_use_code,
        trusted_gate_keys=trusted_gate_keys,
        executor=executor,
        preflight=lambda: mandate_preflight(
            mandate,
            settings,
            now=check_time,
        ),
        now=check_time,
        attempt_label=attempt_label,
    )
