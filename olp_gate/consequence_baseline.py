"""Conventional permission validation for the SQLite consequence experiment.

The baseline uses the same portable, signed Verified Commit decision, trust
anchors, canonical action hashes, and one-use code as the OpenLine adapter.
Reusing the existing cryptographic verifier avoids comparing against weaker
authorization or maintaining a second signature implementation. This module
is pure: the shared SQLite transaction kernel must additionally enforce
current owner/subject authority, revocation, receiver policy, evidence and
site freshness, unique consumption/idempotency, mutation, and signed audit
records. Calling this validator alone does not authorize a side effect.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from .adapters import parse_timestamp
from .gateway import verify_decision_receipt
from .verified_commit import (
    VerifiedCommitError,
    _action_hash,
    _normalize_execution_action,
    one_use_code_hash,
)


def validate_permission(
    receipt: Mapping[str, Any],
    action: Mapping[str, Any],
    *,
    one_use_code: str,
    trusted_gate_keys: Sequence[str],
    now: datetime,
) -> list[str]:
    """Return sorted refusal reasons without reading or mutating local state.

    An empty result establishes only signed, exact-action permission at
    ``now``; transaction-local checks and uniqueness remain mandatory.
    """

    if not isinstance(receipt, Mapping):
        return ["decision_receipt_invalid:receipt_not_mapping"]

    errors: list[str] = []
    try:
        decision_check = verify_decision_receipt(receipt, trusted_gate_keys)
    except Exception as exc:
        # Malformed untrusted structures must fail closed, including shapes
        # the existing verifier does not yet turn into structured errors.
        errors.append(f"decision_receipt_invalid:verification_error:{type(exc).__name__}")
    else:
        errors.extend(
            f"decision_receipt_invalid:{error}"
            for error in decision_check.get("errors", [])
        )
        if not decision_check.get("valid") and not decision_check.get("errors"):
            errors.append("decision_receipt_invalid:verification_failed")

    if receipt.get("decision") != "COMMIT" or receipt.get("verdict") != "VERIFIED":
        errors.append("decision_not_commit")
    authorization = receipt.get("commit_authorization")
    if not isinstance(authorization, Mapping):
        errors.append("commit_authorization_missing")
        authorization = {}

    try:
        binding, action_errors = _normalize_execution_action(action)
    except Exception as exc:
        binding = None
        action_errors = [f"execution_action_invalid:{type(exc).__name__}"]
    errors.extend(action_errors)
    if binding is not None and authorization:
        comparisons = {
            "tool": "tool_mismatch",
            "target": "target_mismatch",
            "settings_hash": "settings_mismatch",
            "run_id": "run_mismatch",
            "capsule_hash": "capsule_mismatch",
            "evidence_hashes": "evidence_mismatch",
            "policy_hash": "policy_mismatch",
        }
        for field, reason in comparisons.items():
            if binding.get(field) != authorization.get(field):
                errors.append(reason)
        if _action_hash(binding) != authorization.get("action_hash"):
            errors.append("action_hash_mismatch")

    try:
        supplied_code_hash = one_use_code_hash(one_use_code)
    except VerifiedCommitError:
        errors.append("one_use_code_invalid")
    else:
        expected_code_hash = authorization.get("one_use_code_hash")
        if (
            not isinstance(expected_code_hash, str)
            or not expected_code_hash.isascii()
            or not hmac.compare_digest(supplied_code_hash, expected_code_hash)
        ):
            errors.append("one_use_code_mismatch")

    expiry = parse_timestamp(authorization.get("expires_at"))
    created = parse_timestamp(receipt.get("created_at"))
    if expiry is None:
        errors.append("authorization_expiry_invalid")
    if created is None:
        errors.append("decision_timestamp_invalid")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        errors.append("validation_time_invalid")
    else:
        if expiry is not None and now >= expiry:
            errors.append("authorization_expired")
        if created is not None and created > now:
            errors.append("decision_created_in_future")

    return sorted(set(errors))
