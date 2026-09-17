"""Application scope profile ``principal-mandates-v1``.

The profile predicate: an effect is in scope iff it was admitted under a
currently-valid mandate whose ``principal_id`` equals the capability
issuer's ``owner_id``. Attenuation is moot — there is no delegation, so
there is nothing to narrow.

Amount derivation (explicit, never inferred): the v1 profile accounts
``value_cents`` effects against ``unit == "cents", scale == 0``
capabilities. A scale is never inferred (§4.1); any other unit simply
does not apply to value_cents effects.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Mapping

SCOPE_PROFILE = "principal-mandates-v1"
UNIT_CENTS = "cents"


class ScopeError(ValueError):
    """Raised when an effect is outside the capability's scope."""


def derive_amount(effect: Mapping[str, Any], capability: Mapping[str, Any]) -> int | None:
    """Consumption amount for an admitted effect, or None if the profile
    does not account this effect kind."""
    if capability.get("unit") != UNIT_CENTS or capability.get("scale") != 0:
        return None
    value = effect.get("value_cents")
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return None
    return value


def in_scope(preflight: Mapping[str, Any], capability: Mapping[str, Any]) -> bool:
    """True iff the preflight admitted the effect and its principal is the
    capability's issuer owner."""
    if not isinstance(preflight, Mapping) or preflight.get("allowed") is not True:
        return False
    evidence = preflight.get("evidence")
    if not isinstance(evidence, Mapping):
        return False
    return evidence.get("principal_id") == capability["issuer_owner_id"]


def check_no_double_admission(
    conn: sqlite3.Connection,
    capability_id: str,
    exercise_action_digest: str,
    op_id: str,
) -> None:
    """Refuse a second live reservation for the same admitted action.

    (With one capability per principal this is structural, but an executor
    double-submit must still fail loudly rather than double-reserve.)
    """
    cur = conn.execute(
        "SELECT op_id FROM operations WHERE capability_id = ?"
        " AND exercise_action_digest = ?"
        " AND state IN ('reserved','provider_entered','indeterminate')"
        " AND op_id != ?",
        (capability_id, exercise_action_digest, op_id),
    )
    if cur.fetchone() is not None:
        raise ScopeError("duplicate_action_reservation")
