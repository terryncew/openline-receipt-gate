"""Capability hook for the existing consequence path.

This module wraps — never modifies — the existing admission machinery.
``reserve_for_effect`` runs after ``mandate_preflight`` allows an effect
and before it executes; ``settle_for`` runs after the outcome is known.
The mandate remains the sole admission authority: this layer can only
narrow (refuse on budget grounds), never widen. A principal with no
active capability proceeds exactly as before (additive, opt-in).
"""
from __future__ import annotations

import sqlite3
from typing import Any, Mapping

from . import capability_lifecycle as lifecycle
from . import capability_scope as scope
from . import capability_store as store
from .crypto import olp_canonical_json, sha256_hex


def reserve_for_effect(
    conn: sqlite3.Connection,
    preflight: Mapping[str, Any],
    effect: Mapping[str, Any],
    *,
    op_id: str,
    now_unix: int,
    entry_ttl: int = lifecycle.DEFAULT_ENTRY_TTL,
) -> dict[str, Any]:
    """Reserve budget for an admitted effect.

    Returns ``{"allowed": True, "capability": None}`` when no capability
    accounting applies, ``{"allowed": False, ...}`` on denial or budget
    refusal, else the reservation (including the one-time token).
    """
    if not isinstance(preflight, Mapping) or preflight.get("allowed") is not True:
        return {
            "allowed": False,
            "reason_codes": list(preflight.get("reason_codes", ["mandate_denied"])),
            "capability": None,
        }
    principal_id = preflight["evidence"]["principal_id"]
    cap = store.active_capability_for(conn, principal_id, now_unix)
    if cap is None:
        return {"allowed": True, "reason_codes": [], "capability": None}
    if not scope.in_scope(preflight, cap):
        return {
            "allowed": False,
            "reason_codes": ["capability_scope_mismatch"],
            "capability": None,
        }
    amount = scope.derive_amount(effect, cap)
    if amount is None:
        return {"allowed": True, "reason_codes": [], "capability": None}
    action_digest = sha256_hex(olp_canonical_json(dict(effect)))
    mandate_hash = str(preflight["evidence"].get("mandate_hash") or "")
    try:
        scope.check_no_double_admission(conn, cap["capability_id"], action_digest, op_id)
        result = lifecycle.reserve(
            conn, cap, op_id, amount, action_digest, mandate_hash, now_unix,
            entry_ttl=entry_ttl,
        )
    except lifecycle.BudgetRefused as exc:
        return {
            "allowed": False,
            "reason_codes": [f"capability_budget_exceeded:{exc}"],
            "capability": {"capability_id": cap["capability_id"]},
        }
    return {
        "allowed": True,
        "reason_codes": [],
        "capability": {"capability_id": cap["capability_id"]},
        "reservation": {
            "op_id": op_id,
            "receipt_digest": cap["receipt_digest"],
            "token": result["token"],
            "duplicate": result["duplicate"],
        },
    }


def note_entry_for(
    conn: sqlite3.Connection,
    reservation: Mapping[str, Any],
    capability_id: str,
    token: str,
    now_unix: int,
) -> dict[str, Any]:
    """Record crossing the effect boundary for a reservation."""
    return lifecycle.note_provider_entry(
        conn, capability_id, reservation["receipt_digest"],
        reservation["op_id"], token, now_unix,
    )


def settle_for(
    conn: sqlite3.Connection,
    reservation: Mapping[str, Any],
    capability_id: str,
    token: str,
    outcome: str,
    *,
    evidence_digest: str | None = None,
    proven: bool = False,
    now_unix: int,
) -> dict[str, Any]:
    """Settle a reservation: executed | not_entered | unknown (-> indeterminate)."""
    return lifecycle.commit(
        conn, capability_id, reservation["receipt_digest"], reservation["op_id"],
        token, outcome, evidence_digest=evidence_digest, proven=proven,
        now_unix=now_unix,
    )
