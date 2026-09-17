"""Reserve/admit/reconcile lifecycle (draft §10).

Operation states: reserved -> provider_entered -> executed | not_entered
| indeterminate. Terminal: executed, not_entered. Non-terminal: reserved,
provider_entered, indeterminate.

Every transition is exactly one atomic transaction (via
:mod:`olp_gate.capability_store`). No transaction spans two transitions.

The critical rule (§10.4): uncertainty is encumbered, never released. A
provider_entered operation with missing or ambiguous evidence becomes
``indeterminate`` — budget stays encumbered until explicit resolution.
The reconciler may never invent non-entry.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from typing import Any, Callable, Mapping

from .capability_store import StoreError, get_capability, transaction

RESERVED = "reserved"
PROVIDER_ENTERED = "provider_entered"
EXECUTED = "executed"
NOT_ENTERED = "not_entered"
INDETERMINATE = "indeterminate"
TERMINAL = frozenset({EXECUTED, NOT_ENTERED})
NON_TERMINAL = frozenset({RESERVED, PROVIDER_ENTERED, INDETERMINATE})
DEFAULT_ENTRY_TTL = 300  # seconds; deadline never exceeds capability expiry
_HEX = frozenset("0123456789abcdef")


class BudgetRefused(ValueError):
    """Reservation refused on budget/state grounds (fail-closed)."""


class OperationError(ValueError):
    """Operation transition invalid (fail-closed)."""


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in _HEX for c in value.lower())
    )


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _sums(conn: sqlite3.Connection, capability_id: str) -> tuple[int, int]:
    cur = conn.execute(
        "SELECT COALESCE(SUM(amount),0) FROM operations"
        " WHERE capability_id = ? AND state = 'executed'",
        (capability_id,),
    )
    committed = cur.fetchone()[0]
    cur = conn.execute(
        "SELECT COALESCE(SUM(amount),0) FROM operations"
        " WHERE capability_id = ? AND state IN ('reserved','provider_entered','indeterminate')",
        (capability_id,),
    )
    encumbered = cur.fetchone()[0]
    return committed, encumbered


def available(conn: sqlite3.Connection, capability_id: str) -> dict[str, int | bool]:
    """Observed budget posture. Asserts the conservation invariant."""
    cap = get_capability(conn, capability_id)
    if cap is None:
        raise OperationError("capability_unknown")
    committed, encumbered = _sums(conn, capability_id)
    avail = cap["amount"] - committed - encumbered
    assert avail + encumbered + committed == cap["amount"], "conservation_violated"
    assert avail >= 0, "negative_available"
    return {
        "budget": cap["amount"],
        "committed": committed,
        "encumbered": encumbered,
        "available": avail,
        "revoked": bool(cap["revoked"]),
    }


def _get_op(
    conn: sqlite3.Connection, capability_id: str, receipt_digest: str, op_id: str
) -> dict[str, Any] | None:
    cur = conn.execute(
        "SELECT capability_id, op_id, receipt_digest, state, amount,"
        " exercise_action_digest, mandate_hash, token_hash, entry_deadline,"
        " effect_evidence_digest, resolution_note, created_at, updated_at"
        " FROM operations WHERE receipt_digest = ? AND op_id = ?",
        (receipt_digest, op_id),
    )
    found = cur.fetchone()
    if found is None:
        return None
    op = dict(zip([d[0] for d in cur.description], found))
    if op["capability_id"] != capability_id:
        raise OperationError("operation_capability_mismatch")
    return op


def get_operation(
    conn: sqlite3.Connection, capability_id: str, receipt_digest: str, op_id: str
) -> dict[str, Any] | None:
    return _get_op(conn, capability_id, receipt_digest, op_id)


def reserve(
    conn: sqlite3.Connection,
    capability: Mapping[str, Any],
    op_id: str,
    amount: int,
    exercise_action_digest: str,
    mandate_hash: str,
    now_unix: int,
    entry_ttl: int = DEFAULT_ENTRY_TTL,
) -> dict[str, Any]:
    """Reserve ``amount``; returns ``{"token", "op", "duplicate"}``.

    Idempotent on the op key: an identical retry returns the existing
    reservation metadata WITHOUT the token (issued exactly once).
    """
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise OperationError("reserve_amount_invalid")
    with transaction(conn):
        cap = get_capability(conn, capability["capability_id"])
        if cap is None:
            raise OperationError("capability_unknown")
        if cap["revoked"]:
            raise BudgetRefused("capability_revoked")
        if now_unix >= cap["expires_at"]:
            raise BudgetRefused("capability_expired")
        existing = _get_op(conn, cap["capability_id"], cap["receipt_digest"], op_id)
        if existing is not None:
            if (
                existing["amount"] == amount
                and existing["exercise_action_digest"] == exercise_action_digest
                and existing["mandate_hash"] == mandate_hash
            ):
                return {"token": None, "op": existing, "duplicate": True}
            raise OperationError("operation_key_reuse")
        posture = available(conn, cap["capability_id"])
        if amount > posture["available"]:
            raise BudgetRefused("insufficient_available")
        token = secrets.token_hex(16)
        deadline = min(now_unix + entry_ttl, cap["expires_at"])
        conn.execute(
            "INSERT INTO operations(capability_id, op_id, receipt_digest, state,"
            " amount, exercise_action_digest, mandate_hash, token_hash,"
            " entry_deadline, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                cap["capability_id"], op_id, cap["receipt_digest"], RESERVED,
                amount, exercise_action_digest, mandate_hash,
                _token_hash(token), deadline, now_unix, now_unix,
            ),
        )
        op = _get_op(conn, cap["capability_id"], cap["receipt_digest"], op_id)
        assert op is not None
        return {"token": token, "op": op, "duplicate": False}


def note_provider_entry(
    conn: sqlite3.Connection,
    capability_id: str,
    receipt_digest: str,
    op_id: str,
    token: str,
    now_unix: int,
) -> dict[str, Any]:
    """Record crossing the effect boundary. Late entry is refused."""
    with transaction(conn):
        op = _get_op(conn, capability_id, receipt_digest, op_id)
        if op is None:
            raise OperationError("operation_unknown")
        if op["state"] != RESERVED:
            raise OperationError("operation_state_invalid")
        if _token_hash(token) != (op["token_hash"] or ""):
            raise OperationError("reservation_token_invalid")
        if now_unix > (op["entry_deadline"] or 0):
            raise OperationError("entry_deadline_exceeded")
        cap = get_capability(conn, capability_id)
        if cap is None or cap["revoked"]:
            raise OperationError("capability_revoked")
        conn.execute(
            "UPDATE operations SET state = ?, updated_at = ?"
            " WHERE receipt_digest = ? AND op_id = ?",
            (PROVIDER_ENTERED, now_unix, receipt_digest, op_id),
        )
        updated = _get_op(conn, capability_id, receipt_digest, op_id)
        assert updated is not None
        return updated


def commit(
    conn: sqlite3.Connection,
    capability_id: str,
    receipt_digest: str,
    op_id: str,
    token: str,
    outcome: str,
    *,
    evidence_digest: str | None = None,
    proven: bool = False,
    now_unix: int,
) -> dict[str, Any]:
    """Settle a reserved operation. ``outcome`` is executed | not_entered |
    unknown. Unknown from provider_entered -> indeterminate (fail-closed);
    budget is never restored on uncertainty."""
    with transaction(conn):
        op = _get_op(conn, capability_id, receipt_digest, op_id)
        if op is None:
            raise OperationError("operation_unknown")
        if _token_hash(token) != (op["token_hash"] or ""):
            raise OperationError("reservation_token_invalid")
        if outcome == EXECUTED:
            if op["state"] != PROVIDER_ENTERED:
                raise OperationError("operation_state_invalid")
            if not _is_hex(evidence_digest, 64):
                raise OperationError("effect_evidence_required")
            new_state: str = EXECUTED
        elif outcome == NOT_ENTERED:
            if op["state"] not in (RESERVED, PROVIDER_ENTERED):
                raise OperationError("operation_state_invalid")
            if not proven:
                raise OperationError("non_entry_proof_required")
            new_state = NOT_ENTERED
        elif outcome == "unknown":
            if op["state"] != PROVIDER_ENTERED:
                raise OperationError("operation_state_invalid")
            new_state = INDETERMINATE
        else:
            raise OperationError("commit_outcome_invalid")
        conn.execute(
            "UPDATE operations SET state = ?, effect_evidence_digest = ?,"
            " token_hash = NULL, entry_deadline = NULL, updated_at = ?"
            " WHERE receipt_digest = ? AND op_id = ?",
            (new_state, evidence_digest, now_unix, receipt_digest, op_id),
        )
        updated = _get_op(conn, capability_id, receipt_digest, op_id)
        assert updated is not None
        return updated


def resolve_indeterminate(
    conn: sqlite3.Connection,
    capability_id: str,
    receipt_digest: str,
    op_id: str,
    resolution: str,
    *,
    evidence_digest: str | None = None,
    resolver_id: str,
    note: str,
    now_unix: int,
) -> dict[str, Any]:
    """Explicit, audited resolution of an indeterminate operation. Never
    automatic: requires a named resolver and a written justification."""
    if resolution not in (EXECUTED, NOT_ENTERED):
        raise OperationError("resolution_invalid")
    if not isinstance(resolver_id, str) or not resolver_id:
        raise OperationError("resolver_required")
    if not isinstance(note, str) or not note:
        raise OperationError("resolution_note_required")
    if resolution == EXECUTED and not _is_hex(evidence_digest, 64):
        raise OperationError("effect_evidence_required")
    with transaction(conn):
        op = _get_op(conn, capability_id, receipt_digest, op_id)
        if op is None:
            raise OperationError("operation_unknown")
        if op["state"] != INDETERMINATE:
            raise OperationError("operation_state_invalid")
        audit = f"resolver={resolver_id} note={note}"
        conn.execute(
            "UPDATE operations SET state = ?, effect_evidence_digest = ?,"
            " resolution_note = ?, updated_at = ?"
            " WHERE receipt_digest = ? AND op_id = ?",
            (resolution, evidence_digest, audit, now_unix, receipt_digest, op_id),
        )
        updated = _get_op(conn, capability_id, receipt_digest, op_id)
        assert updated is not None
        return updated


def reconcile(
    conn: sqlite3.Connection,
    now_unix: int,
    evidence_provider: Callable[[dict[str, Any]], tuple[str, str | None]] | None = None,
) -> list[dict[str, Any]]:
    """Store-driven recovery. No daemon: called on startup, lazily before
    transitions touching a capability, or explicitly by the operator.

    - reserved past deadline with no entry record -> not_entered. Entry
      requires the token and our own log shows none past the deadline, so
      non-entry is proven from our own records.
    - provider_entered -> ask the evidence provider (the effect adapter's
      honest report): executed / not_entered move accordingly; anything
      else -> indeterminate (encumbered). The reconciler never invents
      non-entry.
    """
    provider = evidence_provider or (lambda op: ("unknown", None))
    moved: list[dict[str, Any]] = []
    cur = conn.execute(
        "SELECT capability_id, op_id, receipt_digest, state FROM operations"
        f" WHERE state IN ('{RESERVED}','{PROVIDER_ENTERED}')"
    )
    targets = cur.fetchall()
    for capability_id, op_id, receipt_digest, state in targets:
        with transaction(conn):
            op = _get_op(conn, capability_id, receipt_digest, op_id)
            if op is None or op["state"] != state:
                continue  # moved concurrently; single-writer serializes
            if state == RESERVED:
                if now_unix <= (op["entry_deadline"] or 0):
                    continue
                conn.execute(
                    "UPDATE operations SET state = ?, token_hash = NULL,"
                    " entry_deadline = NULL, resolution_note = ?, updated_at = ?"
                    " WHERE receipt_digest = ? AND op_id = ?",
                    (
                        NOT_ENTERED,
                        "reconciled: entry deadline passed without entry",
                        now_unix, receipt_digest, op_id,
                    ),
                )
                moved.append({"op_id": op_id, "from": RESERVED, "to": NOT_ENTERED})
            else:
                verdict, digest = provider(op)
                if verdict == EXECUTED and _is_hex(digest, 64):
                    new_state: str = EXECUTED
                elif verdict == NOT_ENTERED and _is_hex(digest, 64):
                    new_state = NOT_ENTERED
                else:
                    new_state = INDETERMINATE
                conn.execute(
                    "UPDATE operations SET state = ?, effect_evidence_digest = ?,"
                    " token_hash = NULL, entry_deadline = NULL,"
                    " resolution_note = ?, updated_at = ?"
                    " WHERE receipt_digest = ? AND op_id = ?",
                    (
                        new_state, digest,
                        f"reconciled: evidence={verdict}", now_unix,
                        receipt_digest, op_id,
                    ),
                )
                moved.append({"op_id": op_id, "from": PROVIDER_ENTERED, "to": new_state})
    return moved
