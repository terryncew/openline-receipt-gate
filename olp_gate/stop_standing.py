"""Portable owner-STOP standing adapter for the verified-commit boundary.

This module is a protocol adapter, not a second authority engine. It maps the
portable kill-switch STOP contract onto the existing receiver-owned standing
vocabulary:

- portable owner-STOP := the existing owner-signed terminal standing —
  ``MandateOwnerView`` head -> REVOKED for the covered mandate slot, or
  ``ReceiverStandingView`` head -> INACTIVE for the covered action — admitted
  through the existing ``admit`` successor rules. No new authority machinery.
- STOP_EFFECTIVE := the monotonic head sequence at which the terminal state
  was admitted.

The adapter exposes final-authority check callables that
``VerifiedCommitLedger.check_and_consume`` / ``execute_once`` run inside the
same ``_locked()`` region as permission consumption, so the final standing
check and commit-or-refuse share one serialization point. Compiled or
preliminary authorization is explicitly non-authoritative at finalize time:
only the observation taken under the lock governs.

It also exposes pure re-derivation helpers so an independent appraiser can
recompute every path verdict (STOPPED / ESCAPED / UNKNOWN) and the
PRE_STOP_COMMIT ordering classification from the ledger journal plus the
standing admission history, without trusting the live system.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

ADAPTER_VERSION = "openline.stop-standing.adapter.v1"

# Attempt-journal field versions. Additive; old journal readers ignore them.
FINAL_CHECK_FIELD = "standing_final_check_v1"
PATH_VERDICT_FIELD = "path_verdict_v1"

# Execution statuses that mean the protected effect committed.
_COMMITTED_STATUSES = {"completed", "completed_result_unhashable"}

# Reason codes the final check may report. The ledger stores them verbatim.
REASON_REVOKED = "owner_standing_revoked"
REASON_NOT_ACTIVE = "owner_standing_not_active"
REASON_HEAD_MISSING = "owner_standing_head_missing"
REASON_CHECK_FAILED = "final_standing_check_failed"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _jsonable(value: Any) -> Any:
    """Best-effort JSON-safe copy for journal evidence."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return str(value)


def owner_mandate_stop_check(
    mandate_view: Any,
    slot_id: str,
    *,
    now: datetime | None = None,
) -> Callable[[], dict[str, Any]]:
    """Build the final-authority check for one mandate slot.

    Terminal := ``MandateOwnerView.status()`` reports REVOKED. Any other
    non-ACTIVE status (MISSING, AUTHORIZATION_EXPIRED, MANDATE_EXPIRED)
    also refuses, fail-closed, but is classified as not-established rather
    than as an owner STOP.
    """

    def check() -> dict[str, Any]:
        check_time = now or _utc_now()
        status = mandate_view.status(slot_id, now=check_time)
        head_hash = mandate_view.head_hash(slot_id)
        head_seq = mandate_view.head_sequence(slot_id)
        record = mandate_view.head_record(slot_id)
        if status == "ACTIVE":
            return {
                "installed": True,
                "allowed": True,
                "standing": "ACTIVE",
                "terminal": False,
                "head_seq": head_seq,
                "head_hash": head_hash,
                "reason_codes": [],
                "record": _jsonable(record),
            }
        terminal = status == "REVOKED"
        if status == "MISSING":
            codes = [REASON_HEAD_MISSING]
        elif terminal:
            codes = [REASON_REVOKED]
        else:
            codes = [f"{REASON_NOT_ACTIVE}:{status}"]
        return {
            "installed": True,
            "allowed": False,
            "standing": status,
            "terminal": terminal,
            "head_seq": head_seq if head_hash is not None else None,
            "head_hash": head_hash,
            "reason_codes": codes,
            "record": _jsonable(record),
        }

    return check


def receiver_action_stop_check(
    standing_view: Any,
    support_hash: str,
    action_hash: str,
    *,
    now: datetime | None = None,
) -> Callable[[], dict[str, Any]]:
    """Build the final-authority check for one covered (support, action) pair.

    Terminal := ``ReceiverStandingView`` head standing INACTIVE. An expired
    head is treated as not-established (fail closed), never as ACTIVE.
    """

    def check() -> dict[str, Any]:
        check_time = now or _utc_now()
        if check_time.tzinfo is None:
            check_time = check_time.replace(tzinfo=timezone.utc)
        head = standing_view.head(support_hash, action_hash)
        if head is None:
            return {
                "installed": True,
                "allowed": False,
                "standing": "MISSING",
                "terminal": False,
                "head_seq": None,
                "head_hash": None,
                "reason_codes": [REASON_HEAD_MISSING],
                "record": None,
            }
        standing = str(head.get("standing", "UNKNOWN"))
        try:
            expires_at = datetime.fromisoformat(
                str(head.get("expires_at", "")).replace("Z", "+00:00")
            )
        except ValueError:
            expires_at = None
        if expires_at is not None and expires_at <= check_time:
            standing = "EXPIRED"
        if standing == "ACTIVE":
            return {
                "installed": True,
                "allowed": True,
                "standing": "ACTIVE",
                "terminal": False,
                "head_seq": head.get("sequence"),
                "head_hash": head.get("payload_hash"),
                "reason_codes": [],
                "record": _jsonable(head),
            }
        terminal = standing == "INACTIVE"
        codes = (
            [REASON_REVOKED]
            if terminal
            else [f"{REASON_NOT_ACTIVE}:{standing}"]
        )
        return {
            "installed": True,
            "allowed": False,
            "standing": standing,
            "terminal": terminal,
            "head_seq": head.get("sequence"),
            "head_hash": head.get("payload_hash"),
            "reason_codes": codes,
            "record": _jsonable(head),
        }

    return check


def _admission_is_terminal(admission: Mapping[str, Any]) -> bool:
    state = admission.get("state", admission.get("standing"))
    return state in ("REVOKED", "INACTIVE")


def _admission_seq(admission: Mapping[str, Any]) -> int | None:
    seq = admission.get("sequence")
    if isinstance(seq, bool) or not isinstance(seq, int):
        return None
    return seq


def derive_path_verdict(
    attempt: Mapping[str, Any],
    standing_admissions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Re-derive one attempt's path verdict without trusting the live system.

    Inputs are the attempt's journal record (with its ``standing_final_check_v1``
    observation) and the standing admission history — the admit receipts the
    owner-signed records produced. Pure function; no view or ledger access.
    """
    observation = attempt.get(FINAL_CHECK_FIELD)
    if not isinstance(observation, Mapping) or not observation.get("installed"):
        return {"verdict": None, "ordering": None, "basis": "not_covered"}
    standing = observation.get("standing")
    if standing == "CHECK_FAILED":
        return {
            "verdict": "UNKNOWN",
            "ordering": "CHECK_FAILED",
            "basis": "standing could not be established at finalize time",
        }
    reason_codes = attempt.get("reason_codes") or []
    final_refusal = any(
        str(code).startswith(("owner_standing_", "final_standing_"))
        for code in reason_codes
    )
    observed_seq = observation.get("head_seq")
    terminal_admissions = [
        admission
        for admission in standing_admissions
        if _admission_is_terminal(admission)
        and _admission_seq(admission) is not None
    ]
    if attempt.get("result") == "BLOCKED" and final_refusal:
        if observation.get("terminal") and isinstance(observed_seq, int):
            return {
                "verdict": "STOPPED",
                "ordering": "STOP_FIRST",
                "stop_effective_seq": observed_seq,
                "basis": "terminal owner standing observed under the commit lock",
            }
        return {
            "verdict": "UNKNOWN",
            "ordering": "NOT_ESTABLISHED",
            "basis": "refused fail-closed without a terminal head sequence",
        }
    if attempt.get("execution_status") in _COMMITTED_STATUSES:
        if not isinstance(observed_seq, int):
            return {
                "verdict": "UNKNOWN",
                "ordering": "NO_OBSERVED_SEQ",
                "basis": "committed without a recorded standing head sequence",
            }
        earlier_or_equal = [
            admission
            for admission in terminal_admissions
            if _admission_seq(admission) <= observed_seq  # type: ignore[operator]
        ]
        if earlier_or_equal:
            return {
                "verdict": "ESCAPED",
                "ordering": "STOP_FIRST_VIOLATED",
                "stop_effective_seq": min(
                    _admission_seq(admission)  # type: ignore[misc]
                    for admission in earlier_or_equal
                ),
                "basis": (
                    "effect committed while a terminal admission at or before "
                    "the observed head sequence exists"
                ),
            }
        later = [
            admission
            for admission in terminal_admissions
            if _admission_seq(admission) > observed_seq  # type: ignore[operator]
        ]
        if later:
            return {
                "verdict": None,
                "ordering": "PRE_STOP_COMMIT",
                "stop_effective_seq": min(
                    _admission_seq(admission)  # type: ignore[misc]
                    for admission in later
                ),
                "basis": (
                    "effect committed while standing was ACTIVE; terminal "
                    "standing admitted later"
                ),
            }
        return {
            "verdict": None,
            "ordering": "NO_STOP_ADMITTED",
            "basis": "effect committed; no terminal admission in history",
        }
    return {
        "verdict": None,
        "ordering": "NO_EFFECT",
        "basis": "covered attempt produced no committed effect",
    }


def derive_path_verdicts(
    ledger_state: Mapping[str, Any],
    standing_admissions: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Re-derive path verdicts for every covered attempt in a ledger state."""
    attempts = ledger_state.get("attempts")
    if not isinstance(attempts, list):
        return []
    derived = []
    for attempt in attempts:
        if not isinstance(attempt, Mapping):
            continue
        verdict = derive_path_verdict(attempt, standing_admissions)
        derived.append(
            {
                "attempt_id": attempt.get("attempt_id"),
                "commit_seq": attempt.get("commit_seq"),
                **verdict,
            }
        )
    return derived
