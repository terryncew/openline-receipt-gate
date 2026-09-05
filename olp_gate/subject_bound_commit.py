"""Receiver-owned subject binding for portable Verified Commit permissions.

Verified Commit intentionally remains the frozen exact-action / one-use primitive.
This additive gate answers a different question immediately outside that primitive:

    Is the authenticated caller the stable authority subject that the receiver
    currently admits for this mandate slot?

The expected subject comes only from receiver-owned MandateOwnerView state.
The observed subject comes only from a zero-argument receiver-owned subject
source (for example verified workload identity, mTLS identity, or protected
local process context).  No receipt field, proposal field, model name, provider
name, or caller-supplied function argument can assert the observed subject.

A mismatch is rejected before the underlying VerifiedCommitLedger is touched,
so possession of a valid receipt/action/one-use-code tuple cannot let another
subject execute the effect or burn the rightful subject's permission.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, TypeVar

from .mandate import MandateSpec


T = TypeVar("T")


class SubjectBoundCommitError(ValueError):
    """Raised when the receiver-side subject gate is misconfigured."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SubjectBoundCommitGate:
    """Compose receiver-authenticated subject identity with Verified Commit.

    ``mandate_view`` must expose ``require_current(slot_id, now=...)``.
    ``subject_source`` must be receiver-controlled and accept no caller input.

    This class deliberately does not authenticate an agent by itself.  It
    consumes an identity established by the receiver's authentication layer.
    """

    def __init__(
        self,
        ledger: Any,
        *,
        mandate_view: Any,
        mandate_slot_id: str,
        subject_source: Callable[[], str],
    ) -> None:
        if not hasattr(ledger, "check_and_consume") or not callable(
            ledger.check_and_consume
        ):
            raise SubjectBoundCommitError("verified_commit_ledger_invalid")
        if not hasattr(ledger, "execute_once") or not callable(ledger.execute_once):
            raise SubjectBoundCommitError("verified_commit_ledger_invalid")
        if not hasattr(mandate_view, "require_current") or not callable(
            mandate_view.require_current
        ):
            raise SubjectBoundCommitError("mandate_view_invalid")
        if not isinstance(mandate_slot_id, str) or not mandate_slot_id:
            raise SubjectBoundCommitError("mandate_slot_id_invalid")
        if not callable(subject_source):
            raise SubjectBoundCommitError("subject_source_invalid")

        self.ledger = ledger
        self.mandate_view = mandate_view
        self.mandate_slot_id = mandate_slot_id
        self.subject_source = subject_source

    @staticmethod
    def _blocked(
        receipt: Mapping[str, Any],
        *,
        reason_codes: Sequence[str],
        replay_scope_hash: str | None,
        detail: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        authorization = receipt.get("commit_authorization")
        if not isinstance(authorization, Mapping):
            authorization = {}
        result: dict[str, Any] = {
            "authorized": False,
            "reason_codes": sorted(set(reason_codes)),
            "attempt_id": None,
            "decision_payload_hash": receipt.get("payload_hash"),
            "authorization_hash": authorization.get("authorization_hash"),
            "action_hash": authorization.get("action_hash"),
            "replay_scope_hash": replay_scope_hash,
            "execution_status": "not_started",
            "subject_gate": "BLOCKED",
        }
        if detail:
            result["subject_gate_detail"] = dict(detail)
        return result

    def _check_subject(
        self,
        *,
        now: datetime,
    ) -> tuple[bool, list[str], dict[str, Any]]:
        try:
            mandate_value, head_hash = self.mandate_view.require_current(
                self.mandate_slot_id,
                now=now,
            )
            mandate = MandateSpec.from_mapping(mandate_value)
        except BaseException as exc:
            return (
                False,
                ["authority_subject_current_mandate_unavailable"],
                {
                    "mandate_slot_id": self.mandate_slot_id,
                    "error_type": type(exc).__name__,
                },
            )

        try:
            observed_subject = self.subject_source()
        except BaseException as exc:
            return (
                False,
                ["authority_subject_resolution_failed"],
                {
                    "mandate_slot_id": self.mandate_slot_id,
                    "mandate_head_hash": head_hash,
                    "error_type": type(exc).__name__,
                },
            )

        if not isinstance(observed_subject, str) or not observed_subject:
            return (
                False,
                ["authority_subject_observation_invalid"],
                {
                    "mandate_slot_id": self.mandate_slot_id,
                    "mandate_head_hash": head_hash,
                },
            )

        if observed_subject != mandate.agent_id:
            return (
                False,
                ["authority_subject_mismatch"],
                {
                    "mandate_slot_id": self.mandate_slot_id,
                    "mandate_head_hash": head_hash,
                },
            )

        return (
            True,
            [],
            {
                "mandate_slot_id": self.mandate_slot_id,
                "mandate_head_hash": head_hash,
            },
        )

    def check_and_consume(
        self,
        receipt: Mapping[str, Any],
        action: Mapping[str, Any],
        *,
        one_use_code: str,
        trusted_gate_keys: Sequence[str],
        replay_scope_hash: str | None = None,
        now: datetime | None = None,
        attempt_label: str | None = None,
    ) -> dict[str, Any]:
        """Reject the wrong authenticated subject before consuming permission."""

        check_time = now or _utc_now()
        allowed, reasons, detail = self._check_subject(now=check_time)
        if not allowed:
            return self._blocked(
                receipt,
                reason_codes=reasons,
                replay_scope_hash=replay_scope_hash,
                detail=detail,
            )

        result = self.ledger.check_and_consume(
            receipt,
            action,
            one_use_code=one_use_code,
            trusted_gate_keys=trusted_gate_keys,
            replay_scope_hash=replay_scope_hash,
            now=check_time,
            attempt_label=attempt_label,
        )
        if isinstance(result, Mapping):
            result = dict(result)
            result["subject_gate"] = "PASSED"
            result["subject_gate_detail"] = detail
        return result

    def execute_once(
        self,
        receipt: Mapping[str, Any],
        action: Mapping[str, Any],
        *,
        one_use_code: str,
        trusted_gate_keys: Sequence[str],
        executor: Callable[[], T],
        preflight: Callable[[], Mapping[str, Any]] | None = None,
        replay_scope_hash: str | None = None,
        now: datetime | None = None,
        attempt_label: str | None = None,
    ) -> dict[str, Any]:
        """Enforce subject identity, then delegate unchanged one-use semantics.

        The first subject check occurs before the underlying ledger can consume
        permission.  When the caller already supplies a receiver-owned fresh
        preflight, the subject is checked again at that same pre-effect anchor.
        If no preflight is supplied, this wrapper leaves ``preflight=None`` so
        profiles such as x402 that require their own fresh preflight cannot be
        accidentally satisfied by a subject check.
        """

        check_time = now or _utc_now()
        allowed, reasons, detail = self._check_subject(now=check_time)
        if not allowed:
            return self._blocked(
                receipt,
                reason_codes=reasons,
                replay_scope_hash=replay_scope_hash,
                detail=detail,
            )

        effective_preflight = preflight
        if preflight is not None:
            def effective_preflight() -> Mapping[str, Any]:
                fresh_allowed, fresh_reasons, fresh_detail = self._check_subject(
                    now=check_time
                )
                if not fresh_allowed:
                    return {
                        "allowed": False,
                        "reason_codes": fresh_reasons,
                        "evidence": {
                            "schema": "openline.subject-bound-commit.preflight.v1",
                            "subject_gate": "BLOCKED",
                            **fresh_detail,
                        },
                    }
                return preflight()

        result = self.ledger.execute_once(
            receipt,
            action,
            one_use_code=one_use_code,
            trusted_gate_keys=trusted_gate_keys,
            executor=executor,
            preflight=effective_preflight,
            replay_scope_hash=replay_scope_hash,
            now=check_time,
            attempt_label=attempt_label,
        )
        if isinstance(result, Mapping):
            result = dict(result)
            result["subject_gate"] = "PASSED"
            result["subject_gate_detail"] = detail
        return result
