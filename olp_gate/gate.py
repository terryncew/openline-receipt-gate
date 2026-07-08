from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .receipts import hash_any, make_receipt


class Decision(str, Enum):
    COMMIT = "COMMIT"
    QUARANTINE = "QUARANTINE"
    NO_BADGE = "NO_BADGE"


@dataclass
class GatePolicy:
    """Fail-closed policy for one risky boundary crossing."""

    evidence_required: bool = False
    user_intent_required: bool = False
    grader_required: bool = False
    tool_result_required: bool = False
    store_raw_evidence: bool = False
    store_traceback: bool = False
    receipt_path: str = "receipts/olp_receipts.jsonl"


@dataclass
class ReceiptGate:
    """Context manager for a risky agent action.

    Use:

        with gate("tool_call", claim="Search customer records", evidence_required=True) as g:
            result = search_customer_records(query)
            g.commit(result, evidence={"query_hash": "..."})
    """

    action_type: str
    claim: str
    policy: GatePolicy = field(default_factory=GatePolicy)
    metadata: Dict[str, Any] = field(default_factory=dict)
    _closed: bool = False
    receipt: Optional[Dict[str, Any]] = None

    def __enter__(self) -> "ReceiptGate":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc is not None:
            meta = {
                "exception_type": getattr(exc_type, "__name__", str(exc_type)),
                "exception_message": str(exc),
            }
            if self.policy.store_traceback:
                import traceback
                meta["traceback"] = "".join(traceback.format_exception(exc_type, exc, tb))[-2000:]
            self.quarantine(reason="exception_inside_gate", metadata=meta)
            return False

        if not self._closed:
            self.no_badge(
                reason="gate_exited_without_commit_or_quarantine",
                metadata={"hint": "call gate.commit(result, evidence=...) or gate.quarantine(reason=...)"},
            )
        return False

    def _policy_flags(
        self,
        *,
        evidence_hash: Optional[str],
        result_hash: Optional[str],
        evidence: Optional[Dict[str, Any]],
        extra_flags: Optional[List[str]] = None,
    ) -> List[str]:
        flags: List[str] = []
        evidence = evidence or {}

        if self.policy.evidence_required and not evidence_hash:
            flags.append("missing_evidence_hash")

        if result_hash is None:
            flags.append("missing_result_hash")

        if self.policy.user_intent_required and not evidence.get("user_intent_confirmed", False):
            flags.append("missing_user_intent")

        if self.policy.grader_required and not evidence.get("grader_receipt_hash"):
            flags.append("missing_grader_receipt")

        if self.policy.tool_result_required and not evidence.get("tool_result_hash"):
            flags.append("missing_tool_result")

        if extra_flags:
            flags.extend(extra_flags)

        return flags

    def _safe_metadata(
        self,
        *,
        evidence: Optional[Dict[str, Any]],
        evidence_hash: Optional[str],
        metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        evidence = evidence or {}
        safe = {
            **self.metadata,
            **(metadata or {}),
            "evidence_keys": sorted(list(evidence.keys())),
            "raw_evidence_stored": self.policy.store_raw_evidence,
        }
        if self.policy.store_raw_evidence:
            safe["evidence"] = evidence
        if evidence_hash:
            safe["evidence_hash"] = evidence_hash
        return safe

    def commit(
        self,
        result: Any,
        *,
        evidence: Optional[Dict[str, Any]] = None,
        evidence_hash: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if self._closed:
            raise RuntimeError("gate already closed")

        evidence = evidence or {}
        if evidence_hash is None and evidence:
            evidence_hash = hash_any(evidence)
        result_hash = hash_any(result)

        flags = self._policy_flags(
            evidence_hash=evidence_hash,
            result_hash=result_hash,
            evidence=evidence,
        )

        if flags:
            decision = Decision.QUARANTINE.value
            status = "quarantined"
            next_use_note = "Do not trust this action as committed. Review missing proof before replay or downstream use."
        else:
            decision = Decision.COMMIT.value
            status = "committed"
            next_use_note = "This action passed the receipt gate. Use receipt_hash for audit, handoff, or replay checks."

        self.receipt = make_receipt(
            path=self.policy.receipt_path,
            action_type=self.action_type,
            claim=self.claim,
            evidence_hash=evidence_hash,
            result_hash=result_hash,
            status=status,
            decision=decision,
            policy_flags=flags,
            next_use_note=next_use_note,
            metadata=self._safe_metadata(evidence=evidence, evidence_hash=evidence_hash, metadata=metadata),
        )
        self._closed = True
        return self.receipt

    def quarantine(
        self,
        *,
        reason: str,
        evidence: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if self._closed:
            raise RuntimeError("gate already closed")

        evidence = evidence or {}
        evidence_hash = hash_any(evidence) if evidence else None
        flags = self._policy_flags(
            evidence_hash=evidence_hash,
            result_hash=None,
            evidence=evidence,
            extra_flags=[reason],
        )

        self.receipt = make_receipt(
            path=self.policy.receipt_path,
            action_type=self.action_type,
            claim=self.claim,
            evidence_hash=evidence_hash,
            result_hash=None,
            status="quarantined",
            decision=Decision.QUARANTINE.value,
            policy_flags=flags,
            next_use_note="Action was quarantined. Human or policy review required before downstream use.",
            metadata=self._safe_metadata(evidence=evidence, evidence_hash=evidence_hash, metadata=metadata),
        )
        self._closed = True
        return self.receipt

    def no_badge(
        self,
        *,
        reason: str,
        evidence: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if self._closed:
            raise RuntimeError("gate already closed")

        evidence = evidence or {}
        evidence_hash = hash_any(evidence) if evidence else None
        flags = self._policy_flags(
            evidence_hash=evidence_hash,
            result_hash=None,
            evidence=evidence,
            extra_flags=[reason],
        )

        self.receipt = make_receipt(
            path=self.policy.receipt_path,
            action_type=self.action_type,
            claim=self.claim,
            evidence_hash=evidence_hash,
            result_hash=None,
            status="no_badge",
            decision=Decision.NO_BADGE.value,
            policy_flags=flags,
            next_use_note="No badge. The action lacks a complete enough receipt trail to certify.",
            metadata=self._safe_metadata(evidence=evidence, evidence_hash=evidence_hash, metadata=metadata),
        )
        self._closed = True
        return self.receipt


def gate(
    *,
    action_type: str,
    claim: str,
    evidence_required: bool = False,
    user_intent_required: bool = False,
    grader_required: bool = False,
    tool_result_required: bool = False,
    store_raw_evidence: bool = False,
    store_traceback: bool = False,
    receipt_path: str = "receipts/olp_receipts.jsonl",
    metadata: Optional[Dict[str, Any]] = None,
) -> ReceiptGate:
    policy = GatePolicy(
        evidence_required=evidence_required,
        user_intent_required=user_intent_required,
        grader_required=grader_required,
        tool_result_required=tool_result_required,
        store_raw_evidence=store_raw_evidence,
        store_traceback=store_traceback,
        receipt_path=receipt_path,
    )
    return ReceiptGate(action_type=action_type, claim=claim, policy=policy, metadata=metadata or {})
