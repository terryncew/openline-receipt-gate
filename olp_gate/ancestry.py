"""Receiver-owned ancestry closure for standing-loss consequences.

This is deliberately smaller than a general Claim Graph.

The receiver records the one support artifact that actually earned a committed
decision receipt. Later, when receiver-recognized standing for an upstream
support is lost, this view computes downstream reachability over those admitted
BASIS_FOR edges.

Historical receipts are never rewritten. Closure changes whether a support
receipt may continue to earn current execution standing.
"""
from __future__ import annotations

from dataclasses import replace
from collections import deque
import copy
import hashlib
import json
import threading
from typing import Any, Callable, Mapping, Sequence

from ._durable_heads import DurableOpLog, DurableOpLogError
from .standing import (
    ReceiverStandingView,
    standing_action_hash_from_call,
    standing_requirement_source,
    support_receipt_hash,
)
from .tool_adapter import EvidenceAssertion, ToolCallContext


AFFECTED_STATE = "AFFECTED_UPSTREAM_STANDING_LOSS"
RELATIONSHIP = "BASIS_FOR"
ANCESTRY_CLOSURE_VIEW_IDENTITY = "ancestry_closure/v1"
_HEX = frozenset("0123456789abcdef")


class AncestryClosureError(ValueError):
    """Raised when receiver-owned ancestry state would become ambiguous."""


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


def _copy(value: Any) -> Any:
    try:
        return json.loads(
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        )
    except (TypeError, ValueError) as exc:
        raise AncestryClosureError("ancestry_json_invalid") from exc


def _edge_id(
    *,
    support_hash: str,
    derived_receipt_hash: str,
    decision_id: str,
    sequence: int,
) -> str:
    payload = {
        "support_hash": support_hash,
        "derived_receipt_hash": derived_receipt_hash,
        "relationship": RELATIONSHIP,
        "decision_id": decision_id,
        "sequence": sequence,
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


class ReceiverAncestryClosureView:
    """Small local receiver-owned dependency closure.

    V1 intentionally accepts exactly one support artifact per committed receipt.
    Multi-basis sufficiency is a separate research question.
    """

    def __init__(
        self,
        *,
        durable_path: str | None = None,
        identity: Mapping[str, Any] | None = None,
    ) -> None:
        self._nodes: set[str] = set()
        self._edges: dict[tuple[str, str], dict[str, Any]] = {}
        self._children: dict[str, set[str]] = {}
        self._parent_by_child: dict[str, str] = {}
        self._edge_sequence = 0

        self._processed_standing_events: dict[str, dict[str, Any]] = {}
        self._affected: dict[str, dict[str, Any]] = {}
        self._closure_event_sequence = 0

        # Serializes validate/append/install so in-memory state always
        # matches log order, within and across processes (the file lock
        # serializes across processes).
        self._op_lock = threading.Lock()
        # Explicit opt-in durability. Without durable_path the view keeps the
        # legacy in-memory closure, which resets on process restart.
        self._op_log: DurableOpLog | None = None
        if durable_path is not None:
            if not isinstance(identity, Mapping) or not identity:
                raise AncestryClosureError("ancestry_durable_identity_invalid")
            log = DurableOpLog(str(durable_path), dict(identity))
            self._replay(log.load_ops())
            self._op_log = log

    @classmethod
    def create_durable_log(
        cls, path: str, identity: Mapping[str, Any]
    ) -> "ReceiverAncestryClosureView":
        """First boot: create the ancestry log, then open it. Documented path.

        Recommended identity shape (same trust root as the paired standing
        view): {"view": ANCESTRY_CLOSURE_VIEW_IDENTITY,
                "trusted_issuers": {...}}.
        """
        if not isinstance(identity, Mapping) or not identity:
            raise AncestryClosureError("ancestry_durable_identity_invalid")
        DurableOpLog.create(str(path), dict(identity))
        return cls(durable_path=path, identity=identity)

    @property
    def durable(self) -> bool:
        """Whether this view replays from and appends to a durable op log."""
        return self._op_log is not None

    def _validate_hash(self, value: Any, name: str) -> str:
        if not _is_hash(value):
            raise AncestryClosureError(f"{name}_invalid")
        return str(value)

    def _path_exists(self, start: str, target: str) -> bool:
        if start == target:
            return True
        seen = {start}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for child in sorted(self._children.get(current, ())):
                if child == target:
                    return True
                if child not in seen:
                    seen.add(child)
                    queue.append(child)
        return False

    def _validate_commit_inputs(
        self,
        *,
        decision_id: str,
        derived_receipt: Mapping[str, Any],
        accepted_supports: Sequence[Mapping[str, Any]],
    ) -> tuple[str, str]:
        """Shape/hash validation for record_commit. Reads no closure state."""
        if not isinstance(decision_id, str) or not decision_id:
            raise AncestryClosureError("ancestry_decision_id_invalid")
        if not isinstance(derived_receipt, Mapping):
            raise AncestryClosureError("ancestry_derived_receipt_invalid")
        if isinstance(accepted_supports, (str, bytes)) or not isinstance(
            accepted_supports, Sequence
        ):
            raise AncestryClosureError("ancestry_accepted_supports_invalid")

        supports = list(accepted_supports)
        if len(supports) != 1:
            raise AncestryClosureError("ancestry_multi_basis_not_supported")
        if not isinstance(supports[0], Mapping):
            raise AncestryClosureError("ancestry_support_invalid")

        support_hash = support_receipt_hash(supports[0])
        derived_hash = support_receipt_hash(derived_receipt)
        self._validate_hash(support_hash, "ancestry_support_hash")
        self._validate_hash(derived_hash, "ancestry_derived_receipt_hash")
        return support_hash, derived_hash

    def _build_edge(
        self, support_hash: str, derived_hash: str, decision_id: str
    ) -> dict[str, Any] | None:
        """Read-only edge construction. Returns None for an idempotent replay.

        Raises on duplicate-with-conflict, multi-parent, or cycle — before
        any durable write, so a rejected edge never reaches the log.
        """
        pair = (support_hash, derived_hash)
        existing = self._edges.get(pair)
        if existing is not None:
            if existing["decision_id"] != decision_id:
                raise AncestryClosureError("ancestry_duplicate_edge_conflict")
            return None

        existing_parent = self._parent_by_child.get(derived_hash)
        if existing_parent is not None and existing_parent != support_hash:
            raise AncestryClosureError("ancestry_multi_basis_not_supported")

        if support_hash == derived_hash or self._path_exists(
            derived_hash, support_hash
        ):
            raise AncestryClosureError("ancestry_cycle_forbidden")

        sequence = self._edge_sequence + 1
        return {
            "edge_id": _edge_id(
                support_hash=support_hash,
                derived_receipt_hash=derived_hash,
                decision_id=decision_id,
                sequence=sequence,
            ),
            "support_hash": support_hash,
            "derived_receipt_hash": derived_hash,
            "relationship": RELATIONSHIP,
            "decision_id": decision_id,
            "sequence": sequence,
        }

    def _install_edge(self, edge: Mapping[str, Any]) -> None:
        """Install a validated edge into the in-memory indexes."""
        support_hash = str(edge["support_hash"])
        derived_hash = str(edge["derived_receipt_hash"])
        pair = (support_hash, derived_hash)
        self._edge_sequence = max(self._edge_sequence, int(edge["sequence"]))
        self._nodes.add(support_hash)
        self._nodes.add(derived_hash)
        self._edges[pair] = dict(edge)
        self._children.setdefault(support_hash, set()).add(derived_hash)
        self._parent_by_child[derived_hash] = support_hash

    def _replay_edge(self, op: Mapping[str, Any]) -> None:
        """Install one logged edge op during durable replay (no logging)."""
        support_hash = str(op["support_hash"])
        derived_hash = str(op["derived_receipt_hash"])
        decision_id = str(op["decision_id"])
        pair = (support_hash, derived_hash)
        existing = self._edges.get(pair)
        if existing is not None:
            if existing["decision_id"] != decision_id:
                raise AncestryClosureError("ancestry_log_edge_conflict")
            return
        existing_parent = self._parent_by_child.get(derived_hash)
        if existing_parent is not None and existing_parent != support_hash:
            raise AncestryClosureError("ancestry_log_edge_conflict")
        if support_hash == derived_hash or self._path_exists(
            derived_hash, support_hash
        ):
            raise AncestryClosureError("ancestry_log_cycle_forbidden")
        self._install_edge(
            {
                "edge_id": _edge_id(
                    support_hash=support_hash,
                    derived_receipt_hash=derived_hash,
                    decision_id=decision_id,
                    sequence=int(op["sequence"]),
                ),
                "support_hash": support_hash,
                "derived_receipt_hash": derived_hash,
                "relationship": RELATIONSHIP,
                "decision_id": decision_id,
                "sequence": int(op["sequence"]),
            }
        )

    def _replay(self, ops: Sequence[Mapping[str, Any]]) -> None:
        """Rebuild derived closure state from the durable op log, in order."""
        for op in ops:
            if op["op"] == "edge":
                self._replay_edge(op)
            elif op["op"] == "loss":
                self._apply_loss_locked(
                    str(op["support_hash"]),
                    str(op["standing_event_id"]),
                    int(op["standing_event_sequence"]),
                    log=False,
                )
            else:  # pragma: no cover — _check_op_shape rejects this first
                raise AncestryClosureError("ancestry_log_op_invalid")

    def record_commit(
        self,
        *,
        decision_id: str,
        derived_receipt: Mapping[str, Any],
        accepted_supports: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Record the basis actually accepted at the receiver commit boundary.

        Edge material embedded inside the receipt is ignored. Only
        ``accepted_supports`` supplied by the receiver creates authority-bearing
        ancestry state.

        Durable mode: the edge op is appended to the log before the
        in-memory install. Append failure raises with no in-memory change,
        so the receiver never acknowledges a lineage it cannot reconstruct.
        """
        support_hash, derived_hash = self._validate_commit_inputs(
            decision_id=decision_id,
            derived_receipt=derived_receipt,
            accepted_supports=accepted_supports,
        )
        with self._op_lock:
            edge = self._build_edge(support_hash, derived_hash, decision_id)
            if edge is None:
                return {
                    "admitted": True,
                    "created": False,
                    "edge": _copy(self._edges[(support_hash, derived_hash)]),
                }
            if self._op_log is not None:
                self._op_log.append(
                    {
                        "op": "edge",
                        "decision_id": decision_id,
                        "support_hash": support_hash,
                        "derived_receipt_hash": derived_hash,
                        "sequence": edge["sequence"],
                    }
                )
            self._install_edge(edge)
            return {
                "admitted": True,
                "created": True,
                "edge": _copy(edge),
            }

    def assess_untrusted_edge(
        self,
        assertion: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Explicitly reject producer/external dependency assertions.

        Receiver ancestry can only move through ``record_commit``.
        """
        before = self._edge_sequence
        return {
            "admitted": False,
            "reason": "ancestry_external_edge_forbidden",
            "edge_sequence": before,
            "assertion_hash": hashlib.sha256(
                json.dumps(
                    _copy(dict(assertion)) if isinstance(assertion, Mapping) else {},
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest(),
        }

    def _validate_loss_inputs(
        self,
        *,
        support_hash: str,
        standing_event_id: str,
        standing_event_sequence: int,
    ) -> tuple[str, str, int]:
        """Input validation for apply_standing_loss. Reads no closure state."""
        support_hash = self._validate_hash(
            support_hash, "ancestry_standing_support_hash"
        )
        if not isinstance(standing_event_id, str) or not standing_event_id:
            raise AncestryClosureError("ancestry_standing_event_id_invalid")
        if (
            not isinstance(standing_event_sequence, int)
            or isinstance(standing_event_sequence, bool)
            or standing_event_sequence <= 0
        ):
            raise AncestryClosureError(
                "ancestry_standing_event_sequence_invalid"
            )
        return support_hash, standing_event_id, standing_event_sequence

    def _loss_replay_check(
        self,
        support_hash: str,
        standing_event_id: str,
        standing_event_sequence: int,
    ) -> dict[str, Any] | None:
        """Return the replay result if this event was already applied, else None.

        Raises on a replay with mismatched parameters: the same event id
        must always mean the same upstream loss.
        """
        prior = self._processed_standing_events.get(standing_event_id)
        if prior is None:
            return None
        if (
            prior["support_hash"] != support_hash
            or prior["standing_event_sequence"] != standing_event_sequence
        ):
            raise AncestryClosureError(
                "ancestry_standing_event_replay_mismatch"
            )
        replay = _copy(prior["result"])
        replay["replayed"] = True
        return replay

    def _compute_loss(
        self,
        support_hash: str,
        standing_event_id: str,
        standing_event_sequence: int,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], int]:
        """Read-only loss computation against the pre-append closure state.

        Computing before the durable append guarantees in-memory state can
        never disagree with log-order replay under concurrency.
        """
        paths: dict[str, list[str]] = {support_hash: [support_hash]}
        queue = deque([support_hash])
        ordered_descendants: list[str] = []

        while queue:
            current = queue.popleft()
            for child in sorted(self._children.get(current, ())):
                if child in paths:
                    continue
                paths[child] = paths[current] + [child]
                ordered_descendants.append(child)
                queue.append(child)

        events: list[dict[str, Any]] = []
        closure_sequence = self._closure_event_sequence
        newly_affected: list[str] = []
        for receipt_hash in ordered_descendants:
            if receipt_hash in self._affected:
                continue
            closure_sequence += 1
            events.append(
                {
                    "receipt_hash": receipt_hash,
                    "state": AFFECTED_STATE,
                    "upstream_support_hash": support_hash,
                    "standing_event_id": standing_event_id,
                    "standing_event_sequence": standing_event_sequence,
                    "closure_event_sequence": closure_sequence,
                    "causal_path": list(paths[receipt_hash]),
                }
            )
            newly_affected.append(receipt_hash)

        result = {
            "support_hash": support_hash,
            "standing_event_id": standing_event_id,
            "standing_event_sequence": standing_event_sequence,
            "affected_state": AFFECTED_STATE,
            "affected_receipt_hashes": list(ordered_descendants),
            "newly_affected_receipt_hashes": newly_affected,
            "causal_paths": {
                receipt_hash: list(paths[receipt_hash])
                for receipt_hash in ordered_descendants
            },
            "closure_event_sequence_after": closure_sequence,
            "replayed": False,
        }
        return result, events, closure_sequence

    def _install_loss(
        self,
        *,
        support_hash: str,
        standing_event_id: str,
        standing_event_sequence: int,
        result: dict[str, Any],
        events: list[dict[str, Any]],
        closure_sequence: int,
    ) -> None:
        """Install a computed loss into the in-memory derived state."""
        for event in events:
            self._affected[str(event["receipt_hash"])] = dict(event)
        self._closure_event_sequence = closure_sequence
        self._processed_standing_events[standing_event_id] = {
            "support_hash": support_hash,
            "standing_event_sequence": standing_event_sequence,
            "result": _copy(result),
        }

    def _apply_loss_locked(
        self,
        support_hash: str,
        standing_event_id: str,
        standing_event_sequence: int,
        *,
        log: bool,
    ) -> dict[str, Any]:
        """Replay-checked compute, optional durable append, install.

        Caller holds the op lock. When `log` is true and the view is
        durable, the loss op is appended before install; append failure
        raises with no in-memory change.
        """
        replay = self._loss_replay_check(
            support_hash, standing_event_id, standing_event_sequence
        )
        if replay is not None:
            return replay
        result, events, closure_sequence = self._compute_loss(
            support_hash, standing_event_id, standing_event_sequence
        )
        if log and self._op_log is not None:
            self._op_log.append(
                {
                    "op": "loss",
                    "support_hash": support_hash,
                    "standing_event_id": standing_event_id,
                    "standing_event_sequence": standing_event_sequence,
                }
            )
        self._install_loss(
            support_hash=support_hash,
            standing_event_id=standing_event_id,
            standing_event_sequence=standing_event_sequence,
            result=result,
            events=events,
            closure_sequence=closure_sequence,
        )
        return _copy(result)

    def apply_standing_loss(
        self,
        *,
        support_hash: str,
        standing_event_id: str,
        standing_event_sequence: int,
    ) -> dict[str, Any]:
        """Apply upstream standing loss to downstream descendants.

        Durable mode: the loss op is appended to the log before the
        in-memory install. Append failure raises with no in-memory change.
        """
        support_hash, standing_event_id, standing_event_sequence = (
            self._validate_loss_inputs(
                support_hash=support_hash,
                standing_event_id=standing_event_id,
                standing_event_sequence=standing_event_sequence,
            )
        )
        with self._op_lock:
            return self._apply_loss_locked(
                support_hash,
                standing_event_id,
                standing_event_sequence,
                log=True,
            )

    def _apply_loss_memory_only(
        self,
        *,
        support_hash: str,
        standing_event_id: str,
        standing_event_sequence: int,
    ) -> dict[str, Any]:
        """Best-effort in-memory loss install with no durable write.

        Used only on the coupled-admit failure path: the 001 head is
        already durably committed, so the consequence is installed from
        the authoritative head to keep the live process from widening.
        The next durable construction reconciles the log.
        """
        support_hash, standing_event_id, standing_event_sequence = (
            self._validate_loss_inputs(
                support_hash=support_hash,
                standing_event_id=standing_event_id,
                standing_event_sequence=standing_event_sequence,
            )
        )
        with self._op_lock:
            return self._apply_loss_locked(
                support_hash,
                standing_event_id,
                standing_event_sequence,
                log=False,
            )

    def reconcile_from_heads(
        self, heads: Sequence[Mapping[str, Any]]
    ) -> list[str]:
        """Re-derive durably-missing loss events from the 001 head frontier.

        For every head with standing != ACTIVE whose payload hash is not
        already a processed standing-event id, appends and applies a
        synthesized loss op. Idempotent. This heals the split-brain where
        a head commit survived but the ancestry loss op did not.
        """
        if self._op_log is None:
            return []
        added: list[str] = []
        with self._op_lock:
            for head in heads or []:
                if not isinstance(head, Mapping):
                    raise AncestryClosureError("ancestry_reconcile_head_invalid")
                if head.get("standing") == "ACTIVE":
                    continue
                support_hash = self._validate_hash(
                    head.get("support_hash"), "ancestry_reconcile_support_hash"
                )
                event_id = self._validate_hash(
                    head.get("payload_hash"), "ancestry_reconcile_event_id"
                )
                sequence = head.get("sequence")
                if (
                    not isinstance(sequence, int)
                    or isinstance(sequence, bool)
                    or sequence <= 0
                ):
                    raise AncestryClosureError(
                        "ancestry_reconcile_sequence_invalid"
                    )
                if event_id in self._processed_standing_events:
                    continue
                self._apply_loss_locked(
                    support_hash, event_id, sequence, log=True
                )
                added.append(event_id)
        return added

    def affected(self, receipt_hash: str) -> dict[str, Any] | None:
        if not _is_hash(receipt_hash):
            return None
        value = self._affected.get(receipt_hash)
        return None if value is None else _copy(value)

    def is_affected(self, receipt_hash: str) -> bool:
        return self.affected(receipt_hash) is not None

    def snapshot(self) -> dict[str, Any]:
        edges = sorted(
            (_copy(value) for value in self._edges.values()),
            key=lambda item: item["sequence"],
        )
        affected = {
            key: _copy(self._affected[key])
            for key in sorted(self._affected)
        }
        return {
            "schema": "openline.receiver_ancestry_closure.v1",
            "nodes": sorted(self._nodes),
            "edges": edges,
            "edge_sequence": self._edge_sequence,
            "processed_standing_event_ids": sorted(
                self._processed_standing_events
            ),
            "affected": affected,
            "closure_event_sequence": self._closure_event_sequence,
        }


class ClosureAwareStandingView(ReceiverStandingView):
    """Current standing plus receiver-owned downstream consequence closure."""

    def __init__(
        self,
        trusted_issuers: Mapping[str, str],
        *,
        closure_view: ReceiverAncestryClosureView,
        durable_path: str | None = None,
    ) -> None:
        if not isinstance(closure_view, ReceiverAncestryClosureView):
            raise AncestryClosureError("ancestry_closure_view_invalid")
        super().__init__(trusted_issuers, durable_path=durable_path)
        self._closure_view = closure_view
        # Heal the split-brain where a 001 head commit survived but the
        # ancestry loss op did not: re-derive missing losses from the
        # authoritative head frontier. Idempotent; fail closed.
        if self._durable is not None and closure_view.durable:
            closure_view.reconcile_from_heads(self._heads_snapshot())

    @property
    def closure_view(self) -> ReceiverAncestryClosureView:
        return self._closure_view

    def admit(self, projection: Mapping[str, Any], *, now=None) -> dict[str, Any]:
        # Persistence order: the 001 head commit lands first. If the
        # ancestry loss op then fails to commit, the loss is still
        # installed in memory from the authoritative just-written head
        # (this process cannot widen), the admission is refused, and the
        # next durable construction reconciles the log.
        admitted = super().admit(projection, now=now)
        result = dict(admitted)
        if admitted["standing"] != "ACTIVE":
            try:
                closure = self._closure_view.apply_standing_loss(
                    support_hash=str(admitted["support_hash"]),
                    standing_event_id=str(admitted["head_hash"]),
                    standing_event_sequence=int(admitted["sequence"]),
                )
            except Exception:
                try:
                    self._closure_view._apply_loss_memory_only(
                        support_hash=str(admitted["support_hash"]),
                        standing_event_id=str(admitted["head_hash"]),
                        standing_event_sequence=int(admitted["sequence"]),
                    )
                except Exception:
                    pass
                raise
            result["closure"] = closure
        return result


def closure_aware_standing_requirement_source(
    view: ReceiverStandingView,
    *,
    closure_view: ReceiverAncestryClosureView,
    support_source: Callable[[ToolCallContext], Mapping[str, Any] | None],
    projection_source: Callable[[ToolCallContext], Mapping[str, Any] | None],
    action_hash_source: Callable[[ToolCallContext], str] = standing_action_hash_from_call,
    evidence_issuer_id: str = "receiver_standing",
    max_assertion_ttl_seconds: int = 60,
    now_source=None,
) -> Callable[[ToolCallContext], EvidenceAssertion | None]:
    """Add transitive affected-state enforcement to the existing standing seam."""
    if not isinstance(closure_view, ReceiverAncestryClosureView):
        raise AncestryClosureError("ancestry_closure_view_invalid")

    kwargs = {
        "support_source": support_source,
        "projection_source": projection_source,
        "action_hash_source": action_hash_source,
        "evidence_issuer_id": evidence_issuer_id,
        "max_assertion_ttl_seconds": max_assertion_ttl_seconds,
    }
    if now_source is not None:
        kwargs["now_source"] = now_source

    base = standing_requirement_source(view, **kwargs)

    def provide(call: ToolCallContext) -> EvidenceAssertion | None:
        assertion = base(call)
        if assertion is None:
            return None

        payload = dict(assertion.payload)
        support_hash = payload.get("support_hash")
        affected = (
            closure_view.affected(str(support_hash))
            if isinstance(support_hash, str)
            else None
        )
        if affected is None:
            return assertion

        payload["closure_state"] = affected["state"]
        payload["closure_causal_path"] = affected["causal_path"]
        payload["closure_upstream_support_hash"] = affected[
            "upstream_support_hash"
        ]
        payload["closure_standing_event_id"] = affected[
            "standing_event_id"
        ]
        payload["closure_event_sequence"] = affected[
            "closure_event_sequence"
        ]

        return replace(
            assertion,
            payload=payload,
            revoked=True,
        )

    return provide
