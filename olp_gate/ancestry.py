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
from typing import Any, Callable, Mapping, Sequence

from .standing import (
    ReceiverStandingView,
    standing_action_hash_from_call,
    standing_requirement_source,
    support_receipt_hash,
)
from .tool_adapter import EvidenceAssertion, ToolCallContext


AFFECTED_STATE = "AFFECTED_UPSTREAM_STANDING_LOSS"
RELATIONSHIP = "BASIS_FOR"
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

    def __init__(self) -> None:
        self._nodes: set[str] = set()
        self._edges: dict[tuple[str, str], dict[str, Any]] = {}
        self._children: dict[str, set[str]] = {}
        self._parent_by_child: dict[str, str] = {}
        self._edge_sequence = 0

        self._processed_standing_events: dict[str, dict[str, Any]] = {}
        self._affected: dict[str, dict[str, Any]] = {}
        self._closure_event_sequence = 0

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
        """
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

        pair = (support_hash, derived_hash)
        existing = self._edges.get(pair)
        if existing is not None:
            if existing["decision_id"] != decision_id:
                raise AncestryClosureError("ancestry_duplicate_edge_conflict")
            return {
                "admitted": True,
                "created": False,
                "edge": _copy(existing),
            }

        existing_parent = self._parent_by_child.get(derived_hash)
        if existing_parent is not None and existing_parent != support_hash:
            raise AncestryClosureError("ancestry_multi_basis_not_supported")

        if support_hash == derived_hash or self._path_exists(
            derived_hash, support_hash
        ):
            raise AncestryClosureError("ancestry_cycle_forbidden")

        sequence = self._edge_sequence + 1
        edge = {
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

        self._edge_sequence = sequence
        self._nodes.add(support_hash)
        self._nodes.add(derived_hash)
        self._edges[pair] = edge
        self._children.setdefault(support_hash, set()).add(derived_hash)
        self._parent_by_child[derived_hash] = support_hash

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

    def apply_standing_loss(
        self,
        *,
        support_hash: str,
        standing_event_id: str,
        standing_event_sequence: int,
    ) -> dict[str, Any]:
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

        prior = self._processed_standing_events.get(standing_event_id)
        if prior is not None:
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

        newly_affected: list[str] = []
        for receipt_hash in ordered_descendants:
            if receipt_hash in self._affected:
                continue
            self._closure_event_sequence += 1
            event = {
                "receipt_hash": receipt_hash,
                "state": AFFECTED_STATE,
                "upstream_support_hash": support_hash,
                "standing_event_id": standing_event_id,
                "standing_event_sequence": standing_event_sequence,
                "closure_event_sequence": self._closure_event_sequence,
                "causal_path": list(paths[receipt_hash]),
            }
            self._affected[receipt_hash] = event
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
            "closure_event_sequence_after": self._closure_event_sequence,
            "replayed": False,
        }

        self._processed_standing_events[standing_event_id] = {
            "support_hash": support_hash,
            "standing_event_sequence": standing_event_sequence,
            "result": _copy(result),
        }
        return _copy(result)

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
    ) -> None:
        if not isinstance(closure_view, ReceiverAncestryClosureView):
            raise AncestryClosureError("ancestry_closure_view_invalid")
        super().__init__(trusted_issuers)
        self._closure_view = closure_view

    @property
    def closure_view(self) -> ReceiverAncestryClosureView:
        return self._closure_view

    def admit(self, projection: Mapping[str, Any], *, now=None) -> dict[str, Any]:
        admitted = super().admit(projection, now=now)
        result = dict(admitted)
        if admitted["standing"] != "ACTIVE":
            closure = self._closure_view.apply_standing_loss(
                support_hash=str(admitted["support_hash"]),
                standing_event_id=str(admitted["head_hash"]),
                standing_event_sequence=int(admitted["sequence"]),
            )
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
