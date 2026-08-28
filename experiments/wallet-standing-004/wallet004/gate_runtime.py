"""Adapter from durable process state to the frozen wallet003 interfaces."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import os
from typing import Any, Mapping

from wallet001 import AdmissionPolicy
from wallet002 import ReceiverRootView, RootHistoryEntry
from wallet003 import (
    evaluate_distributed_bundle,
    ingest_guardian_freeze,
    ingest_root_checkpoint,
    ingest_root_succession,
    initialize_distributed_gate,
)
from wallet003.distribution import ActiveFreeze, DistributedGateState, RootCheckpoint, SuccessionRecord

from .envelope import verify_envelope
from .store import DurableStore


def state_to_dict(state: DistributedGateState) -> dict[str, Any]:
    return asdict(state)


def state_from_dict(value: Mapping[str, Any]) -> DistributedGateState:
    rv = value["root_view"]
    root_view = ReceiverRootView(
        principal_id=rv["principal_id"],
        recovery_policy_hash=rv["recovery_policy_hash"],
        current_root_public_key=rv["current_root_public_key"],
        current_generation=int(rv["current_generation"]),
        root_history=tuple(RootHistoryEntry(**row) for row in rv.get("root_history", [])),
        accepted_event_hashes=tuple(rv.get("accepted_event_hashes", [])),
    )
    active = value.get("active_freeze")
    checkpoint = value.get("checkpoint")
    return DistributedGateState(
        gate_id=value["gate_id"],
        root_view=root_view,
        requires_checkpoint=bool(value["requires_checkpoint"]),
        active_freeze=ActiveFreeze(**active) if active else None,
        used_freeze_generations=tuple(value.get("used_freeze_generations", [])),
        seen_freeze_hashes=tuple(value.get("seen_freeze_hashes", [])),
        succession_records=tuple(SuccessionRecord(**row) for row in value.get("succession_records", [])),
        checkpoint=RootCheckpoint(**checkpoint) if checkpoint else None,
        fork_event_hashes=tuple(value.get("fork_event_hashes", [])),
    )


class GateRuntime:
    def __init__(
        self,
        *,
        gate_id: str,
        db_path: str,
        recovery_policy: Mapping[str, Any],
        trusted_policy_hash: str,
        measurement_public_key: str,
        requires_checkpoint: bool,
    ) -> None:
        self.gate_id = gate_id
        self.recovery_policy = dict(recovery_policy)
        self.measurement_public_key = measurement_public_key
        self.store = DurableStore(db_path)
        stored, _revision = self.store.load()
        if stored is None:
            state = initialize_distributed_gate(
                self.recovery_policy,
                trusted_policy_hash=trusted_policy_hash,
                gate_id=gate_id,
                requires_checkpoint=requires_checkpoint,
            )
            self.store.initialize(state_to_dict(state))
            self.state = state
        else:
            self.state = state_from_dict(stored)

    def close(self) -> None:
        self.store.close()

    def _ingest_inner(self, kind: str, inner: Mapping[str, Any], now: datetime):
        if kind == "FREEZE":
            return ingest_guardian_freeze(self.state, self.recovery_policy, inner, now=now)
        if kind == "SUCCESSION":
            return ingest_root_succession(self.state, self.recovery_policy, inner, now=now)
        if kind == "CHECKPOINT":
            return ingest_root_checkpoint(self.state, self.recovery_policy, inner, now=now)
        raise ValueError("event_kind_invalid")

    def ingest(self, envelope: Mapping[str, Any], *, crash_before_commit: bool = False) -> dict[str, Any]:
        valid, reason = verify_envelope(envelope, measurement_public_key=self.measurement_public_key)
        if not valid:
            return {
                "ok": True,
                "gate_id": self.gate_id,
                "admitted": False,
                "decision": "REJECT_TRANSPORT_ENVELOPE",
                "reason": reason,
                "commit_complete_ns": None,
            }
        kind = str(envelope["kind"])
        now = datetime.now(timezone.utc)
        next_state, receipt = self._ingest_inner(kind, envelope["inner"], now)
        state_changed = next_state != self.state
        if crash_before_commit and state_changed:
            # Fault injection belongs to the transport/durability substrate. No DB write,
            # no ACK. The parent test must observe socket loss and then restart the Gate.
            os._exit(86)
        timing = None
        if state_changed:
            event_hash = None
            inner = envelope["inner"]
            if isinstance(inner, Mapping):
                event_hash = inner.get("event_hash") or inner.get("payload_hash") or inner.get("checkpoint_hash")
            timing = self.store.commit_state(
                state=state_to_dict(next_state),
                kind=kind,
                event_hash=str(event_hash) if event_hash else None,
                receipt=dict(receipt),
            )
            self.state = next_state
        return {
            "ok": True,
            "gate_id": self.gate_id,
            "admitted": bool(state_changed),
            "receipt": dict(receipt),
            "revision": self.store.revision(),
            "commit_started_ns": timing["commit_started_ns"] if timing else None,
            "commit_complete_ns": timing["commit_complete_ns"] if timing else None,
            "emitted_ns": int(envelope["emitted_ns"]),
            "measurement_authority": "NONE",
        }

    def evaluate(
        self,
        *,
        bundle: Mapping[str, Any],
        expected_action: Mapping[str, Any],
        receiver_challenge: str,
        admission_policy: Mapping[str, Any],
    ) -> dict[str, Any]:
        policy = AdmissionPolicy(
            high_risk_max_witness_age_seconds=int(admission_policy["high_risk_max_witness_age_seconds"]),
            low_risk_max_offline_ttl_seconds=int(admission_policy["low_risk_max_offline_ttl_seconds"]),
            required_fields=tuple(admission_policy["required_fields"]),
            forbid_extra_disclosures=bool(admission_policy.get("forbid_extra_disclosures", True)),
        )
        receipt = evaluate_distributed_bundle(
            self.state,
            bundle,
            expected_action=expected_action,
            receiver_challenge=receiver_challenge,
            now=datetime.now(timezone.utc),
            policy=policy,
        )
        return {"ok": True, "gate_id": self.gate_id, "receipt": dict(receipt), "revision": self.store.revision()}

    def summary(self) -> dict[str, Any]:
        return {
            "ok": True,
            "gate_id": self.gate_id,
            "revision": self.store.revision(),
            "state": state_to_dict(self.state),
        }
