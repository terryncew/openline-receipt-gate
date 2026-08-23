from __future__ import annotations
import asyncio, time
from dataclasses import dataclass, field

@dataclass
class AtomicReceiver:
    clean: set[str]
    tainted: set[str]
    unknown: set[str]
    arm: str
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    corrected: bool = False
    sequence: int = 0
    correction_sequence: int | None = None
    events: list[dict] = field(default_factory=list)

    async def _record(self, kind, authority, classification=None):
        self.sequence += 1
        event = {
            "sequence": self.sequence,
            "monotonic_ns": time.monotonic_ns(),
            "kind": kind,
            "authority": authority,
        }
        if classification is not None:
            event["classification"] = classification
        self.events.append(event)
        return event

    async def apply_correction(self):
        async with self._lock:
            self.corrected = True
            e = await self._record("APPLY_CORRECTION", "source")
            self.correction_sequence = e["sequence"]

    def _decision_now(self, authority):
        if self.arm == "NO_PROPAGATION":
            return "ALLOW"
        if self.arm == "GLOBAL_KILL":
            return "BLOCK" if self.corrected else "ALLOW"
        if authority in self.clean:
            return "ALLOW"
        if not self.corrected:
            return "ALLOW"
        if authority in self.tainted:
            return "BLOCK"
        if authority in self.unknown:
            return "QUARANTINE"
        return "QUARANTINE"

    async def precheck(self, authority):
        async with self._lock:
            decision = self._decision_now(authority)
            await self._record("PRECHECK", authority, decision)
            return decision

    async def stale_commit(self, earlier_decision, authority):
        # Deliberately wrong baseline: commit based on stale earlier decision.
        async with self._lock:
            if earlier_decision == "ALLOW":
                return await self._record("COMMIT", authority, earlier_decision)
            return await self._record(earlier_decision, authority, earlier_decision)

    async def atomic_commit(self, authority):
        # Correct design: decide and commit in one receiver-owned critical section.
        async with self._lock:
            decision = self._decision_now(authority)
            if decision == "ALLOW":
                return await self._record("COMMIT", authority, decision)
            return await self._record(decision, authority, decision)
