"""COALITION-001: the single authoritative atomic consequence ledger.

Exactly one ledger exists per receiver. Check-and-consume is atomic under one
lock: the read of committed(origin), the bound comparison, and the increment
happen as one indivisible step, so no interleaving can slip two consumptions
past the bound. "Mechanically observable consequence" in this experiment is
exactly the committed-unit total per origin in this ledger.
"""

import threading


class AtomicLedger:
    def __init__(self):
        self._lock = threading.Lock()
        self._committed = {}        # origin_id -> int units committed
        self._entries = []          # committed consequence entries
        self._refusals = []         # refusal receipts
        self._consumed_nonces = set()
        self._abandoned_intents = set()
        self._abandoned_ops = []

    # ---- authorization bookkeeping (all under the same lock) ----

    def nonce_consumed(self, nonce):
        with self._lock:
            return nonce in self._consumed_nonces

    def consume_nonce(self, nonce):
        with self._lock:
            self._consumed_nonces.add(nonce)

    def intent_abandoned(self, intent_id):
        with self._lock:
            return intent_id in self._abandoned_intents

    def record_abandoned(self, op):
        with self._lock:
            self._abandoned_intents.add(op["intent_id"])
            self._abandoned_ops.append(op)

    # ---- the atomic check-and-consume primitive ----

    def try_consume(self, origin_id, units, bound):
        """Atomically: if committed(origin) + units <= bound, commit and return
        (True, new_total); otherwise return (False, current_total) and change
        nothing. There is no partial consumption."""
        with self._lock:
            current = self._committed.get(origin_id, 0)
            if current + units <= bound:
                self._committed[origin_id] = current + units
                return True, current + units
            return False, current

    def commit_unbounded(self, origin_id, units, entry):
        """Baseline mode only: commit with no bound check (per-action
        authorization without cumulative origin state)."""
        with self._lock:
            self._committed[origin_id] = self._committed.get(origin_id, 0) + units
            self._entries.append(entry)
            return self._committed[origin_id]

    def record_entry(self, entry):
        with self._lock:
            self._entries.append(entry)

    def record_refusal(self, receipt):
        with self._lock:
            self._refusals.append(receipt)

    # ---- read-only snapshot for observation ----

    def snapshot(self):
        with self._lock:
            return {
                "committed": dict(self._committed),
                "entries": list(self._entries),
                "refusals": list(self._refusals),
                "consumed_nonce_count": len(self._consumed_nonces),
                "abandoned_ops": list(self._abandoned_ops),
            }
