#!/usr/bin/env python3
"""POPPY-PROOF-001: Poppy-native baseline (no OpenLine extension).

Implements the SAME operation using ONLY Poppy Draft 0.1 mechanisms,
faithfully — no weakening:

- Agent discovers poppy.json, user signs in via OAuth, gets a
  DPoP-bound session JWT with write scope.
- The company checks: session valid? scope == write? Then it applies
  its OWN policy (e.g., amount under a per-session limit).
- There is NO owner-signed exact-terms mandate. The company cannot
  tell whether the owner authorized THIS EXACT operation — only that
  the user granted write scope in this session.

This baseline is the honest comparison point. It is not weakened:
DPoP binding, short-lived JWTs, and company-side revocation all work.
The demonstrated difference is exactly one thing: the owner never
signed the exact operation terms.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from poppy_session import PoppyCompany  # noqa: E402


class PoppyNativeReceiver(PoppyCompany):
    """A Poppy company using ONLY draft-0.1 mechanisms.

    Policy: allow write-scoped sessions to charge up to a per-company
    limit. This is what a conscientious Poppy-0.1 company would do —
    coarse, company-defined, not owner-signed per operation.
    """

    def __init__(self, org_name: str, org_id: str,
                 per_charge_limit_cents: int = 10000):
        super().__init__(org_name, org_id)
        self.per_charge_limit_cents = per_charge_limit_cents
        self._ledger: dict[str, int] = {}
        self._log: list[dict[str, Any]] = []

    def fund(self, account: str, cents: int) -> None:
        self._ledger[account] = self._ledger.get(account, 0) + cents

    def balance(self, account: str) -> int:
        return self._ledger.get(account, 0)

    def decide_native(
        self,
        *,
        operation: Mapping[str, Any],
        session_token: str,
        dpop_public_key: str,
    ) -> dict[str, Any]:
        """Decide using ONLY Poppy-0.1 session + company policy."""
        now = datetime.now(timezone.utc)
        sess = self.verify_session(session_token, dpop_public_key, now=now)
        if not sess["valid"]:
            return {"decision": "STOPPED",
                    "reason": f"POPPY_{sess['reason']}",
                    "decided_at": now.isoformat()}
        if sess["claims"].get("scope") != "write":
            return {"decision": "STOPPED", "reason": "POPPY_SCOPE_INSUFFICIENT",
                    "decided_at": now.isoformat()}

        # Company policy: per-charge limit. This is the company's rule,
        # not the owner's signature on exact terms.
        amount = int(operation.get("amount_cents", 0))
        if amount > self.per_charge_limit_cents:
            return {"decision": "STOPPED", "reason": "COMPANY_POLICY_LIMIT",
                    "decided_at": now.isoformat()}

        account = operation["account"]
        merchant = operation["merchant"]
        if self._ledger.get(account, 0) < amount:
            return {"decision": "STOPPED", "reason": "INSUFFICIENT_FUNDS",
                    "decided_at": now.isoformat()}
        self._ledger[account] -= amount
        self._ledger[merchant] = self._ledger.get(merchant, 0) + amount
        record = {
            "decision": "ALLOWED",
            "reason": "POPPY_SESSION_VALID_AND_COMPANY_POLICY",
            "operation": dict(operation),
            "decided_at": now.isoformat(),
            # NOTE: no owner signature, no exact-terms binding, no signed
            # receipt. The company acted on its own policy judgment.
            "owner_authorized_exact_terms": False,
        }
        self._log.append(record)
        return record


def main() -> int:
    """Demonstrate the baseline: what Poppy 0.1 alone can and cannot do."""
    from poppy_session import PoppyAgent

    print("Poppy-native baseline (draft 0.1 only, no OpenLine extension)\n")
    rx = PoppyNativeReceiver("Manzanita Supply", "manzanita")
    rx.fund("owner-checking", 100000)
    agent = PoppyAgent("atlas")
    sess = agent.open_session(rx, user_id="user_123", access_choice="write")

    operation = {
        "type": "charge", "merchant": "manzanita-supply",
        "account": "owner-checking", "amount_cents": 4250,
        "currency": "USD",
        "items": [{"sku": "JKT-RAIN-042", "qty": 1, "price_cents": 4250}],
        "order_ref": "ord_native_001",
    }
    r = rx.decide_native(
        operation=operation, session_token=sess["session_token"],
        dpop_public_key=agent.dpop_public_key)
    print(f"legitimate $42.50 charge: {r['decision']} ({r['reason']})")
    print(f"  owner_authorized_exact_terms: {r.get('owner_authorized_exact_terms')}")

    # The gap: an agent with a valid write session can charge a DIFFERENT
    # amount/merchant within company policy. Nothing ties the charge to
    # what the owner actually approved.
    sneaky = dict(operation)
    sneaky["amount_cents"] = 9999  # under the $100 company limit
    sneaky["order_ref"] = "ord_native_002"
    r2 = rx.decide_native(
        operation=sneaky, session_token=sess["session_token"],
        dpop_public_key=agent.dpop_public_key)
    print(f"\nagent-initiated $99.99 charge (same session): {r2['decision']} ({r2['reason']})")
    print("  The owner never signed for $99.99. Poppy 0.1 cannot tell.")
    print("  This is the gap the OpenLine extension fills — not a Poppy flaw,")
    print("  but a documented limitation of coarse OAuth scopes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
