#!/usr/bin/env python3
"""POPPY-PROOF-001 demonstration: owner-controlled authority for a Poppy operation.

Scenario: A personal agent wants to place a $42.50 order at Manzanita
Supply (a Poppy company) on the owner's behalf.

Poppy-native flow (draft 0.1): agent discovers poppy.json, user signs in
via OAuth, agent gets a DPoP-bound session JWT with write scope, calls
the order API. The company checks the session — but nothing binds the
owner's signature to THE EXACT ORDER ($42.50, these items, this merchant).

OpenLine extension: the owner signs a Wallet mandate whose scope encodes
the exact operation hash. The receiver verifies the Poppy session AND
the owner-signed mandate before the ledger moves. Every decision gets a
signed, independently verifiable receipt.

Fictional owner, agent, merchant, and funds. No real payments.
Exit 0 only if every assertion holds.
"""

from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from openline_wallet import Wallet  # noqa: E402
from openline_wallet.crypto import public_key_hex  # noqa: E402
from poppy_session import PoppyAgent, POPPY_SPEC_VERSION  # noqa: E402
from poppy_receiver import (  # noqa: E402
    PoppyReceiver,
    mandate_scope_for_operation,
    operation_terms_hash,
)
from wallet_bridge import worker_present  # noqa: E402

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((PASS if cond else FAIL, name))
    print(f"[{PASS if cond else FAIL}] {name}" + (f" — {detail}" if detail else ""))


def main() -> int:
    print(f"Poppy spec: Draft {POPPY_SPEC_VERSION} (2026-10-09, personalagentprotocol.org)")
    now = datetime.now(timezone.utc)

    # ---- The exact operation the owner wants to authorize ----
    operation = {
        "type": "charge",
        "merchant": "manzanita-supply",
        "account": "owner-checking",
        "amount_cents": 4250,
        "currency": "USD",
        "items": [{"sku": "JKT-RAIN-042", "qty": 1, "price_cents": 4250}],
        "order_ref": "ord_20261011_001",
    }
    op_hash = operation_terms_hash(operation)
    print(f"operation hash: {op_hash[:16]}...")

    with tempfile.TemporaryDirectory() as tmp:
        # ---- 1. Owner creates Wallet, grants mandate for EXACT terms ----
        wallet = Wallet.create(tmp)
        principal_id = wallet.principal_id
        root_pub = wallet.root_public_key

        agent_key = Ed25519PrivateKey.generate()
        agent_pub = public_key_hex(agent_key)
        scope = mandate_scope_for_operation(operation)
        mandate = wallet.grant(
            subject_id="agent-atlas",
            subject_public_key=agent_pub,
            scopes=[scope],
            expires_at=now + timedelta(hours=1),
        )
        mandate_id = mandate["data"]["mandate_id"]
        check("owner grants mandate for exact operation terms",
              mandate["event_type"] == "MANDATE_ISSUED",
              f"scope {scope[:40]}...")

        bundle = wallet.export_bundle(ttl_seconds=300)

        # ---- 2. Receiver (Manzanita Supply) pins owner, admits bundle ----
        rx = PoppyReceiver("Manzanita Supply", "manzanita")
        rx.pin_owner(principal_id, root_pub)
        rx.admit_authority_bundle(bundle)
        rx.fund("owner-checking", 10000)  # $100.00
        check("receiver pins owner and admits authority bundle", True)
        check("poppy.json is version 0.1",
              rx.discovery_doc()["poppy_version"] == "0.1")

        # ---- 3. Agent: discover, session, user sign-in (Poppy 0.1) ----
        agent = PoppyAgent("atlas")
        agent.discover(rx)
        sess = agent.open_session(rx, user_id="user_123", access_choice="write")
        check("Poppy session opened (DPoP-bound JWT, write scope)",
              sess["scope"] == "write")

        # ---- 4. Agent presents operation + session + mandate ----
        # The action is the operation's terms hash (exact-terms binding).
        op_action = mandate_scope_for_operation(operation)
        ch = rx.authority.issue_challenge(principal_id, "agent-atlas", op_action)
        pres = worker_present(
            bundle=bundle, mandate_id=mandate_id,
            subject_id="agent-atlas", subject_key=agent_key,
            action=op_action, challenge=ch,
        )
        receipt = rx.decide(
            operation=operation,
            session_token=sess["session_token"],
            dpop_public_key=agent.dpop_public_key,
            presentation=pres,
            principal_id=principal_id,
        )
        check("receiver ALLOWS exact authorized operation",
              receipt["decision"] == "ALLOWED",
              f"receipt {receipt['receipt_id']}")
        check("ledger moved exactly $42.50",
              rx.balance("owner-checking") == 5750
              and rx.balance("manzanita-supply") == 4250,
              f"checking={rx.balance('owner-checking')} merchant={rx.balance('manzanita-supply')}")
        check("receipt signature verifies independently",
              rx.verify_receipt(receipt))

        # ---- 5. Agent claims approval but presents NO mandate ----
        receipt2 = rx.decide(
            operation=operation,
            session_token=sess["session_token"],
            dpop_public_key=agent.dpop_public_key,
            presentation=None,
            principal_id=principal_id,
        )
        check("no mandate -> STOPPED (agent assertion insufficient)",
              receipt2["decision"] == "STOPPED"
              and "AUTHORITY_NOT_PRESENTED" in receipt2["reason_codes"],
              f"reasons {receipt2['reason_codes']}")
        check("no ledger movement on STOPPED",
              rx.balance("owner-checking") == 5750,
              "balance unchanged")

        # ---- 6. Changed operation details (amount tampered) ----
        tampered = dict(operation)
        tampered["amount_cents"] = 42500  # $425.00 instead of $42.50
        # The tampered operation has a different hash -> different action.
        # The agent's mandate (for the original hash) cannot authorize it.
        # We present with the ORIGINAL action (what the mandate covers);
        # the receiver computes the action from the PRESENTED operation.
        ch3 = rx.authority.issue_challenge(principal_id, "agent-atlas", op_action)
        pres3 = worker_present(
            bundle=bundle, mandate_id=mandate_id,
            subject_id="agent-atlas", subject_key=agent_key,
            action=op_action, challenge=ch3,
        )
        receipt3 = rx.decide(
            operation=tampered,
            session_token=sess["session_token"],
            dpop_public_key=agent.dpop_public_key,
            presentation=pres3,
            principal_id=principal_id,
        )
        check("tampered amount -> STOPPED (terms mismatch)",
              receipt3["decision"] == "STOPPED",
              f"reasons {receipt3['reason_codes']}")
        check("no ledger movement on tampered operation",
              rx.balance("owner-checking") == 5750)

    n_fail = sum(1 for s, _ in results if s == FAIL)
    print(f"\n{len(results) - n_fail}/{len(results)} checks passed")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
