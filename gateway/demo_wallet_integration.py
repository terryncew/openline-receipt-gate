#!/usr/bin/env python3
"""OPENLINE-RECEIVER-001 Priority 2: portable Wallet authority demo.

Demonstrates, with the real OpenLine Wallet contracts (not a parallel
format):

1. Owner creates a signed, bounded mandate (Wallet.grant).
2. A separately operated receiver pins the owner's root key (its own
   trust decision) and admits the signed bundle.
3. Worker-1 (fresh keypair) presents a challenge-bound proof and is
   ALLOWED — the authorization is portable, not tied to the worker's
   identity beyond its key.
4. Owner revokes. The receiver admits the new bundle. Worker-1's old
   presentation is STALE; a fresh presentation against the new bundle
   is REVOKED. Revocation is checked against the freshness-bounded
   admitted bundle — the old bundle is not pretended to be live.
5. Worker replacement: worker-2 (rotated key, separately issued
   credential) is granted the same mandate scopes, presents, and is
   ALLOWED with the same permissions. The mandate survived the worker.

Fictional owner, workers, and funds. No real payment processing.
Exit 0 only if every assertion holds.
"""

from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from openline_wallet import Wallet  # noqa: E402
from openline_wallet.crypto import public_key_hex  # noqa: E402
from wallet_bridge import WalletReceiver, worker_present  # noqa: E402

ACTION = "authorize_payment"
SCOPES = ["authorize_payment"]
PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((PASS if cond else FAIL, name))
    print(f"[{PASS if cond else FAIL}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        print(f"    DETAIL: {detail}")


def main() -> int:
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(hours=1)

    # ---- 1. Owner creates Wallet and grants a bounded mandate ----
    with tempfile.TemporaryDirectory() as tmp:
        wallet = Wallet.create(tmp)
        principal_id = wallet.principal_id
        root_pub = wallet.root_public_key
        print(f"owner principal: {principal_id}")

        worker1_key = Ed25519PrivateKey.generate()
        worker1_pub = public_key_hex(worker1_key)
        mandate = wallet.grant(
            subject_id="worker-1",
            subject_public_key=worker1_pub,
            scopes=SCOPES,
            expires_at=expiry,
        )
        mandate_id = mandate["data"]["mandate_id"]
        check("owner grants bounded mandate", mandate["event_type"] == "MANDATE_ISSUED",
              f"mandate {mandate_id}, scopes {SCOPES}")

        bundle_v1 = wallet.export_bundle(ttl_seconds=300)
        check("owner exports signed bundle v1", bool(bundle_v1.get("signature")),
              f"head {bundle_v1['head']['event_hash'][:16]}...")

        # ---- 2. Separately operated receiver pins trust, admits ----
        rx = WalletReceiver("gateway-demo-1", max_bundle_age_seconds=300)
        rx.pin_owner(principal_id, root_pub)
        rx.protect_action(ACTION, SCOPES)
        adm = rx.admit_bundle(bundle_v1)
        check("receiver admits bundle from pinned principal",
              adm.get("decision") == "BUNDLE_ADMITTED",
              f"head seq {adm.get('head_sequence')}")

        # ---- 3. Worker-1 presents, is ALLOWED ----
        ch = rx.issue_challenge(principal_id, "worker-1", ACTION)
        pres = worker_present(
            bundle=bundle_v1, mandate_id=mandate_id,
            subject_id="worker-1", subject_key=worker1_key,
            action=ACTION, challenge=ch,
        )
        dec = rx.authorize(pres, ACTION)
        check("worker-1 presentation ALLOWED",
              dec.get("decision") == "ALLOWED",
              f"decision {dec.get('decision')}")

        # ---- 4. Owner revokes; receiver admits the new bundle ----
        wallet.revoke(mandate_id, reason="USER_REVOKED")
        bundle_v2 = wallet.export_bundle(ttl_seconds=300)
        check("owner revokes and exports bundle v2",
              bundle_v2["head"]["event_hash"] != bundle_v1["head"]["event_hash"],
              "head advanced")
        adm2 = rx.admit_bundle(bundle_v2)
        check("receiver admits bundle v2",
              adm2.get("decision") == "BUNDLE_ADMITTED")

        # Old presentation (head v1) against admitted v2 -> STALE
        ch2 = rx.issue_challenge(principal_id, "worker-1", ACTION)
        stale_pres = worker_present(
            bundle=bundle_v1, mandate_id=mandate_id,
            subject_id="worker-1", subject_key=worker1_key,
            action=ACTION, challenge=ch2,
        )
        dec_stale = rx.authorize(stale_pres, ACTION)
        check("old presentation rejected as STALE",
              dec_stale.get("decision") == "STOPPED"
              and "PRESENTATION_HEAD_STALE" in dec_stale.get("reason_codes", []),
              f"reasons {dec_stale.get('reason_codes')}")

        # Fresh presentation against v2 -> REVOKED (mandate status)
        ch3 = rx.issue_challenge(principal_id, "worker-1", ACTION)
        fresh_pres = worker_present(
            bundle=bundle_v2, mandate_id=mandate_id,
            subject_id="worker-1", subject_key=worker1_key,
            action=ACTION, challenge=ch3,
        )
        dec_rev = rx.authorize(fresh_pres, ACTION)
        check("revoked mandate denied",
              dec_rev.get("decision") == "STOPPED"
              and any("REVOKED" in r for r in dec_rev.get("reason_codes", [])),
              f"reasons {dec_rev.get('reason_codes')}")

        # ---- 5. Worker replacement: rotated key, same mandate ----
        worker2_key = Ed25519PrivateKey.generate()
        worker2_pub = public_key_hex(worker2_key)
        mandate2 = wallet.grant(
            subject_id="worker-2",
            subject_public_key=worker2_pub,
            scopes=SCOPES,
            expires_at=expiry,
        )
        mandate2_id = mandate2["data"]["mandate_id"]
        bundle_v3 = wallet.export_bundle(ttl_seconds=300)
        rx.admit_bundle(bundle_v3)
        ch4 = rx.issue_challenge(principal_id, "worker-2", ACTION)
        pres2 = worker_present(
            bundle=bundle_v3, mandate_id=mandate2_id,
            subject_id="worker-2", subject_key=worker2_key,
            action=ACTION, challenge=ch4,
        )
        dec2 = rx.authorize(pres2, ACTION)
        check("worker-2 (rotated key) ALLOWED with same scopes",
              dec2.get("decision") == "ALLOWED",
              f"mandate {mandate2_id}, decision {dec2.get('decision')}")

        # Worker-1's key cannot impersonate worker-2's mandate
        ch5 = rx.issue_challenge(principal_id, "worker-2", ACTION)
        impostor = worker_present(
            bundle=bundle_v3, mandate_id=mandate2_id,
            subject_id="worker-2", subject_key=worker1_key,  # wrong key
            action=ACTION, challenge=ch5,
        )
        dec_imp = rx.authorize(impostor, ACTION)
        check("wrong key cannot use another worker's mandate",
              dec_imp.get("decision") == "STOPPED",
              f"reasons {dec_imp.get('reason_codes')}")

    n_fail = sum(1 for s, _ in results if s == FAIL)
    print(f"\n{len(results) - n_fail}/{len(results)} checks passed")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
