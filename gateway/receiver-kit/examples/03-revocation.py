#!/usr/bin/env python3
"""Example 03: Revocation.

Revocation is a new bundle. The owner revokes the mandate and exports
a fresh bundle. The receiver admits it. Two things happen:

1. Old presentations (bound to the old head) are STALE — they don't
   match the admitted bundle, so they're rejected without even
   checking the mandate.
2. Fresh presentations against the new bundle are evaluated against
   the revoked mandate and DENIED.

The old bundle is never pretended to contain live revocation info.
The freshness bound is explicit: max_bundle_age_seconds.

Run: python3 gateway/receiver-kit/examples/03-revocation.py
"""

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / ".." / ".."))
sys.path.insert(0, str(HERE / ".." / ".." / "openline_wallet"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from openline_wallet import Wallet
from openline_wallet.crypto import public_key_hex
from wallet_bridge import WalletReceiver, worker_present

ACTION = "spend_budget"
SCOPES = ["spend_budget"]

with tempfile.TemporaryDirectory() as tmp:
    owner = Wallet.create(tmp)
    worker_key = Ed25519PrivateKey.generate()
    mandate = owner.grant(
        subject_id="worker-1",
        subject_public_key=public_key_hex(worker_key),
        scopes=SCOPES,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    mid = mandate["data"]["mandate_id"]
    bundle_v1 = owner.export_bundle(ttl_seconds=300)

    rx = WalletReceiver("my-receiver-1", max_bundle_age_seconds=300)
    rx.pin_owner(owner.principal_id, owner.root_public_key)
    rx.protect_action(ACTION, SCOPES)
    rx.admit_bundle(bundle_v1)

    # Worker is allowed before revocation.
    ch = rx.issue_challenge(owner.principal_id, "worker-1", ACTION)
    d = rx.authorize(worker_present(
        bundle=bundle_v1, mandate_id=mid, subject_id="worker-1",
        subject_key=worker_key, action=ACTION, challenge=ch), ACTION)
    print(f"before revocation: {d['decision']}")

    # Owner revokes and exports a new bundle.
    owner.revoke(mid, reason="USER_REVOKED")
    bundle_v2 = owner.export_bundle(ttl_seconds=300)
    print(f"owner revoked; bundle head advanced")
    rx.admit_bundle(bundle_v2)
    print(f"receiver admitted bundle v2")

    # 1. Old presentation (head v1) -> STALE
    ch2 = rx.issue_challenge(owner.principal_id, "worker-1", ACTION)
    d_stale = rx.authorize(worker_present(
        bundle=bundle_v1, mandate_id=mid, subject_id="worker-1",
        subject_key=worker_key, action=ACTION, challenge=ch2), ACTION)
    print(f"old presentation: {d_stale['decision']} {d_stale.get('reason_codes')}")

    # 2. Fresh presentation (head v2) -> mandate is REVOKED
    ch3 = rx.issue_challenge(owner.principal_id, "worker-1", ACTION)
    d_rev = rx.authorize(worker_present(
        bundle=bundle_v2, mandate_id=mid, subject_id="worker-1",
        subject_key=worker_key, action=ACTION, challenge=ch3), ACTION)
    print(f"fresh presentation: {d_rev['decision']} {d_rev.get('reason_codes')}")

    print()
    print("Revocation bound: new presentations stop when the receiver")
    print("admits the new bundle. The receiver's refresh policy determines")
    print("how quickly that happens (here: manual, immediate).")
