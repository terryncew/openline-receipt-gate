#!/usr/bin/env python3
"""Example 02: Worker replacement.

The authorization is portable: when worker-1's key is rotated (or the
worker is replaced by a different model), the owner grants the same
mandate scopes to worker-2's fresh key. The receiver admits the new
bundle and worker-2 gets the same permissions. Nothing about the
receiver's policy changes.

Run: python3 gateway/receiver-kit/examples/02-worker-replacement.py
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

ACTION = "deploy_staging"
SCOPES = ["deploy_staging"]

with tempfile.TemporaryDirectory() as tmp:
    owner = Wallet.create(tmp)
    expiry = datetime.now(timezone.utc) + timedelta(hours=1)

    # Receiver setup (once; policy doesn't change across workers)
    rx = WalletReceiver("my-receiver-1")
    rx.pin_owner(owner.principal_id, owner.root_public_key)
    rx.protect_action(ACTION, SCOPES)

    # --- Worker 1: original ---
    w1_key = Ed25519PrivateKey.generate()
    m1 = owner.grant(subject_id="worker-1",
                     subject_public_key=public_key_hex(w1_key),
                     scopes=SCOPES, expires_at=expiry)
    rx.admit_bundle(owner.export_bundle(ttl_seconds=300))
    ch = rx.issue_challenge(owner.principal_id, "worker-1", ACTION)
    d1 = rx.authorize(worker_present(
        bundle=owner.export_bundle(ttl_seconds=300),
        mandate_id=m1["data"]["mandate_id"], subject_id="worker-1",
        subject_key=w1_key, action=ACTION, challenge=ch), ACTION)
    print(f"worker-1: {d1['decision']}")

    # --- Worker 1 is replaced. Owner grants worker-2 the same scopes. ---
    # (In practice: revoke worker-1's mandate first. Here we focus on
    # the portability: the new key gets the same permissions.)
    owner.revoke(m1["data"]["mandate_id"], reason="KEY_ROTATED")
    w2_key = Ed25519PrivateKey.generate()
    m2 = owner.grant(subject_id="worker-2",
                     subject_public_key=public_key_hex(w2_key),
                     scopes=SCOPES, expires_at=expiry)
    bundle2 = owner.export_bundle(ttl_seconds=300)
    rx.admit_bundle(bundle2)

    ch2 = rx.issue_challenge(owner.principal_id, "worker-2", ACTION)
    d2 = rx.authorize(worker_present(
        bundle=bundle2, mandate_id=m2["data"]["mandate_id"],
        subject_id="worker-2", subject_key=w2_key,
        action=ACTION, challenge=ch2), ACTION)
    print(f"worker-2 (rotated key): {d2['decision']}")
    print(f"same scopes: {SCOPES}")
    print("The mandate survived the worker. The receiver's policy didn't change.")

    # Worker-1's old key is now useless (mandate revoked).
    ch3 = rx.issue_challenge(owner.principal_id, "worker-1", ACTION)
    d3 = rx.authorize(worker_present(
        bundle=bundle2, mandate_id=m1["data"]["mandate_id"],
        subject_id="worker-1", subject_key=w1_key,
        action=ACTION, challenge=ch3), ACTION)
    print(f"worker-1 (old key, revoked): {d3['decision']} "
          f"{d3.get('reason_codes')}")
