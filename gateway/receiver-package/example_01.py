#!/usr/bin/env python3
"""Example 01: Minimal receiver.

The smallest possible external receiver: pin an owner, admit their
bundle, issue a challenge, evaluate a worker's presentation.

Run: python3 gateway/receiver-kit/examples/01-minimal-receiver.py
Needs: cryptography (pip install cryptography)
"""

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / ".." / ".."))  # gateway/
sys.path.insert(0, str(HERE / ".." / ".." / "openline_wallet"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from openline_receiver.openline_wallet import Wallet
from openline_receiver.openline_wallet.crypto import public_key_hex
from openline_receiver.wallet_bridge import WalletReceiver, worker_present

# --- Owner: create a wallet, grant a mandate to a worker ---
with tempfile.TemporaryDirectory() as tmp:
    owner = Wallet.create(tmp)
    worker_key = Ed25519PrivateKey.generate()
    mandate = owner.grant(
        subject_id="worker-1",
        subject_public_key=public_key_hex(worker_key),
        scopes=["read_reports"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    bundle = owner.export_bundle(ttl_seconds=300)
    print(f"owner: {owner.principal_id[:32]}...")
    print(f"mandate: {mandate['data']['mandate_id']}")

    # --- Receiver: pin the owner's key (out-of-band trust) ---
    rx = WalletReceiver("my-receiver-1")
    # In production, you'd get this key via a trusted channel.
    # Here we copy it directly to show the mechanism.
    rx.pin_owner(owner.principal_id, owner.root_public_key)
    rx.protect_action("read_reports", ["read_reports"])
    print("receiver: owner pinned")

    # --- Receiver: admit the signed bundle (checks freshness) ---
    result = rx.admit_bundle(bundle)
    print(f"receiver: {result['decision']}")

    # --- Worker: get a challenge, sign a presentation ---
    challenge = rx.issue_challenge(owner.principal_id, "worker-1", "read_reports")
    presentation = worker_present(
        bundle=bundle,
        mandate_id=mandate["data"]["mandate_id"],
        subject_id="worker-1",
        subject_key=worker_key,
        action="read_reports",
        challenge=challenge,
    )
    print("worker: presentation signed")

    # --- Receiver: evaluate (this is the consequence-time decision) ---
    decision = rx.authorize(presentation, "read_reports")
    print(f"receiver: {decision['decision']}")
    if decision["decision"] == "ALLOWED":
        print("The worker may read reports. The receiver signed a receipt.")
    else:
        print(f"Denied: {decision.get('reason_codes')}")
