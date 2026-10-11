# OpenLine Receiver

A minimal package for an **external receiver** — a party that did not issue
the authority — to verify owner-signed OpenLine mandates and enforce them.

## Installation

```bash
pip install ./gateway/receiver-package
# Or from the repo root:
# pip install git+https://github.com/terryncew/openline-receipt-gate.git#subdirectory=gateway/receiver-package
```

Requires Python 3.10+, `cryptography` package (installed automatically).

## 5-Minute Quickstart

```python
from openline_receiver.wallet_bridge import WalletReceiver

# 1. Create a receiver, pin the owner's root key (out-of-band)
receiver = WalletReceiver(gate_id="my-receiver-1")
owner_root_key_hex = "..."  # From the owner, via a channel you trust
receiver.pin_owner("owner-principal-id", owner_root_key_hex)

# 2. Admit the owner's signed bundle (grants, revocations)
bundle = {...}  # From the owner or their Wallet
result = receiver.admit_bundle(bundle)
assert result == "BUNDLE_ADMITTED"

# 3. Decide on a worker's presentation
from openline_receiver.wallet_bridge import worker_present
# (Worker signs with their mandate key; you verify)
decision = receiver.decide(presentation, action="read:reports")
if decision == "ALLOWED":
    # Do the consequential thing, then sign a receipt
    receipt = receiver.sign_receipt(decision, presentation)
else:
    # STOPPED: presentation was stale, revoked, or invalid
    pass
```

See `examples/` for complete worked examples.

## What's Included

- `openline_receiver/openline_wallet/`: Vendored OpenLine Wallet contracts.
  Do not modify. Source: `github.com/terryncew/openline-wallet`.
- `openline_receiver/wallet_bridge.py`: `WalletReceiver` class and
  `worker_present()` helper.

## What's NOT Included

- No gateway, no Envoy, no mock ledger. You bring your own consequential API.
- No network code. You decide how to receive bundles and presentations.
- No key distribution. See ENROLLMENT.md.

## Trust Model

See `../receiver-kit/TRUST-MODEL.md` for the full model. Short version:
1. You pin the owner's root key out-of-band. No PKI.
2. You admit signed bundles. Check freshness (≤ your max age).
3. Workers prove key ownership per action. You verify.

## Honest Limits

- Revocation is not instant. New bundles stop new presentations immediately;
  in-flight presentations live to their challenge TTL (60s default).
- This is a library, not a service. You operate it.
- SQLite is used for demo state; use your own store in production.
