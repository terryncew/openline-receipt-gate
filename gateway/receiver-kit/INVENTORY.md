# Receiver Kit Inventory

Every component an external receiver needs, where it lives, and what
it does. All paths relative to the repo root.

## Authority contracts (do not modify)

| Path | Source | What it is |
|------|--------|-----------|
| `gateway/openline_wallet/__init__.py` | openline-wallet@c46e82a | Package exports |
| `gateway/openline_wallet/wallet.py` | openline-wallet@c46e82a | `Wallet`: grant/revoke/export_bundle |
| `gateway/openline_wallet/receiver.py` | openline-wallet@c46e82a | `ReferenceGate`: pin/admit/challenge/evaluate |
| `gateway/openline_wallet/crypto.py` | openline-wallet@c46e82a | Ed25519, hashing, signatures |
| `gateway/openline_wallet/canonical.py` | openline-wallet@c46e82a | Canonical JSON |
| `gateway/openline_wallet/clock.py` | openline-wallet@c46e82a | Time parsing |
| `gateway/openline_wallet/errors.py` | openline-wallet@c46e82a | `WalletError` |
| `gateway/openline_wallet/storage.py` | openline-wallet@c46e82a | Wallet state persistence |
| `gateway/openline_wallet/VENDOR-README.md` | receiver-001 | Vendoring provenance |

## Receiver integration

| Path | What it is |
|------|-----------|
| `gateway/wallet_bridge.py` | `WalletReceiver`: wraps `ReferenceGate` with receiver-side action policies. `worker_present()`: worker-side presentation helper. |
| `gateway/demo_wallet_integration.py` | 10/10 demonstration: grant → admit → allow → revoke → stale/denied → worker replacement. Run it: `python3 gateway/demo_wallet_integration.py` |

## Starter kit docs

| Path | What it is |
|------|-----------|
| `gateway/receiver-kit/README.md` | Overview, 5-minute path, trust model summary, honest limits |
| `gateway/receiver-kit/INVENTORY.md` | This file |
| `gateway/receiver-kit/TRUST-MODEL.md` | Pinning, freshness bounds, revocation semantics, failure modes |

## Worked examples

| Path | What it demonstrates |
|------|---------------------|
| `gateway/receiver-kit/examples/01-minimal-receiver.py` | The smallest possible receiver: pin, admit, challenge, decide. |
| `gateway/receiver-kit/examples/02-worker-replacement.py` | Key rotation: new worker, same mandate scopes, same permissions. |
| `gateway/receiver-kit/examples/03-revocation.py` | Revocation flow: old proofs stale, new proofs denied. |

## Full gateway (separate deployment)

The Envoy + authz service + mock API stack is the production-shaped
receiver. It's not required for the kit examples.

| Path | What it is |
|------|-----------|
| `gateway/docs/ARCHITECTURE.md` | System design |
| `gateway/docs/QUICKSTART.md` | Local run instructions |
| `gateway/compose/` | Docker Compose (CI-verified) |
| `gateway/authz_server.py` | gRPC authz service (Envoy ext_authz) |
| `gateway/mock_api.py` | Mock consequential API |
| `gateway/olp_gate/` | Mandate evaluation logic |
