# OpenLine External Receiver Starter Kit

**Status:** Prototype (OPENLINE-RECEIVER-001). The Docker Compose gateway
path is verified in CI; the Wallet integration demo passes 10/10 locally.
No external engineer has adopted this yet.

## What this is

A minimal kit for an **external receiver** — a party that did not issue
the authority — to accept portable OpenLine Wallet mandates and enforce
them at consequence time. You run the receiver. The owner runs the Wallet.
The worker carries the proof.

The kit reuses the Wallet's own contracts (`gateway/openline_wallet/`,
vendored from `github.com/terryncew/openline-wallet`). It does not invent
a parallel authority format.

## Who it's for

An engineer operating a consequential API (payments, deployments,
infrastructure, business systems) who wants to answer, per request:
"is this exact action allowed now, by whose authority, with what proof?"

## What's in the kit

| File | What it is |
|------|-----------|
| `README.md` (this file) | Overview, trust model, honest limits |
| `INVENTORY.md` | Every component, where it lives, what it does |
| `TRUST-MODEL.md` | Pinning, freshness bounds, revocation semantics |
| `examples/01-minimal-receiver.py` | Pin an owner, admit a bundle, allow/deny (30 lines of decisions) |
| `examples/02-worker-replacement.py` | Rotated worker key, same mandate, same permissions |
| `examples/03-revocation.py` | Revoke, admit new bundle, old proofs go stale |
| `../wallet_bridge.py` | `WalletReceiver`: the receiver integration |
| `../demo_wallet_integration.py` | Full 10/10 demonstration |
| `../openline_wallet/` | Vendored Wallet contracts (do not modify) |

## The 5-minute path

```bash
cd gateway
python3 receiver-kit/examples/01-minimal-receiver.py
```

This creates a fictional owner, grants a mandate, and runs a receiver
that pins the owner and decides. Read the example — it's 60 lines and
every step is commented.

## Trust model (short version)

1. **You pin the owner's root key out-of-band.** No PKI, no CA. You
   decide which owners you trust, by copying their root public key
   through a channel you trust.
2. **You admit signed bundles.** The bundle is the owner's signed
   statement of "who may do what." You verify the signature and check
   the bundle is fresh (≤ your `max_bundle_age_seconds`, default 300s).
3. **Workers prove key ownership per action.** The worker signs a
   challenge-bound presentation with the key named in its mandate.
   You verify the signature, the challenge, and the mandate status
   against the admitted bundle.
4. **Revocation is a new bundle.** When the owner revokes, they export
   a new bundle. You admit it. Old presentations go stale
   (`PRESENTATION_HEAD_STALE`); new ones are denied (`MANDATE_REVOKED`).

See `TRUST-MODEL.md` for the full semantics, including the freshness
bounds and what happens when bundles expire.

## What this does NOT do

- **No instant revocation.** If a worker holds a valid presentation and
  the bundle hasn't been updated, the mandate stands. The revocation
  bound is: new bundles stop new presentations immediately; in-flight
  presentations are valid to their challenge TTL (default 60s).
- **No global identity.** Subjects are keypairs. "worker-1" is a label;
  the key is the identity. Key rotation is explicit (new mandate).
- **No privacy.** Bundles contain the mandate history. Don't put
  secrets in mandates.
- **No production hardening.** This is a prototype. The crypto is
  standard (Ed25519), but the surrounding code has not been audited.
- **No hosted service.** You run the receiver. There is no OpenLine
  cloud to call.

## Requirements

- Python 3.11+
- `pip install cryptography`
- The vendored `openline_wallet` package (included)

No Docker, no network, no paid APIs for the examples. The full gateway
(Envoy + authz service) is a separate deployment; see
`gateway/docs/ARCHITECTURE.md`.
