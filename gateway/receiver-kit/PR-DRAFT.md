# OPENLINE-RECEIVER-001: Independently installable receiver with portable Wallet authority

**Branch:** `experiment/openline-receiver-001`
**Status:** Review requested. **Do not merge** — P1 Docker verification pending.

## What this is

Turns the Gateway prototype into an independently installable receiver
integration that accepts portable OpenLine Wallet authority. An external
receiver (who did not issue the authority) can pin an owner's root key,
admit signed bundles, and enforce mandates at consequence time — with
explicit freshness bounds on revocation.

## Priority 1: Docker Compose verification

**Status:** [PENDING/COMPLETE — update before opening]

- Workflow: `.github/workflows/gateway-docker-verify.yml`
- Runs on `ubuntu-latest` (real Docker): builds the stack, waits for
  Envoy, runs `gateway/ci/docker_verify.py` (21 checks: signed transfers,
  tamper/replay 403s, ledger deltas, receipt verification, restart
  persistence, revocation).
- Fixes applied: STRICT_DNS for compose hostnames, init container
  (replaces racy entrypoint lock), MOCK_API_HOST=0.0.0.0, stale network
  cleanup.

## Priority 2: Wallet integration (COMPLETE, 10/10 locally)

- **Vendored contracts:** `gateway/openline_wallet/` (8 files from
  openline-wallet@c46e82a). The gateway does NOT invent a parallel
  authority format. See `VENDOR-README.md`.
- **Bridge:** `gateway/wallet_bridge.py` — `WalletReceiver` wraps
  `ReferenceGate` with receiver-side action policies.
- **Demo:** `gateway/demo_wallet_integration.py` — 10/10 checks:
  - Owner grants bounded mandate → receiver admits → worker ALLOWED
  - Owner revokes → old presentation STALE, fresh presentation REVOKED
  - Worker replacement (rotated key) → same scopes, ALLOWED
  - Wrong key → `SUBJECT_BINDING_MISMATCH`

Revocation is checked against the freshness-bounded admitted bundle
(`max_bundle_age_seconds=300`). Old bundles are not pretended to be live.

## Priority 3: Starter kit (COMPLETE)

`gateway/receiver-kit/`:
- `README.md` — overview, 5-minute path, honest limits
- `INVENTORY.md` — every component, where it lives
- `TRUST-MODEL.md` — pinning, freshness bounds, revocation semantics,
  failure modes
- `examples/01-minimal-receiver.py` — pin, admit, challenge, decide
- `examples/02-worker-replacement.py` — key rotation, same permissions
- `examples/03-revocation.py` — revoke flow, stale vs. denied
- `ECONOMIC-COMPARISON.md` — see P4

All examples run with `python3` + `cryptography`. No Docker required.

## Priority 4: Fair economic comparison (COMPLETE)

`gateway/receiver-kit/ECONOMIC-COMPARISON.md`:
- **Latency:** OpenLine ~140ms p50 overhead vs. OPA-A (measured). Buys
  replay protection, signed tokens, signed receipts, revocation.
- **Install:** OpenLine 3 steps; OPA-A 5 steps; OPA-B 8+ steps;
  "build it all" weeks.
- **Thesis:** Burden, not capability. A capable team *can* build this
  from Envoy+OPA. OpenLine is for teams that want the protections
  without building and maintaining them.
- **Honest "why not":** 140ms too much for HFT; already built it;
  don't need evidence; need Rego.

## Divergence from main

77 files, +8780 lines, all additive under `gateway/` (plus the CI
workflow and one `.gitignore` line). No existing code modified. No new
repos. No paid APIs. No public deployment.

## What remains

1. P1 Docker verification must go green (currently in progress).
2. External engineer invitation (drafted separately, unsent).
3. **Do not merge** without explicit order.
