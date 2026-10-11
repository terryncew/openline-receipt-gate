# POPPY-PROOF-001: OpenLine authority-and-evidence extension for Poppy

**Branch:** `experiment/openline-poppy-proof-001`
**Status:** Review requested. **Do not merge.**

## What this is

A working prototype demonstrating that a receiving business can
independently verify owner-controlled authorization for a consequential
AI-agent operation under Poppy (Sierra/Meta's Personal Agent Protocol),
enforce its decision, and preserve verifiable evidence — without relying
on the agent's assertion of approval.

**Pinned spec:** Personal Agent Protocol Draft 0.1, published 2026-10-09
at https://personalagentprotocol.org (Apache 2.0). Verified 2026-10-11.

## The strict distinction (addition 2026-10-11)

1. **Delegated authority**: agent permitted within limits (Gateway mandate).
   Proves the AGENT is permitted. Never proof of human approval.
2. **Transaction approval**: owner explicitly authorized one exact operation
   (Wallet mandate, scope = operation hash). Proves the HUMAN approved.

The business API requires BOTH. Delegated alone →
`DELEGATED_AUTHORITY_NOT_TRANSACTION_APPROVAL`. Never conflated.

## Gateway integration (addition 2026-10-11)

Tested through the ACTUAL business API (real `mock_api.py` process):

- `gateway/mock_api.py`: experimental `/poppy-charge` endpoint enforcing
  both layers; test-only `/poppy-admit` and `/poppy-challenge`.
- `gateway/poppy/test_gateway_path.py`: **18/18** — delegated-only 403,
  delegated+approval 200 with ledger moving exactly $42.50, terms
  mismatch 403, revoked 403, bad signature 403, limit exceeded 403.
- `gateway/poppy/bench_gateway.py`: median incremental cost of
  transaction approval: **0.66ms** (local, n=30, real process).

## Original prototype (2026-10-11)

- `poppy_session.py` — faithful Poppy 0.1: poppy.json, OAuth-style
  sign-in, DPoP-bound JWTs.
- `poppy_receiver.py` — standalone verifier (unit-level).
- `demo_poppy_proof.py` — 11/11. `test_poppy_proof.py` — 16/16.
- `poppy_native_baseline.py` — honest gap: Poppy-native allows $99.99
  the owner never signed for (coarse scopes, not a flaw).
- `bench_poppy.py` — standalone: +0.38ms median.

## What remains

1. **Do not merge** without explicit order.
2. Performance optimization deferred to Codex phase.
3. No real OAuth, no real payments, single receiver — documented.

## Divergence

Additive: `gateway/poppy/` (new) + `/poppy-*` endpoints in
`gateway/mock_api.py` (experimental, documented). No existing behavior
changed. No new repos. No frozen records altered. Built on the
verified Gateway core (identical to subscription-001 post-PR-#103).
