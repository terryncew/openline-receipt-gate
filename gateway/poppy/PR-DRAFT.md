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

## Review findings addressed (2026-10-11)

### 1. Complete request path (no substitutions)
`test_gateway_path.py`: **18/18** via the full path:
`client -> Envoy :8080 -> authz :50051 (ext_authz) -> mockapi :9000 -> ledger`.
The direct-header verification bypass was **removed**. The endpoint
requires a real Gateway decision token minted by the live authz service.

### 2. One-use approval semantics
A transaction approval authorizes exactly ONE execution. Distinguishes:
- "Owner approved these terms" (the mandate, scoped to operation hash)
- "Owner approved this execution" (the one-use approval)

Second execution with a fresh challenge → `403 TRANSACTION_APPROVAL_ALREADY_USED`.
Tested in `test_gateway_path.py` Case 3.

### 3. Bypass closed, amount binding enforced
- Direct-header bypass **removed** from `/poppy-charge`.
- Amount binding: the Gateway token's `value_cents` must **exactly**
  equal the operation's `amount_cents`. An action signed for $0 cannot
  authorize a $42.50 execution, even with a $50 mandate ceiling.
  → `403 AMOUNT_BINDING_MISMATCH` (Case 4).
- Nonce, timestamp, mandate, revocation, and replay checks preserved
  (via the live authz + Wallet contracts).

### 4. Signed receiver receipts with separate evidence
Each successful charge returns a signed receipt with:
- `decision_evidence`: the business decision (ALLOWED), delegated
  authority verification, transaction approval verification, amount
  binding proof.
- `effect_evidence`: the measured ledger effect (treasury/merchant
  before/after/delta).
- `receiver_signature`: Ed25519 signature, independently verifiable
  with the included public key.

Verified in `test_gateway_path.py` Case 2.

### Concurrency and restart
`test_concurrent_restart.py`: **5/5**
- 10 concurrent requests with the same approval: exactly one wins,
  others rejected (no double-spend).
- Restart: used approval persists in sqlite; replay after restart
  → `403 TRANSACTION_APPROVAL_ALREADY_USED`.

### Performance (full path, n=50, local)
`bench_gateway.py` via Envoy → authz → mockapi:
- Baseline (delegated only): p50 8.68ms, p95 15.02ms, p99 18.03ms
- Extended (delegated + approval): p50 8.05ms, p95 19.96ms, p99 28.05ms
- Incremental: p50 -0.63ms, p95 +4.93ms, p99 +10.02ms (run 1);
  p50 +1.72ms, p95 +1.61ms, p99 +5.76ms (run 2)

Local only. Not production claims. The 0.66ms standalone result is
superseded; this is the end-to-end measurement.

## The strict distinction

1. **Delegated authority**: agent permitted within limits (Gateway mandate).
   Proves the AGENT is permitted. Never proof of human approval.
2. **Transaction approval**: owner explicitly authorized one exact operation
   (Wallet mandate, scope = operation hash). Proves the HUMAN approved
   THIS execution (one-use).

The business API requires BOTH. Delegated alone →
`DELEGATED_AUTHORITY_NOT_TRANSACTION_APPROVAL`. Never conflated.

## Original prototype

- `poppy_session.py` — faithful Poppy 0.1: poppy.json, OAuth-style
  sign-in, DPoP-bound JWTs.
- `poppy_receiver.py` — standalone verifier (unit-level).
- `demo_poppy_proof.py` — 11/11. `test_poppy_proof.py` — 16/16.
- `poppy_native_baseline.py` — honest gap: Poppy-native allows $99.99
  the owner never signed for (coarse scopes, not a flaw).

## What remains

1. **Do not merge** without explicit order.
2. Performance optimization deferred to Codex phase.
3. No real OAuth, no real payments, single receiver — documented.

## Divergence

Additive: `gateway/poppy/` (new) + `/poppy-*` endpoints in
`gateway/mock_api.py` (experimental, documented). No existing behavior
changed. No new repos. No frozen records altered. Built on the
verified Gateway core (identical to subscription-001 post-PR-#103).
