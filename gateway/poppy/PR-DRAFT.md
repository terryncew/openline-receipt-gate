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

## The honest gap

Poppy 0.1 gives the company: user identity (OAuth sign-in) + coarse
scope (read/write). It does not bind the owner's signature to the exact
operation terms. A valid write-scoped session can charge $99.99 the
owner never approved for — demonstrated in `poppy_native_baseline.py`.
This is not a Poppy flaw; per-action authorization is on Poppy's stated
roadmap. This experiment shows one concrete way to fill it.

## What was built (`gateway/poppy/`)

- `poppy_session.py` — faithful Poppy 0.1: poppy.json discovery,
  OAuth-style sign-in, DPoP-bound short-lived session JWTs.
- `poppy_receiver.py` — receiver verifying BOTH layers: Poppy session
  (identity, draft 0.1) AND owner-signed Wallet mandate matching the
  exact operation hash (experimental extension). Signed decision
  receipts, simulated ledger effects only on ALLOWED.
- `demo_poppy_proof.py` — 11/11: end-to-end $42.50 order.
- `test_poppy_proof.py` — 16/16: revocation, replay, changed amount,
  changed merchant, stale bundle head, worker replacement, provider
  replacement, expired mandate, forged session, DPoP mismatch,
  company-revoked session.
- `poppy_native_baseline.py` — fair Poppy-only comparison (not weakened).
- `bench_poppy.py` — latency/complexity baseline.
- `POPPY-PROOF-001.md` — full design doc, trust boundaries,
  experimental-vs-standard table.

## Results

- Demo: 11/11. Tests: 16/16. All on the branch, reproducible with
  `python3` + `cryptography` (no Docker, no network, no paid APIs).
- Latency (n=50, local): native p50 0.16ms → extended p50 0.53ms.
  **Median added cost of exact-terms authority: 0.38ms.**
- Complexity: 4 moving parts (native) → 8 (extended).

## What remains

1. **Do not merge** without explicit order.
2. Performance optimization deferred to Codex phase (per work order).
3. No real OAuth server, no real payments, single receiver —
   documented in POPPY-PROOF-001.md.

## Divergence

All additive under `gateway/poppy/` on top of
`experiment/openline-receiver-001`. No existing code modified. No new
repos. No frozen records altered.
