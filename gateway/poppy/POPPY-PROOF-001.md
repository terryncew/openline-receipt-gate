# POPPY-PROOF-001: OpenLine authority-and-evidence extension for Poppy

## Pinned specification

**Personal Agent Protocol ("Poppy") Draft 0.1** — published 2026-10-09 by
Sierra and Meta at https://personalagentprotocol.org (Apache 2.0).
Verified 2026-10-11.

Poppy building blocks used (draft 0.1, faithfully):
1. **Discovery** — company publishes `/.well-known/poppy.json` (version 0.1):
   organization identity, sign-in endpoints, offered APIs/agents.
2. **Standard sign-in** — user signs in on the company's own page via
   OAuth 2.0 (DPoP-bound tokens, PKCE, device grant). User chooses
   read-only or write access.
3. **One session across interfaces** — short-lived signed session JWT
   covers API calls, conversations, web browsing.
4. **Spectrum of interfaces** — OpenAPI, MCP, web pages, company agent.
   Each API keeps its own schema.
5. **Extensions** — discovery, identity, APIs, conversations are open
   to extension.

Explicitly NOT in draft 0.1 (per the published draft and Sierra's own
statements): finer-grained per-action permissions (listed as future
extensions); payments (listed as an open topic).

## The gap this experiment addresses

Poppy 0.1 establishes *who the user is* (signed in, OAuth) and *coarse
scope* (read-only vs write). It does not bind the owner's signature to
the *exact terms* of a consequential operation: which item, exact
amount, exact merchant, exact limits, exact expiry.

An agent holding a write-scoped session JWT can perform any write the
company's policy allows. The company decides what "write" means — the
owner never signed the exact operation. If the agent is compromised,
confused, or replaced, there is no owner-controlled, independently
verifiable record of *this exact operation* being authorized.

This is not a criticism of Poppy — coarse OAuth scopes are the
industry standard, and per-action authorization is on Poppy's stated
roadmap. This experiment demonstrates one concrete way to fill the gap.

## The extension (experimental, not a Poppy standard feature)

An **OpenLine mandate** rides alongside the Poppy session:

- The owner signs a Wallet mandate whose scopes encode the EXACT
  operation terms (merchant, line items, amounts, limits, expiry).
- The receiving business runs an OpenLine-aware receiver that verifies:
  1. The Poppy session is valid (OAuth JWT, DPoP binding, not expired)
     — *identity established, per Poppy 0.1*.
  2. The owner-signed mandate matches the EXACT operation presented
     (terms hash, amounts, merchant, expiry) — *authority established,
     the experimental extension*.
- The receiver issues a **signed decision receipt** (ALLOWED/STOPPED
  with reason codes), independently verifiable with the receiver's
  public key.
- The simulated business effect (ledger movement) happens only on
  ALLOWED.

What the extension does NOT do:
- It does not replace Poppy sign-in, sessions, or DPoP. Those run
  unchanged underneath.
- It does not weaken any Poppy protection to manufacture an advantage.
  The Poppy-native baseline below implements draft 0.1 faithfully.
- It does not claim to be part of the Poppy standard. It is an
  experimental extension, documented as such.

## Operation flow

```
Owner                    Agent                    Receiver (business)
  |                        |                              |
  |  1. grant mandate      |                              |
  |  (exact terms, signed) |                              |
  |                        |  2. discover poppy.json      |
  |                        |  3. open Poppy session       |
  |                        |  4. user OAuth sign-in       |
  |                        |     (read/write choice)      |
  |                        |  5. present operation +      |
  |                        |     session JWT + mandate ---+--> 6. verify session (Poppy)
  |                        |                              |    7. verify mandate (OpenLine)
  |                        |                              |    8. sign decision receipt
  |                        |  9. receipt <----------------+
  |                        | 10. effect (if ALLOWED)      |
```

## Trust boundaries

- **Owner key**: The owner holds their Wallet root key. Compromise of
  the owner key compromises all mandates (same as any signing key).
- **Receiver key**: The receiver signs decision receipts with its own
  key. A compromised receiver can lie about its decisions — but it
  cannot forge the owner's mandate signature.
- **Agent/worker key**: Workers hold only their subject keys. A
  compromised worker cannot mint authority; it can only present what
  the owner granted. Worker replacement = new key, same mandate scopes.
- **Authorization-provider replacement**: If the Wallet (mandate
  issuer) is replaced, the receiver must re-pin the new provider's
  root key out-of-band. Old mandates do not transfer automatically.
- **Freshness**: Revocation is enforced against the freshness-bounded
  admitted bundle (max 300s). A receiver that does not admit fresh
  bundles cannot see new revocations — this is disclosed, not hidden.
- **Poppy session**: The session JWT is short-lived and DPoP-bound
  (per draft 0.1). Token theft without the DPoP key is useless.

## What works (demonstrated)

- Owner-signed mandate bound to exact operation terms.
- Receiver verifies owner signature before simulated business action.
- Rejection when agent claims approval without valid owner authority.
- Revocation, replay protection, changed-details rejection, stale
  authority rejection, worker replacement, provider replacement.
- Signed, independently verifiable receiver decision receipts.
- Actual simulated business effects checked (ledger deltas).

## What remains incomplete

- No real OAuth server (simulated DPoP/JWT with real cryptography).
- No real payment processing (simulated ledger).
- No multi-company federation (single receiver).
- Performance optimization explicitly deferred to Codex phase.

## Experimental vs standard

| Feature | Poppy 0.1 standard | Experimental extension |
|---|---|---|
| poppy.json discovery | Yes | — |
| OAuth sign-in, session JWT | Yes | — |
| DPoP-bound tokens | Yes | — |
| Read/write scope choice | Yes | — |
| Owner-signed exact-terms mandate | No | **Yes** |
| Receiver-side mandate verification | No | **Yes** |
| Signed decision receipts | No | **Yes** |
| Per-action authorization | Future | **Demonstrated** |

## Results (2026-10-11)

- `demo_poppy_proof.py`: 11/11 — exact-terms allow, ledger moves
  $42.50 exactly, no-mandate STOPPED, tampered-amount STOPPED, receipts
  verify independently.
- `test_poppy_proof.py`: 16/16 — revocation, replay, changed amount,
  changed merchant, stale bundle head, worker replacement, provider
  replacement, expired mandate, forged session, DPoP mismatch,
  company-revoked session.
- `poppy_native_baseline.py`: demonstrates the honest gap — a valid
  write-scoped session can charge $99.99 the owner never signed for.
- `bench_poppy.py` (n=50, local): native p50 0.16ms, extended p50
  0.53ms. Median added latency of exact-terms authority: **0.38ms**.
  Operational complexity: 4 moving parts (native) vs 8 (extended).
