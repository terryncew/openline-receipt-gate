# COALITION-001 — Frozen lab result

**Status: FROZEN**

**Experiment:** COALITION-001 — Mandate-Scoped Split-Consequence Bypass

**Pre-experiment production standing:**
`NO_GO_COALITION_001_REQUIRES_SCOPE_EXPANSION`

**Lab result:** `PASS_COALITION_001_MANDATE_SCOPED_BOUND_ENFORCED`
(rule-6: all frozen conditions met, single committed runner invocation
2026-09-16T19:56:46.041211+00:00)

## Question

Given one receiver-recognized originating authority O with cumulative bound
B, can multiple distinct authorities derived from O cause committed
mechanically observable consequence whose sum exceeds B?

## What was proven (lab only)

- Origin O (`origin:coalition-001:O`), immutable, cumulative bound B = 100.
- Two distinct receiver-recognized authority-bearing descendants of O:
  A (`actor-A` / `cred-A`) and B (`actor-B` / `cred-B`).
- A requested 60 units → committed. B separately requested 60 units →
  refused (`ORIGIN_BOUND_EXCEEDED`) with a signed refusal receipt.
- No partial 40-unit rewrite. Committed consequence attributed to O: **60**.
- Frozen baseline (same two valid actions, per-action authorization, no
  cumulative origin state): both committed → **120 units from O**. The
  split-consequence exposure is real.
- The treatment accounted consequence against origin O, never actor
  identity. Changing actor identity did not create a fresh budget.
- Negative control: separate origin O2 (`origin:coalition-001:O2`, own
  bound 100) committed its 60; 40 available; unaffected by O.
- No coordination transcript, hidden-message inspection, intent
  classifier, or collusion detector was consulted.
- Exactly one authoritative receiver, one atomic consequence ledger
  (check-and-consume indivisible under one lock). Simultaneous races were
  not a scientific arm (deferred). Deterministic synthetic consequence.
- All 5 protected existing tests green; exact authorization replay stayed
  blocked; uncertain-effect reconciliation stayed fail-closed.

## Maximum earned claim

> Within the controlled receiver set, splitting one originating bounded
> authority across the two frozen actor authorities did not increase the
> cumulative authority available under that origin.

Do not broaden that sentence.

## Explicit production statement

**Production capability was NOT earned.** Current production
`principal_mandate/v1` does not represent a shared cumulative authority
origin/bound across distinct actor authorities.
`NO_GO_COALITION_001_REQUIRES_SCOPE_EXPANSION` remains true. The lab PASS
is not a production proof, and nothing in this freeze changes production
semantics.

## No claim about

Distributed receivers, physical actuators, semantic harms, arbitrary
coalitions, collusion detection, hidden-message detection, or production
`principal_mandate/v1` support.

## Frozen artifacts

| Artifact | SHA-256 |
|---|---|
| Contract (`artifacts/CONTRACT.md`) | `6cced6ba154970af3160b0ec1f1a398e2a613548cc34ccc6bc3d9a09f1ad5474` |
| `artifacts/src/mandates.py` | `64d2f7162bbf0bff3ac2217598be2a5c861d9d339420c30c410a4496f647690e` |
| `artifacts/src/ledger.py` | `071dcf3850406c87a37eca953b385146832eeadb95fd89b4330ccf444c01d8b0` |
| `artifacts/src/receiver.py` | `b32c12c1e7c3db01a98ac62729949665a4a125fbc88536d08c0ba2a4bcd6828b` |
| `artifacts/runner/runner.py` | `06be51abc180e0d2a270c80c96f79b65bc7ee7846f95e37e357cbcb27efd683f` |
| `artifacts/tests/protected_tests.py` | `d33afaa1ede36bbeaced363e3be4f3aa3e3abdb9227fd849cb4a06c509a7b2d9` |
| Observations (`artifacts/evidence/COALITION-001-observations.json`) | `6ec2d3b917bf812c292ef8ffab28eb822606c5fb2ac596323907ef6d5e11828f` |

Repo main at freeze: `9dc437a54b7f0a4ee044c0eb7712c295f07e4635`.
Machine-readable freeze record: `receipt.json` (schema
`openline.coalition-001.freeze.v1`).
