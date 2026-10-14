# EVIDENCE — standing-check race tests (GATEWAY-SUBSCRIPTION-001, Step 2)

Date: 2026-10-11. Branch: `experiment/gateway-subscription-001`.
All work below was done on this branch; `38e33ce`, `experiment/openline-gateway-001`, and `main` untouched.

## What was built

The standing-check feature did not exist on this branch (the 23b9031
prototype lived only on the old branch). I ported it with identical
semantics — purely additive, env-gated, no signature changes, no changes
to existing code paths:

- `gateway/authz_server.py` (+51): `GET /standing?decision_id=&agent_id=&issued_at=`
  on an HTTP thread, started only when `GATEWAY_STANDING_PORT` is set.
  Standing = agent known AND not revoked AND token within 60 s TTL.
- `gateway/mock_api.py` (+47): with `GATEWAY_STANDING_CHECK=1`, the
  enforce path re-queries the standing endpoint after token verification
  and before the ledger commit; refusal is 403 `"decision no longer
  standing at execution"`; fail-closed on unreachable service; successful
  responses report `standing_to_commit_ms`.
- `gateway/mock_api.py` (+9, TEST-ONLY): `GATEWAY_TEST_PRE_COMMIT_DELAY_MS`
  sleeps between a passed standing check and the ledger commit so the
  kill-9 test can land inside that window. Absent by default → zero
  behavior change. Never set in production.
- `gateway/tests/test_standing_races.py` (new, 10 tests — existing test
  files untouched).
- `gateway/docs/STANDING-CHECK.md`: recreated verbatim from 23b9031 (it
  did not exist on this branch), then appended the race-results section.

## How the tests run (exact commands)

```bash
cd ~/workspace/repos/openline-receipt-gate
git checkout experiment/gateway-subscription-001
cd gateway
python3 -m pytest tests/test_standing_races.py -q        # 10 passed in ~15 s
python3 -m pytest tests/test_gateway.py -q               # 5 passed (no regressions)
```

Each test spins up REAL `authz_server` + `mock_api` subprocesses on
localhost with an isolated config dir, fresh receiver key, and fresh
sqlite DB (the repo's real `gateway/config/receiver.key` is never
touched). Tokens are minted through the real gRPC `Check` path (signed
`AgentClient` action); revocation goes through the real
`gateway_admin revoke-agent` path; execution is HTTP POST to the mock
API; ledger effects are verified by balance reads AND the `effects`
table. Measurements land in
`gateway/subscription001/measurements-2026-10-11.json` (written by
`tearDownModule`).

**Honest limitation:** Envoy is bypassed. The execution-time check lives
entirely between mock_api and the authz service, so Envoy's ext_authz
plumbing adds nothing to the race question being measured — the standing
query and the ledger commit happen inside mock_api exactly as they would
behind Envoy. The full Envoy binary (1.39.3) is present at
`~/workspace/.envoy-binary` and runs; it was not needed for this step.

## Per-test results

| # | Test | Result | Measured |
|---|------|--------|----------|
| 1 | Token minted pre-revocation, executed post-revocation, check ON | PASS | 403 `"decision no longer standing at execution"`; treasury/vendor/effects unchanged (zero effect) |
| 2 | Same scenario, check OFF (control) | PASS (documents the TTL bound, not a bug) | 200, executes; treasury −100¢, vendor +100¢, +1 effect; no `standing_to_commit_ms` in response |
| 3 | Decision-token replay (same token twice) | PASS | 1st: 200; 2nd: 409 `"decision token already used"`; exactly 1 effect |
| 4 | Standing service unreachable (dead port), check ON | PASS | 403 fail-closed, zero ledger effect |
| 5 | Concurrency: 20 threads, revoke mid-stream (3 rounds) | PASS | see distribution below; every attempt that began after revocation was confirmed → 403; ledger effects == number of 200s in all rounds |
| 6 | Retry storm: same token 50× (8 threads) | PASS | exactly 1 execution, 49 refusals; exactly 1 effect |
| 7 | kill -9 mock API between check and commit (3 s instrumented window) | PASS | in-flight attempt died with connection error; ledger showed zero effect after kill; on restart the (never-committed, still-valid) token retried to exactly 1 execution |
| 8a | Standing endpoint latency, n=100 | measured | mean 0.577 ms, p50 0.468 ms, p99 2.64 ms |
| 8b | Check-to-commit interval, n=30 (`standing_to_commit_ms`) | measured | mean 2.61 ms, p50 1.389 ms, p99 35.571 ms, max 35.571 ms |
| 8c | A/B end-to-end POST latency | measured | check ON p50 2.76 ms (n=50) vs OFF p50 1.635 ms (n=20) → **~1.1 ms added** |

Concurrency distribution (rounds × 20 attempts; revoke = `gateway_admin`
subprocess, 85–106 ms wall):

| round | executed | refused (403) | transport ERR | attempts begun after revocation confirmed | of those, executed |
|-------|----------|---------------|---------------|-------------------------------------------|--------------------|
| 0 | 10 | 8 | 2 | 0 | 0 |
| 1 | 7 | 7 | 6 | 0 | 0 |
| 2 | 7 | 9 | 4 | 0 | 0 |

All 20 attempts per round fell in the "straddle" class (the 20 serial
requests complete inside the ~100 ms revoke-subprocess window, so none
cleanly pre- or post-date it). The fail-closed invariant held in every
round: zero executions among attempts that began after revocation was
confirmed, and `effects_added == executed` / treasury delta ==
`executed × 100¢` in every round.

## Is the 60 s window closed?

**No — and it cannot be closed to zero under this architecture.**
What the standing check does, measured: it narrows the post-revocation
execution window from the 60 s token TTL to the check-to-commit
interval — p50 ~1.4 ms, worst observed 35.6 ms on this VM (n=30). A
revocation landing between the standing check and the ledger commit
still executes; that residual window is bounded by the business
application's commit latency, not by anything the gateway can shrink.
Honest statement: *new authorizations stop at revocation; in-flight
tokens are refused at execution by the standing check; the residual
window is the check-to-commit interval (~1–36 ms measured here).*

## Failures encountered (harness/environment, not product)

1. **Python grpc client over IPv4 loopback fails on this VM** —
   `Failed parsing HTTP/2 (Expected SETTINGS frame as the first frame,
   got frame type 101)`, 100% consistent, reproduced with a bare grpc
   server (no authz_server involved); raw TCP to 127.0.0.1 is fine and
   Envoy's ext_authz over 127.0.0.1 is fine per the coordinator's
   isolation. Workaround used by the tests: connect to `[::1]` (server
   binds `[::]` dual-stack). Recorded as an environment quirk; the
   coordinator independently confirmed the same failure and workaround.
2. **Burst-correlated RSTs on IPv4 loopback** — under 20-thread
   connection bursts, ~5–20% of requests die with `ConnectionResetError`/
   `RemoteDisconnected`, with and without a concurrent revoke, and with
   a bare HTTPServer control showing the same class of flake is absent
   at low per-request cost. Every ERR'd token retried cleanly (200, 6/6
   sampled), proving the RST lands before the commit — never a phantom
   execution. Ledger reconciliation (`effects == 200-count`) held in all
   rounds. Transport flake, not a product defect; recorded, not hidden.
3. **My own debug-copy bug (not the product):** while instrumenting a
   throwaway copy of mock_api in /tmp, a `str.replace` matched inside a
   longer indented line and dedented a `return` to method level, causing
   `UnboundLocalError` for all requests. The repo's `mock_api.py` was
   never affected (verified: all product tests pass on the repo file).
   The /tmp copy was discarded.
4. **Coordinator interference check:** the coordinator ran
   `pkill -f "authz_server.py 50051"` around 00:25 PDT. My test failures
   (grpc-over-IPv4, item 1) occurred 00:13–00:14 PDT and the full suite
   passed 00:20 PDT — both before the pkill. **Not affected.**

## What remains unverified

- Envoy in the request path (bypassed; see limitation above).
- The true microsecond mid-commit kill window: the kill-9 test used the
  instrumented 3 s pre-commit window. Atomicity *inside* the sqlite
  commit is argued from sqlite transaction atomicity (single
  `transfer()` transaction covers balance update + used-decision mark +
  effect row), not demonstrated by test — stated, not claimed.
- Multi-host / real network (all localhost); production commit
  latencies will differ — the residual bound must be re-measured there.
- The standing endpoint's `token_expired` branch (all test tokens were
  seconds old); the 60 s TTL expiry path itself is covered by
  `verify_decision_token` in the existing suite's construction.

## Recommendation for the demo

**Yes — `GATEWAY_STANDING_CHECK=1` should be default-on for the
subscription demonstration.** From the measurements: it costs ~1.1 ms
median per execution and it is what makes the demo's central moment
true — a charge attempted after the on-screen revocation is refused
with 403 `"decision no longer standing at execution"` instead of
executing for up to 60 s after the user revoked, which would visibly
contradict the story being told. The fail-closed availability
dependency (authz outage → no charges) is acceptable in a demo where
both processes run on the same box, and the demo's happy path (a
legitimate pre-revocation charge) is unaffected — the check passes and
adds ~1 ms. State the residual window honestly in demo materials: a
charge whose check passes in the ~1–36 ms before the revocation lands
still executes; sequence the filmed revoke with a comfortable margin
before the refused charge so the demonstrated behavior is
deterministic. (The shipped-product default is a separate decision —
the prior investigation's opt-in recommendation stands for production;
this recommendation is for the demonstration only.)
