# Investigation: closing the post-revocation token window

**Question:** A decision token minted before revocation stays valid
until its 60 s TTL. Can final execution-time standing verification
close that window?

**Answer:** It narrows the window from 60 s to the check-to-commit
interval (measured ~75 ms here, dominated by the application's own
commit latency), at the cost of a new availability dependency. It
cannot reach zero — revocation landing between the check and the
commit still executes. And it is not OpenLine-specific: any
architecture (including OPA-B) can re-query policy at execution time.

## Prototype

- Authz service exposes `GET /standing?decision_id=&agent_id=&issued_at=`
  (opt-in via `GATEWAY_STANDING_PORT`; HTTP thread on the authz
  process, reads the same sqlite registry).
- Mock API with `GATEWAY_STANDING_CHECK=1` queries it before every
  `transfer` and refuses to execute unless the decision is still
  standing. Fail-closed: unreachable standing service → 403, no
  execution.

## Measured (2026-10-10, this VM)

| | |
|---|---|
| Post-revocation token, no check | executes (window = up to 60 s TTL) |
| Post-revocation token, with check | 403 "decision no longer standing at execution" |
| Standing check latency | ~1 ms (localhost HTTP) |
| Check-to-commit interval | ~75 ms steady state |
| Fail-closed on standing outage | confirmed 403, no execution |

The 75 ms is dominated by the mock ledger's own sqlite commit, not
the check. The residual window is therefore bounded by the business
application's commit latency — pushing revocation into the commit
transaction itself is the only way to shrink it further, and that is
application work, not gateway work.

## Trade-offs

1. **Availability:** the business API now depends on the authz service
   at execution time. Authz outage → no executions (fail-closed).
   Without the check, already-minted tokens still execute during an
   authz outage (bounded by TTL).
2. **Latency:** ~1 ms added per execution here; the check-to-commit
   interval is the commit's own cost.
3. **Not exclusive:** OPA-B with a stateful application can do exactly
   the same re-query. This is an architectural pattern with a measured
   cost, not a capability competitors can't reproduce.

## Recommendation

Keep TTL-bounded tokens as the default (simpler, fewer runtime
dependencies); offer the standing check as a documented opt-in for
deployments where the 60 s bound is unacceptable. State the bound
honestly either way: *new authorizations stop at revocation;
in-flight tokens are bounded by TTL, or by check-to-commit with the
standing check enabled.*

---

## Race test results (2026-10-11)

GATEWAY-SUBSCRIPTION-001 Step 2 re-implemented the check on the
`experiment/gateway-subscription-001` branch (the prototype above lived
only on the old branch) and tested it with 10 race tests in
`gateway/tests/test_standing_races.py` — real `authz_server` + `mock_api`
subprocesses, tokens minted via the real gRPC `Check`, revocation via
the real `gateway_admin revoke-agent`. Envoy bypassed (the check lives
entirely between mock_api and the authz service). Full evidence:
`gateway/subscription001/EVIDENCE-races.md`; measurements:
`gateway/subscription001/measurements-2026-10-11.json`.

**Is the 60 s window closed? No.** It narrows from the 60 s TTL to the
check-to-commit interval — measured p50 ~1.4 ms, worst observed
35.6 ms (n=30) on this VM. A revocation landing between the check and
the commit still executes; that residual window is bounded by the
application's commit latency and cannot reach zero under this
architecture.

| Test | Result |
|------|--------|
| Pre-revocation token executed post-revocation, check ON | 403 `"decision no longer standing at execution"`, zero ledger effect |
| Same, check OFF (control) | executes — the documented TTL bound, not a bug |
| Token replay (same token ×2) | 2nd refused 409, exactly 1 effect |
| Standing service unreachable | 403 fail-closed, zero effect |
| 20-thread burst with revoke mid-stream (3 rounds) | 0 executions among attempts begun after revocation confirmed; ledger effects == 200-count every round |
| Retry storm (same token 50×) | exactly 1 execution |
| kill -9 between check and commit | zero effect; restart; retry executes exactly once |
| Standing endpoint latency (n=100) | mean 0.58 ms, p50 0.47 ms |
| A/B end-to-end latency | check adds ~1.1 ms median (2.76 vs 1.64 ms) |

Environment quirks recorded (not gateway defects): the Python grpc
client cannot complete an HTTP/2 handshake over IPv4 loopback on this VM
("got frame type 101"; `[::1]` works); ~5–20% of requests in 20-thread
bursts die with RST on IPv4 loopback — every such token retried cleanly,
never a phantom commit.

**Demo recommendation:** `GATEWAY_STANDING_CHECK=1` default-on for the
subscription demonstration — it is what makes the revocation moment
true (post-revocation charge refused instead of executing for up to
60 s), at ~1 ms cost. State the residual check-to-commit window
honestly and sequence the filmed revoke with margin.
