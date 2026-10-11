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
