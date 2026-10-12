# HANDOFF: GATEWAY-SUBSCRIPTION-001 Upstream-Stall Isolation

**Branch:** `temp/stall-isolation-001` (DO NOT MERGE)
**Final commit:** `ceee9d2` (Use down/up for full-restart)
**Date:** 2026-10-12 ~02:45 UTC (2026-10-11 19:45 PDT)
**Executor:** Muse (Prince)

## Verdict: FAIL

The reported post-full-restart Envoy upstream stall did **not** reproduce
under valid test conditions. Two bounded variants were tested:

1. `docker compose --profile openline restart` → NO_STALL
2. `docker compose --profile openline down` + `up -d` → NO_STALL

Both showed healthy baselines (403 in ~4ms = Envoy responsive, ext_authz
denying without token) and healthy post-restart responses (403 in ~4ms).

## What was fixed (owner's review findings)

1. **Compose path:** `trigger-stall-isolation.sh` now `cd`s to `gateway/compose/`
   before invoking Docker Compose (was repo root → "no service selected").

2. **Profile:** All compose commands use `--profile openline` (services are
   profile-gated; without it, zero services start).

3. **Branch checkout:** New workflow `.github/workflows/temp-stall-isolation.yml`
   explicitly checks out `temp/stall-isolation-001` (the existing Docker
   workflow targets `experiment/gateway-subscription-001`).

4. **Baseline validation:** Script aborts if baseline is not HEALTHY.
   Previously any failed request was counted as "stall reproduced".

5. **Failure discrimination:** Classifies TIMEOUT vs CONNECTION_REFUSED vs
   HTTP_5XX vs HTTP_4XX vs HEALTHY. A 403 from ext_authz (no decision token)
   = HEALTHY for stall purposes (Envoy is responsive).

6. **Endpoint:** Uses `/api/balance/treasury` (Envoy routes `/api/` → mock API
   with prefix_rewrite). Was `/balance` → 404.

## GitHub Actions runs

| Run | Commit | Variant | Baseline | Post-restart | Verdict |
|-----|--------|---------|----------|--------------|---------|
| [38196316274](https://github.com/terryncew/openline-receipt-gate/actions/runs/38196316274) | da9e70f | — | — (compose failed) | — | INCONCLUSIVE |
| [38196378443](https://github.com/terryncew/openline-receipt-gate/actions/runs/38196378443) | 997403b | — | HTTP_4XX 404 | aborted | INCONCLUSIVE |
| [38196466589](https://github.com/terryncew/openline-receipt-gate/actions/runs/38196466589) | b850f5a | — | HTTP_4XX 403 | aborted | INCONCLUSIVE |
| [38196748029](https://github.com/terryncew/openline-receipt-gate/actions/runs/38196748029) | 0d6a0e5 | `restart` | HEALTHY 403 4.5ms | HEALTHY 403 4.4ms | **NO_STALL** |
| [38196900856](https://github.com/terryncew/openline-receipt-gate/actions/runs/38196900856) | ceee9d2 | `down`+`up` | HEALTHY 403 4.7ms | HEALTHY 403 3.8ms | **NO_STALL** |

## Interpretation

The stall does not reproduce on a clean GHA runner with the current code.
Possible explanations (not tested):

- The original stall was environment-specific (the earlier GHA run's runner
  state, Docker layer cache, or timing).
- The original stall involved a different sequence (e.g., restart during
  active traffic, or volume state from a prior partial run).
- The stall was transient and already resolved by an intervening change.

**This is not a fix.** The underlying cause was never identified because
the symptom did not reproduce.

## Smallest next discriminating test (if the stall is seen again)

Run the diagnostic *during* the original failing scenario's exact
conditions: capture the GHA run ID, runner image, and full `docker compose`
sequence from the original failure, then replay verbatim on the temp branch.
If it still doesn't reproduce, the stall was environmental, not code.

## Remaining blockers

- None for this experiment. The temp workflow trigger has been disabled
  (see below). Evidence preserved in GHA artifacts (30-day retention).

## Temporary trigger status

**DISABLED** after experiment. The workflow file
`.github/workflows/temp-stall-isolation.yml` has been removed in commit
(see log). GHA run history and artifacts are preserved.

## Boundaries honored

- Synthetic transactions only (no real mandates, no tokens).
- No paid APIs, credentials, or real financial actions.
- No merges. `experiment/gateway-subscription-001` untouched.
- No changes to distribution experiment, Threads drafts, or schedules.
- Temp branch only. Frozen baseline preserved.
