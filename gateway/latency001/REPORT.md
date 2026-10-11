# GATEWAY-LATENCY-001 — Linux benchmark and review report

**Status:** **REVIEW / NO MERGE**. The optimized path passed the functional and required benchmark cases in Linux CI attempt 2; original Gateway concurrent diagnostics failed and remain failed. A follow-up branch-scoped workflow is required to validate the revised *report aggregation*. This is not a production performance or security certification.

**Sources:** [Linux CI attempt 2](https://github.com/terryncew/openline-receipt-gate/actions/runs/38161773565) (source head `3a5943e6bb8ea3c92c94ee846a6ab92bf6ed829e`); its uploaded artifact `gateway-latency-001-linux-docker`, artifact ID `11710208002`. The original code baseline is `9461188f44a15766d35dcf034d386c682db403f7` (PR #103 merged into the subscription experiment). Later edits to `run_matrix.py` change only acceptance reporting, not request enforcement.

## Correctness evidence on GitHub-hosted Linux

- Original Docker verification suite: PASS (workflow step).
- Same complete Docker suite with execution-time standing enabled: PASS (workflow step).
- Unit, security, crash and race regression suite: PASS (workflow step); existing local run reported 24/24.
- Public-key-only, independent verification of signed Gateway receipts: PASS (workflow step).
- Benchmark-integrity tests: PASS (workflow step).
- Real OPA rule parity and fail-closed tests: PASS (workflow step).
- **Optimized Gateway at concurrency 1, 8 and 32: PASS each, 1,000/1,000 successful transfer requests with correct simulated ledger effects and independently verified receipts.**
- Original Gateway: concurrency 1 PASS; concurrency 8, concurrency 32 and profiled concurrency 8 FAIL. These were non-required diagnostic rows in the preregistered matrix. Failures were **not** accepted as successful latency samples.
- **Overall prior workflow status: FAIL**, because the aggregator incorrectly made failed optional-original diagnostics block the optimized implementation's acceptance decision. The updated aggregator explicitly records both `required_passed` and `diagnostics_failed`, with `all_cases_passed: false`. Its revised CI run is still required.

## Actual legacy failure (artifact review)

The original authz service uses one `sqlite3` connection from concurrent gRPC workers and its standing-check server without serialized access. The Docker `compose.log` for original-c8, original-c32 and profile-original-c8 repeatedly records `sqlite3.InterfaceError: bad parameter or other API misuse` inside `GatewayState.get_agent`, sometimes accompanied by invalid/absent row data. Benchmark process `report.json` records `passed: false`, `cases: []`, and `compose exec mockapi failed, exit 1`; receipt export separately encounters `compose exec authz failed, exit 1`. The runner previously disqualified those rows because the post-failure receipt exporter could not complete.

That is an **actual old-implementation failure**, not a successful benchmark, and the logs do not support attributing every failed request to one exclusive cause. The optimized revision serializes complete SQLite connection transactions, atomically inserts nonces, and validates signed agent identity binding. It also addresses separate measured TCP backlog overflows by increasing the bounded listen queue. The historical failures remain in the CI artifact and must not be erased or relabeled as successful checks.

## Linux CI attempt 2 — full-response warm path

All numbers are **milliseconds**, p50 / p95 / p99, 1,000 successful measured requests per passing row, 1-cent fictional ledger transfers, persistent HTTP clients, same host, standing checks ON for matched Gateway and the stateful construction. Warmups and first-client calls are excluded; client preparation is measured separately. No errors were ignored in a passing case.

| Setup | Concurrent clients | p50 | p95 | p99 | Successful req/s | Case verdict |
|---|---:|---:|---:|---:|---:|---|
| Original Gateway (instrumented, profiling OFF) | 1 | 6.36 | 8.85 | 11.11 | 146.4 | PASS |
| Original Gateway (same source) | 8 | — | — | — | — | FAIL (no valid benchmark report) |
| Original Gateway (same source) | 32 | — | — | — | — | FAIL (no valid benchmark report) |
| Optimized Gateway | 1 | **3.89** | **4.81** | **6.33** | 239.3 | PASS |
| Optimized Gateway | 8 | 19.43 | 25.52 | 28.26 | 398.9 | PASS |
| Optimized Gateway | 32 | 77.39 | 84.03 | 92.48 | 408.1 | PASS |
| Native OPA-A, basic | 1 | 1.46 | 1.82 | 2.55 | 641.9 | PASS |
| Native OPA-A, basic | 8 | 5.43 | 7.83 | 8.77 | 1,387.0 | PASS |
| Native OPA-A, basic | 32 | 21.31 | 22.91 | 23.61 | 1,473.6 | PASS |
| Native OPA-B, data revocation | 1 | 1.74 | 2.51 | 3.13 | 533.2 | PASS |
| Native OPA-B, data revocation | 8 | 6.17 | 8.69 | 10.18 | 1,227.2 | PASS |
| Native OPA-B, data revocation | 32 | 24.50 | 28.69 | 31.29 | 1,277.5 | PASS |
| Stateful OPA with Gateway security wrapper | 1 | 5.89 | 7.56 | 9.67 | 159.4 | PASS |
| Stateful OPA with Gateway security wrapper | 8 | 23.99 | 30.42 | 34.94 | 323.1 | PASS |
| Stateful OPA with Gateway security wrapper | 32 | 101.02 | 112.40 | 124.26 | 310.9 | PASS |
| Laboratory Envoy/backend floor (authorization bypassed) | 1 | 2.13 | 2.69 | 3.66 | 442.3 | PASS |
| Laboratory Envoy/backend floor (authorization bypassed) | 8 | 12.80 | 16.04 | 17.84 | 600.6 | PASS |
| Laboratory Envoy/backend floor (authorization bypassed) | 32 | 50.10 | 53.92 | 55.97 | 630.9 | PASS |

The original-vs-optimized median falls from **6.36 to 3.89 ms** at concurrency one on the matched Linux run (approximately 39% lower end-to-end p50). This is a **measured current-host improvement**, not the historical claim of saving 140 milliseconds. The earlier 218.3 ms Gateway/76.4 ms basic OPA comparison was *not reproduced*, and original raw timing evidence is unavailable. The benchmark script for that older comparison also counted exceptions as latency samples, so its figures are not interchangeable with this verified all-success series.

The native basic/data OPA baselines are faster but lack the integrated Gateway's signed one-use decisions, durable replay protections, execution standing and signed receipts. The stateful OPA construction **reuses the OpenLine Gateway security/state wrapper** with real OPA policy evaluation. It is a more comparable integrated architecture but **not** an independently built equivalent OPA product. None of these results establish superiority over the actual Poppy protocol or an enterprise-grade OPA deployment.

## Exact implications and boundaries

1. **Fixed by optimized source:** demonstrated concurrency-safe access to Gateway SQLite state, atomic nonce claims, signed-agent/header identity binding, improved bounded API listen backlog, and WAL with `synchronous=FULL` durable commits. Required Linux functional and benchmark rows pass.
2. **Not fixed:** the original revision still fails under concurrent load. It is preserved as a negative diagnostic, not retroactively patched or counted as a pass.
3. **Not established:** power-loss guarantees, high-availability replicas, real money transfers, commercial demand, a universal maximum revocation interval, or a production SLA. A valid signed decision receipt attests to a recorded receiver decision, not independently to the financial effect.
4. **Standing semantics:** standing ON reduces the pre-issued-token exposure but a race remains between final check and commit. Tests cannot promise instantaneous, globally atomic revocation.
5. **Acceptance:** the updated matrix must show every required optimized/native-OPA/stateful-OPA/floor case PASS, independent receipt verification PASS, intact security suite PASS, all planned rows recorded, and original diagnostic failures surfaced as failures. A green required-case gate does not mean `all_cases_passed` is true.

## Next step / owner review

Await the branch-scoped GitHub Actions run on the aggregator fix; attach its run URL and signed-evidence artifact to the PR. Do **not merge** into `experiment/gateway-subscription-001` or `main` until owner approval. Subsequent Poppy Proof correctness integration remains a separate PR and has not been evaluated here.
