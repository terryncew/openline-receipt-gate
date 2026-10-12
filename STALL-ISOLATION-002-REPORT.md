# STALL-ISOLATION-002 — Authorized-path restart isolation

**Verdict:** INCONCLUSIVE (fail closed before restart)  
**Repository:** terryncew/openline-receipt-gate  
**Branch:** temp/stall-isolation-001 (DO NOT MERGE)  
**Test commit SHA:** `1efbb5ee4c44638d6bd72ba2cd12ff8d76077845`  
**Previous head:** `4bd7a8931ff7e00619ca4b99604b1863224014b4`  
**One GHA diagnostic run:** [38198187700](https://github.com/terryncew/openline-receipt-gate/actions/runs/38198187700) (attempt 1; completed failure)  
**Artifact:** [STALL-ISOLATION-002-38198187700, ID 11724102133](https://github.com/terryncew/openline-receipt-gate/actions/runs/38198187700/artifacts/11724102133)  
**Artifact digest (GitHub reported):** `sha256:bc0240173ef17c0ea189da2b94366c8a5379f6bedef351415dddf5612cfd966b`  
**Artifact expiry:** 2026-11-11 03:02:59 UTC (30 days)  
**Recorded probe:** 2026-10-12 03:02:58.730885 UTC (runner)  
**Diagnostic job:** FAILURE (correct fail-closed exit code 1; logs uploaded successfully).

## Corrected scientific record

STALL-ISOLATION-001 reported FAIL/NO_STALL from unauthenticated 403
responses (~4ms) before/after restart. Those requests were denied by
ext_authz before the mock API and cannot establish recovery of the
authorized upstream. The measurements and old handoff are preserved
below the superseding correction in HANDOFF.md. The actual original
authorized-path failure occurred on [GHA 38122910173](https://github.com/terryncew/openline-receipt-gate/actions/runs/38122910173):
20/22 PASS; inspection-signed balance reads did not recover within
90 seconds after full-stack `docker compose restart`. That failure
is credible and remains unresolved.

## Intended method (only one diagnostic run permitted)

Synthetic Docker Compose `openline` profile on an ubuntu-latest
GitHub-hosted runner. Following the original
`gateway/ci/docker_verify.py` and `AgentClient` pattern, provision
an inspect-only agent with receiver-side mandate
`allowed_action_types=['inspect']`, `max_payment_cents=0`,
`delegation_allowed=false`, and signed fresh headers per GET.
Require correct balance JSON and status 200 before the same full-stack
`docker compose --profile openline restart`; then poll authorized
reads for <=90 seconds. Abort on any unexpected 403 or containment breach.
Report curl exit, HTTP status, response validity, and elapsed time
separately. No synthetic transfers were initiated by this harness.

## Actual execution and measurements

1. Docker Compose build and startup: completed.
2. Containment check: PASS. Envoy host port 8080 was published on
   the ephemeral runner; neither authz nor mockapi had host-published
   ports. Receiver policy mode: `enforce`.
3. Provision inspect-only synthetic `ci-stall-002-inspector`: PASS.
   Receiver DB mandate independently checked; inspect-only,
   max payment 0, target ledger, delegation disabled, not revoked.
   Private key/signatures were not logged.
4. First signed baseline GET to
   `http://127.0.0.1:8080/api/balance/treasury`:
   - HTTP status: **403**
   - curl exit: **0** (HTTP response received, not a timeout)
   - curl `time_total`: **0.002056 s**
   - subprocess wall elapsed: **0.011450 s**
   - parsed expected balance JSON: **false**
   - parsed treasury cents: **null**
   - response kind: `non_json` (raw body not retained)
   - curl stderr: empty
5. The required unexpected-authorization stop fired immediately:
   `Unexpected authorization denial: baseline treasury`.
   Baseline absent; no vendor baseline, no restart, no recovery polling.
   **Recovery time: NOT MEASURED.**
6. Script exited 1; GHA marked the diagnostic/job failure,
   uploaded eight files, and tore down the temporary stack.
   There was no second diagnostic run or automatic retry.

## Captured evidence and narrowest supported finding

Artifact includes: `result.json`, `observations.jsonl`,
`compose-up.txt`, `compose-ps.txt`, `compose-logs.txt`,
`dns-and-direct-mockapi.txt`, `envoy-clusters.txt`, and
`docker-inspect.txt`.

- Containers were running. Authz logs included `listening on :50051`;
  mockapi logs included `on 0.0.0.0:9000` when captured.
- DNS from authz container resolved envoy `172.18.0.4`,
  authz `172.18.0.3`, and mockapi `172.18.0.2`.
  These are ephemeral CI container IP addresses.
- **Direct mockapi GET from the authz container** returned
  **HTTP 200**, valid `{"acct":"treasury","cents":1000000}`.
  This was collected **after** the failed baseline.
- Envoy admin `/clusters?format=json` returned HTTP 200.
  Its `authz_cluster` counters included `cx_connect_fail=1`,
  `rq_error=1`; `mock_api` and `authz_cluster` host entries
  displayed `HEALTHY` by the time diagnostics were captured.
- A failed authz-cluster connection is directly evidenced. It is
  consistent with a cold-start/readiness race, but the precise
  first-probe failure mechanism is **not proven**. A response-body
  explanation, exact temporal correlation, and a successful
  authenticated baseline were not captured.
- **Nothing about post-restart mockapi recovery was tested in 002.**

## Verdict / scope / next discriminator

**INCONCLUSIVE** per the pre-registered rule: authorized setup did
not yield the required valid baseline. No inference that the original
stall is fixed, reproduced, or environmental is licensed.

A future owner-approved discriminating test (not authorized under
this one-run budget) would require an explicit signed-authorization
readiness gate: wait for valid 200 and expected balances, confirm
authz-cluster readiness, then perform the full-stack restart while
recording Envoy/authz versus direct mockapi status. The immediate
403 should remain separately classified and escalated, not silently
retried as a healthy probe.

**Boundaries:** exactly one diagnostic GHA run, zero retries, no paid
APIs, synthetic inspect-only authority, no real payments, no gateway
fix, no distribution change, no merge/deployment, and no frozen
baseline modifications. The earlier records are preserved.
The temporary push-trigger workflow is removed in the final evidence
commit; final commit SHA is the resulting branch HEAD (avoids a
self-referential commit hash).
