# GATEWAY-LATENCY-001: diagnosis and measurement boundaries

The earlier 218.3 ms OpenLine median was **not reproduced** on the current
Linux Docker host. Before optimization, the original Gateway completed a
strict 500-request serial transfer benchmark at 5.841 ms median with new
client connections and 5.653 ms with a persistent client connection. Both
cases executed every requested transfer successfully. The historical
140 ms median difference from basic OPA therefore cannot be claimed as a
measured improvement from this change.

Current profiling does identify a useful bottleneck: the original
authorizer's two durable SQLite commits dominate its serial handler time.
Separate concurrency and security experiments also expose defects in the
original shared-connection and nonce-claim implementation. Those failures
must be fixed and verified; fast refusals are not successful throughput.

## What the historical numbers measured

The frozen [head-to-head report](../bench/HEAD-TO-HEAD.md) records 500
end-to-end requests through Envoy, with these summaries:

| Configuration | p50 ms | p95 ms | p99 ms | Mean ms |
|---|---:|---:|---:|---:|
| Original OpenLine | 218.3 | 258.9 | 283.5 | 194.7 |
| Basic OPA | 76.4 | 89.0 | 119.2 | 70.6 |

The repository does not contain the corresponding raw latency observations,
request statuses, complete launch commands, storage measurements, or host
resource measurements. The report says the configurations ran on the same
VM with Envoy 1.39.3, but that does not establish that the historical VM
matches the present host. Filesystem behavior, resource contention and
process conditions cannot be reconstructed from the summaries alone.

Inspection of [the original benchmark](../bench/bench.py) shows additional
limits:

- It catches every exception and records its elapsed time as a sample.
  Errors, refusals and successful effects are not distinguished.
- It calls `urlopen` without consuming the response body. Its measured
  endpoint is receipt of response headers rather than the full response.
- It creates a new urllib request/connection each iteration, with no
  explicit warmup, process-cold trial or concurrent load.
- Agent action construction/signing occurs before the timer. This is
  appropriate for measuring receiver overhead, but must be stated.
- OpenLine sends `{}` and executes the signed token's amount; OPA sends
  an unsigned body containing its amount. They both transfer 100 cents in
  the intended success case, but enforce different security guarantees.

The historical report attributes the difference to durable SQLite writes
and mentions roughly 42 ms in-handler. The original signed receipt's
`latency_ms` times `_evaluate` only: nonce checking, mandate evaluation
and the nonce commit are included; receipt signing/persistence, decision
token signing, Envoy transport and protected API execution are excluded.
That field cannot substantiate a complete authorization cost or identify
the cause of the 218 ms end-to-end median. No separate historical commit
timings were retained. The attribution remains a hypothesis about that
run rather than a demonstrated explanation of the gap.

## Why later warm requests are different evidence

[The standing-race evidence](../subscription001/EVIDENCE-races.md) explicitly
bypasses Envoy. The test first obtains a decision token through gRPC, then
times a direct HTTP POST to the mock API. Its roughly 2.8 ms API median
excludes action verification, mandate evaluation, nonce persistence,
receipt signing/persistence and token signing. It measures API execution
with a previously minted authorization, not complete Gateway overhead.

The standing report and committed
[measurement JSON](../subscription001/measurements-2026-10-11.json) also
contain different run summaries: for example, the report's standing-off
POST median is 1.635 ms while the JSON records 2.524 ms. These historical
files are preserved; their numbers should not be combined into one
controlled comparison.

[The Docker evidence](../subscription001/EVIDENCE-docker.md) includes a
154.0 ms first full-chain request followed by a 4.7 ms warm request.
That result supports a startup/connection effect in that two-request
sequence. It does not establish why a separate 500-request median was
218.3 ms: one slow first request cannot by itself raise the median of
500 otherwise fast observations to that value.

The new runner reports `first_client_request` separately from warm
requests. A new client connection to an already running service is not
a fresh-process startup experiment. In the original serial trials the
first close-client request took 18.879 ms; the first persistent-client
request, after the preceding case had already warmed the services, took
7.067 ms. The profile trial's first-client request took 31.226 ms.
These observations are not interchangeable with a restarted-process
cold-path distribution, and do not prove one exclusive historical cause.

## Strict original-Gateway reproduction on this host

The original image comes from
`9461188f44a15766d35dcf034d386c682db403f7`, the experiment branch including
merged PR #103. This trial retained the original standing-off behavior,
100-cent transfers and concurrency 1. It added status/effect validation,
full response consumption, explicit warmup and separate first-client
reporting. Fifty warmup requests precede 500 measured requests per case.

| Client | Successful / measured | p50 ms | p95 ms | p99 ms | Successful req/s |
|---|---:|---:|---:|---:|---:|
| Close each request | 500 / 500 | 5.841 | 8.980 | 11.607 | 155.369 |
| Persistent connection | 500 / 500 | 5.653 | 10.169 | 15.336 | 156.900 |

Ledger deltas were checked against all successful measured, warmup and
first-client transfers. This is a successful current-host reproduction
of the workload, **not reproduction of the historical 218 ms value**.
The modest current-host median effect of front-end connection reuse
does not explain the historical difference by itself.

The exact runner arguments are recorded in the
[original-historical report](evidence/local/original-historical/report.json):

```sh
python3 gateway/latency001/benchmark.py \
  --mode openline --samples 500 --concurrency 1 \
  --clients close persistent --workloads transfer --amount 100 \
  --warmup 50 --label original-historical --output "$RESULTS"
```

Use the original image and the Compose settings recorded with that
report. The original standing-off reproduction is separate from the
standing-on original/optimized comparison; those cases should not be
treated as identical workloads.

## Original full-path profiling with execution-time standing enabled

This diagnostic trial backported only the opt-in profiler and supported
standing bind-address override to the original source. It used the same
Docker service topology as the optimized comparison, standing checks
enabled, 1-cent transfers, 20 warmup requests per worker and 1,000 measured
requests per case. The serial case passed: all 1,000 measured transfers
returned 200, with correct ledger/effect deltas and 1,000 correlated
authz/API traces. Its throughput was 134.526 successful requests/s.

| Timed stage, serial n=1,000 | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|
| Full HTTP response through Envoy | 6.847 | 10.642 | 12.812 |
| Complete authorization handler | 2.801 | 5.040 | 7.372 |
| Authorization durable commits, two per request | 1.935 | 4.083 | 6.260 |
| Nonce transaction, including its commit | 1.081 | 1.947 | 4.065 |
| Receipt transaction, including its commit | 0.992 | 2.069 | 3.886 |
| Action signature verification | 0.144 | 0.194 | 0.227 |
| Mandate compile | 0.094 | 0.142 | 0.182 |
| Mandate preflight | 0.060 | 0.096 | 0.145 |
| Revocation check, including registry read | 0.054 | 0.085 | 0.113 |
| Receipt signing | 0.065 | 0.097 | 0.125 |
| Decision token signing/encoding | 0.077 | 0.114 | 0.145 |
| Authorization request handling | 0.026 | 0.042 | 0.055 |
| Complete protected API handler | 2.433 | 3.951 | 5.447 |
| API decision-token verification | 0.161 | 0.219 | 0.273 |
| API standing-check HTTP roundtrip | 0.918 | 1.314 | 1.957 |
| Protected ledger execution, including commit | 1.107 | 2.238 | 3.772 |
| Ledger durable commit | 0.936 | 2.033 | 3.513 |
| API policy file read | 0.065 | 0.097 | 0.147 |
| API request handling/body decode | 0.011 | 0.018 | 0.028 |
| API response write | 0.090 | 0.123 | 0.154 |
| Per-request transport/Envoy/scheduling/profile-output residual | 1.486 | 2.294 | 3.917 |

The residual is calculated **per correlated request** as full HTTP time
minus authorization-handler time minus API-handler time, then summarized.
It includes network/transport and Envoy work, pre-handler queueing,
serialization, and profiler output; it is not a measured network-only
hop. Percentiles of individual stages must not be subtracted or added
to manufacture a path percentile.

Enable diagnostics with `GATEWAY_PROFILE=/tmp/authz-profile.jsonl` in
authz and `/tmp/api-profile.jsonl` in mockapi, then run:

```sh
python3 gateway/latency001/benchmark.py \
  --mode openline --samples 1000 --concurrency 1 8 \
  --clients persistent --workloads transfer --amount 1 --warmup 20 \
  --profile-file authz:/tmp/authz-profile.jsonl \
  --profile-file mockapi:/tmp/api-profile.jsonl \
  --label original-profile-standing-on --output "$RESULTS"
```

The [combined profile report](evidence/local/profile-original-clean/report.json)
is a **failed** run because its concurrency-8 case
failed; the serial case's successful result does not make the complete
report pass.

## Failures preserved during diagnosis

- [profile-original-proxy-failure](evidence/local/profile-original-proxy-failure/report.json): all 1,000 measured serial requests
  returned 403. The cloud's injected HTTP proxy was handling the
  internal `http://authz:50053/standing` request because that service
  name was absent from `NO_PROXY`. The standing check failed closed.
  The benchmark overlay now explicitly bypasses proxies for the local
  service names; it does not disable standing or tolerate the failure.
  The failed raw samples and report remain separate from the corrected
  run.
- [profile-original-clean](evidence/local/profile-original-clean/report.json), concurrency 8: 387 successful requests,
  609 responses with status 403 and 4 with status 503 among 1,000 measured
  attempts. This case is **FAIL**, despite matching ledger/effect deltas
  for the requests that succeeded. Its 36.984 ms success-only median and
  112.584 successful requests/s are conditional failure-run statistics,
  not valid all-success latency or throughput results.
- [nonce_race.json](evidence/local/nonce_race.json): a two-worker schedule synchronized the original
  code after the nonce SELECT and before `INSERT OR IGNORE`. The same
  signed nonce was allowed twice in 19 of 20 rounds; the other round
  recorded a broken barrier plus a denial. The driver and source hash
  are retained. This demonstrates a time-of-check/time-of-use defect,
  not a performance opportunity to skip replay protection.

The original authorizer uses one SQLite connection across gRPC worker
threads with `check_same_thread=False`. That setting permits access
across threads; it does not make separately executed SQL statements and
commits request-isolated transactions. Combined with a SELECT followed
by `INSERT OR IGNORE` whose insert result is not checked, the source
provides a concrete explanation for duplicate authorizations under the
forced schedule. The mixed concurrent HTTP failures are retained as
observed; every individual 403/503 is not assigned that same cause
without its own evidence.

## Optimized-stack connection backlog diagnosis

The first unprofiled optimized trial completed its concurrency-1 case
successfully: 1,000 / 1,000 requests, p50 3.747 ms, p95 4.908 ms and
p99 6.785 ms. Its concurrency-8 case was still **FAIL**, with 996 status
200 responses and four status 503 responses among the 1,000 measured
requests; one additional warmup request returned 503. These results
remain in [optimized-warm](evidence/local/optimized-warm/report.json).

The four measured 503s aligned with Envoy's mock-API cluster counters
`upstream_cx_connect_timeout=4` and `upstream_cx_connect_fail=4`. The API
container's network namespace recorded `ListenOverflows=4`,
`ListenDrops=4` and `TCPBacklogDrop=0`. The matching observed counters are
preserved in [envoy-api-before.txt](evidence/local/envoy-api-before.txt) and
[api-backlog-before.json](evidence/local/api-backlog-before.json).

The API uses a serial HTTP/1.0 server, so Envoy opens connections for
its requests. Python's inherited TCP listen backlog was five. Raising
the server's explicit `request_queue_size` to 128 targets pending
connections while retaining serial ledger execution, HTTP/1.0, the
existing timeouts/TTL and fresh security checks. It does not make ledger
commits concurrent or allow failed requests to count as successes.
Controlled reruns and the final capacity outcome belong in the final
comparison report; these initial counters alone do not prove that the
repair satisfies the complete concurrent workload.

## Independent compute and SQLite cost experiments

The [local compute experiment](evidence/local/compute_cost.json) discarded 1,000 warmup operations and
measured 10,000 operations per case:

| Operation | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|
| Ed25519 verification with public-key reconstruction | 0.104 | 0.120 | 0.155 |
| Ed25519 signing | 0.031 | 0.034 | 0.056 |
| Mandate compile plus preflight | 0.046 | 0.064 | 0.094 |

These isolated measurements omit service and JSON/transport work. They
support retaining every signature and mandate check; their cost is
small relative to this host's measured durable-write cost.

The [SQLite experiment](evidence/local/sqlite_cost.json) used `synchronous=FULL` in every configuration,
discarded 200 warmups and measured 1,000 two-row writes per case:

| Storage location | Journal | Commits/request | p50 ms | p95 ms | p99 ms |
|---|---|---:|---:|---:|---:|
| `/workspace` scratch | DELETE | 2 | 1.271 | 1.944 | 3.482 |
| `/workspace` scratch | DELETE | 1 | 0.691 | 0.920 | 1.115 |
| `/workspace` scratch | WAL | 2 | 0.211 | 0.384 | 1.127 |
| `/workspace` scratch | WAL | 1 | 0.135 | 0.262 | 0.335 |
| `/tmp` | DELETE | 2 | 0.036 | 0.080 | 0.114 |
| `/tmp` | WAL | 2 | 0.012 | 0.018 | 0.032 |

The path-dependent results show why host/storage differences require
measurement. They are synthetic local costs, not Docker-volume results
or proof of hardware power-loss durability. In particular, relocating
the actual durable ledger to `/tmp` is not an accepted optimization.
WAL with `synchronous=FULL` is the targeted configuration to assess on
the real stack. Combining commits requires preserving atomic nonce
consumption and receipt persistence before successful authorization;
the final implementation and correctness evidence are documented
separately.

## Profiling interpretation and limits

`gateway/profiling.py` is opt-in and logs durations, stage call counts,
process/sequence information and a validated UUID trace. It does not
log request bodies, action values, credentials, SQL parameters or keys.
Nested spans are **inclusive**: nonce/receipt transaction spans include
their durable commits; API execution includes the ledger commit.

The output is appended after the timed handler returns internally but
before its caller receives the response. Thus profile output contributes
to real end-to-end latency and its residual even though it is excluded
from the handler span. Profiling-on diagnostics explain cost; the primary
before/after comparison uses profiling disabled. These observations
establish current bottlenecks and methodological differences while
leaving the exact cause of the historical 218/76 ms run unresolved.
