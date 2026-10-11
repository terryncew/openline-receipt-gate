# GATEWAY-LATENCY-001

This isolated investigation starts at `9461188f44a15766d35dcf034d386c682db403f7`
(PR #103 merged into `experiment/gateway-subscription-001`). Historical Gateway
reports, measurements, policies and the frozen baseline remain unchanged.

The measured repair uses SQLite WAL with `synchronous=FULL`, preserving each
durable commit. A lock gives each worker ownership of a complete transaction
on the shared connection. Nonce admission now requires a successful atomic
insert, and the signed action identity must match the verified header identity.
The mock API retains serial execution and HTTP/1.0; its bounded TCP accept
queue grows from five to 128 after measured listen-queue drops at concurrency
eight. Timeouts, token lifetimes, verification and fresh revocation/standing
reads are unchanged.

See [the diagnosis](DIAGNOSIS.md) for historical measurement limits and stage
profiling, and [the OPA construction](OPA-COMPARISON.md) for security and
operational differences. Basic OPA and OPA with revocation data lack the
Gateway's stateful guarantees. The stateful OPA comparison reuses the Gateway
security wrapper and replaces mandate-fit evaluation with real OPA.

## Reproduce

On Linux with Docker and Compose >=2.24.4, from this repository root:

```bash
python3 -m pip install cryptography==50.0.1 grpcio==1.84.0 protobuf==7.36.2
python3 gateway/latency001/run_matrix.py --output /tmp/gateway-latency-matrix \
  --samples 1000 --profile-samples 1000 --concurrency 1 8 32 --historical
```

The matrix runs sequentially with fresh projects and volumes, publishes only
loopback Envoy, and removes only its own projects. It records full-body request
samples, error counts, balance/effect deltas, p50/p95/p99, achieved closed-loop
throughput, first-client requests, image IDs, source revisions and runtime
settings. Request signing is timed separately. Warmup is excluded. No retries
hide errors. An original failure remains a failed row; required optimized,
OPA and floor rows must all pass. Profiling is disabled for primary latency
comparisons and separately enabled for stage diagnostics.

`51ef1df1a0366676eb4a9d6a238c2a79966df517` is an instrumentation-only original
revision. It also makes the opt-in standing listen host configurable so the
original can run with standing enabled across Docker containers. Unset
profiling decorators return their original functions. The exact merged base
is used separately to reproduce the old standing-disabled workload.

The trusted Envoy floor overlay skips proxy authorization **only in this
laboratory measurement**. Unique receiver-signed tokens are minted before
timing; the actual protected API still verifies signatures, TTL, live standing
and durable single-use consumption. Its private key stays in the receiver.
Matched Gateway minus floor medians estimate additional authorization cost;
they are not a distribution of per-request latency differences.

Run correctness verification separately from timing:

```bash
docker compose -f gateway/compose/docker-compose.yml --profile openline up --build -d
python3 gateway/ci/docker_verify.py
docker compose -f gateway/compose/docker-compose.yml --profile openline exec -T authz \
  python3 /app/gateway/ci/run_security_tests.py --output-dir /tmp/latency-security
docker compose -f gateway/compose/docker-compose.yml --profile openline down
python3 -m unittest discover -s gateway/latency001 -p test_benchmark.py -v
```

The branch-scoped [Linux workflow](../../.github/workflows/gateway-latency-001.yml)
also repeats the unchanged Docker verification suite with standing enabled,
exports only public keys and signed receipts for independent verification, and
runs real OPA parity and fail-closed tests. Every matrix Gateway row exports
and independently verifies its receipts. It never deploys or merges.

## Limits

These are simulated balances and locally generated test identities. SQLite
FULL/WAL depends on the filesystem's durability contract; process SIGKILL
tests cannot prove power-loss behavior. WAL-aware backups must include or
checkpoint sidecars. Permission results are never cached. Execution standing
still has the documented check-to-commit race interval. Increasing the accept
queue consumes bounded additional socket resources and can increase queue
latency at overload; it does not increase serial API execution capacity.
Standing verifies live agent revocation and token expiry; it does not
reevaluate mandate edits against already issued tokens. Every new
authorization reads the current mandate. Issued tokens retain the existing
60-second lifetime and execution-time revocation check.

Final Linux CI measurements and the review verdict are recorded in REPORT.md
after the complete run; no Docker success is inferred from partial results.
