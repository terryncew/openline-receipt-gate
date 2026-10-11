# UPSTREAM-RESTART-ISOLATION-001

Verdict: **INCONCLUSIVE for the requested GitHub Actions verification** until a
complete Actions run is inspected. **PASS locally on Linux with real Docker**:
25/25 checks, including real full-stack restart, exact balances, persistent
revocation, and valid receipts. No production service or payment provider used.

Base: `experiment/gateway-subscription-001`,
`f86c23d59dc2a29240c79b8b3628ab98745df12d` (draft PR #102's stated branch).
Fix branch: `codex/upstream-restart-isolation-001`.
The base branch, historical evidence, Gateway application code, Compose
configuration, and frozen baseline are unchanged.

## Diagnosis

The untouched baseline reproduced **20/22**. Every failed readiness probe
returned **HTTP 403**, with `{"denied":true,"reasons":["agent_revoked"]}`.
The test revoked its own client in section e and reused it for section f.
`wait_for` hid the response and retried for 90 seconds. This was an authorization
denial, not evidence of an Envoy upstream outage. The mock API deliberately
suppresses per-request logging (`Handler.log_message`), so missing request logs
alone do not demonstrate failure to start.

While baseline probes failed:
- Both Python services were running, without container exit errors.
- Docker DNS resolved `mockapi` to its bridge address.
- Direct `/health` and both balance requests returned 200.
- Envoy's admin `/clusters?format=json` listed both clusters as healthy.
- An independently provisioned inspection identity read matching balances
  through Envoy, also returning 200.

A second harness defect made `compose("restart")` a successful no-op: every
service is profile-gated, and the helper omitted `--profile openline`.
Container start timestamps stayed unchanged. Explicit service selection made
`restart mockapi` work, but did not activate the profile for a later bare restart.
The baseline reproduction helper now captures before/after timestamps without
changing the historical command.

## Repair and validation

Only the verifier and its CI support change:
- Provision a separate, inspection-only receiver mandate **before** restart.
  Never un-revoke or replace the revoked payment agent.
- Activate the `openline` profile for Compose commands.
- Require newer start timestamps for all three running services.
- Assert the revoked agent is still denied after the real restart.
- Keep exact balance assertions and the existing readiness budget; require
  parsed receipt counts so the no-loss assertion cannot pass vacuously.
- Log successful balance, receipt, and restart evidence as well as failures.

The original 22 checks remain covered; two observer provisioning checks and a
post-restart revocation check bring the total to **25**. Local runs passed twice
before the final receipt-count hardening; the final-source result is recorded
separately in `fixed-final-local.log`. `unit-local.log` records **5/5** existing
Gateway unit tests with initialized temporary receiver configuration. An initial
uninitialized unit invocation failed on a missing local receiver key; no test
assertions or application code were changed to address that prerequisite.

## Commands

Standard GitHub Actions/Linux workflow:

```bash
cd gateway/compose
AUTH_MODE=openline docker compose --profile openline up --build -d
cd ../..
python3 -m pip install --break-system-packages cryptography grpcio protobuf
# Retrieve only the unchanged historical verifier for diagnosis:
git fetch --depth=1 origin f86c23d59dc2a29240c79b8b3628ab98745df12d
git show f86c23d59dc2a29240c79b8b3628ab98745df12d:gateway/ci/docker_verify.py > gateway/ci/_restart_baseline.py
python3 gateway/ci/reproduce_restart_baseline.py
python3 gateway/ci/restart_diagnostics.py
python3 gateway/ci/docker_verify.py
python3 gateway/ci/restart_diagnostics.py
cd gateway/compose
docker compose --profile openline down
```

The baseline helper returns 0 only after observing the specific historical
20/22 failure; its transcript still records the underlying verifier exit 1.
This expected failure is never described as a passing application test.
The fixed verifier must independently return 0 with all 25 checks passing.
`set -o pipefail` preserves failures when CI logs commands through `tee`.

Local cloud-machine commands:

```bash
COMPOSE_FILE=/workspace/openline-receipt-gate/gateway/compose/docker-compose.yml:/workspace/upstream-restart-isolation-001/compose-local.yaml \
  .venv/bin/python gateway/ci/reproduce_restart_baseline.py
COMPOSE_FILE=/workspace/openline-receipt-gate/gateway/compose/docker-compose.yml:/workspace/upstream-restart-isolation-001/compose-local.yaml \
  .venv/bin/python gateway/ci/docker_verify.py
COMPOSE_FILE=/workspace/openline-receipt-gate/gateway/compose/docker-compose.yml:/workspace/upstream-restart-isolation-001/compose-local.yaml \
  .venv/bin/python gateway/ci/restart_diagnostics.py
```

Local Docker required environment-only workarounds: writable `DOCKER_CONFIG`,
pre-downloaded official wheels for the exact Dockerfile dependency pins
(`grpcio==1.84.0`, `protobuf==7.36.2`, `cryptography==50.0.1`), and the unchanged
Envoy YAML copied into a named volume with mode 0644. Docker build networking
could not resolve the package registry/proxy, and the daemon could not read the
checkout bind mount. The temporary Dockerfile replaces the online installation
with `--no-index --find-links` on those wheels. TLS/checksum verification was
not disabled. Gateway code, dependency versions, bridge networking, and
verification assertions remain the same. These workarounds are outside the
checkout and are **not** a claim that the standard Actions build was verified.

## GitHub Actions and review boundary

Historical failing CI:
- https://github.com/terryncew/openline-receipt-gate/actions/runs/38122910173
  (reported 20/22 in the preserved base evidence; API inspection is blocked here).

Investigation workflow:
- https://github.com/terryncew/openline-receipt-gate/actions/workflows/gateway-subscription-001-docker.yml?query=branch%3Acodex%2Fupstream-restart-isolation-001

The environment proxy currently rejects CONNECT to `api.github.com` with 403.
`GH_TOKEN` is present; its value was not inspected. Existing authenticated Git
reads work. The `api.github.com` domain addition was saved to the environment
configuration draft; it has not been proven active or published. API access is
required to inspect Actions results and create the requested draft PR. No
conclusion or run ID is invented. The investigation limit is three additional
Docker CI attempts; see `CI-ATTEMPTS.md` for pushes and known outcomes.

No merge, real money, paid API, production deployment, private-key publication,
or changes to historical/frozen evidence are authorized or performed.
