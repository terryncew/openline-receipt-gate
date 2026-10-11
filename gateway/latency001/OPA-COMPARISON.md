# OPA comparison construction

The fair basic and revocation-data comparisons use the official native Envoy
plugin, `openpolicyagent/opa:1.10.1-envoy`, rather than adding a Python protocol
adapter. OPA itself performs each Rego evaluation. All alternatives use the
same Envoy version, two Envoy workers, protected mock ledger and workload in
the latency runner. The historical policies and historical report are preserved.

The separate REST adapter remains available to reproduce the historical
topology. It uses one HTTP connection per gRPC worker and fails closed on
transport or result errors; it has no permission cache. It is not the preferred
OPA latency result because the native plugin removes that extra process/hop.

| Construction | Policy and credential checks | Revocation and replay | Action boundary and evidence | Components and limits |
|---|---|---|---|---|
| Original Gateway | Agent Ed25519 signature; receiver-owned validated mandate | Receiver-owned SQLite agent status; durable nonce state; execution standing when enabled | Receiver-signed single-use decision, API signature verification, durable decision consumption; signed decision receipts | Envoy + Gateway + API, shared SQLite/configuration. Standing narrows the token TTL window to the standing-check-to-effect interval. |
| Optimized Gateway | Same checks on every request | Same live state reads and replay controls | Same decision and receipt guarantees; durable transactions retain `synchronous=FULL` | Same components. Changes to connection/transaction handling do not introduce permission caching. |
| Native OPA-A (basic) | Demonstration bearer token and `/api/` path policy | No revocation state or request replay protection | API accepts an unsigned decision header; amount/destination come from the body; no signed receipt | Envoy + native OPA + API. Relies on network isolation for decision provenance. Hardcoded demonstration policy is not a production credential system. |
| Native OPA-B (revocation data) | Bearer token allowlist, current OPA revocation data, `/api/` path policy | Reevaluates current in-process data; no request replay protection | Same unsigned header/body behavior; actual unsigned OPA decision logs enabled | Same three containers, plus operational responsibility for authenticated data updates, durable revocation source/distribution and log collection. Data API updates in this lab are in memory and reset to seed data on OPA restart. No API execution-time standing check. |
| Gateway security/state wrapper + OPA (stateful construction) | Actual optimized Gateway verifies signatures and validates schema; real OPA evaluates all current mandate-fit rules | Actual Gateway SQLite, live agent revocation reads, durable nonce state, and the same execution standing configuration | Actual Gateway signs decisions/receipts; actual protected API verifies and consumes them durably | Envoy + Gateway wrapper + OPA + API. Adds OPA policy lifecycle, an HTTP hop, a fail-closed availability dependency and maintained Python/Rego parity. This reuses Gateway components; it is not an independently implemented equivalent OPA product. |

OPA is a policy engine. An independently implemented equivalent stateful
deployment also needs authenticated principal/agent enrollment; canonical
signature verification; durable atomic replay handling; receiver-owned mandate
validation; revocation consistency at admission and execution; action-bound,
signed one-use decisions; protected API validation and durable consumption;
signed persisted receipts; and crash/restart and race validation of their
composition. The basic and revocation-data rows do not provide those mechanisms.
Their latency cannot be presented as the cost of equivalent security.

The original Gateway row describes its intended controls. This investigation
also reproduced concurrent nonce-admission and shared-connection transaction
defects, plus a signed-body/header identity mismatch that could relabel a
decision. The optimized Gateway repairs these defects; the original row must
not be read as proof that the original implementation passed those checks.

The stateful construction retains the original Python schema validators and
hash computation and substitutes only `assess_effect` with an OPA query. Both
the mandate compiler and the consequence preflight references are installed
before the authorization service imports them. OPA checks exact expiry, all
identity/purpose matches, action/target/disclosure allowlists, payment/settlement
limits and delegation. No mandate result is cached. Timeout, disconnect, HTTP
error, undefined result, invalid JSON and invalid assessment all produce a
Gateway refusal rather than an allow.

Both Gateway constructions inherit the documented standing-check-to-effect
race interval; neither claims instantaneous revocation. Signed Gateway receipts
prove the receiver's recorded decision, not an independently observed downstream
effect. These tests use simulated balances and locally generated test keys.

## Reproduce

From the repository root, with the pinned Python dependencies installed:

```bash
# Basic OPA, native plugin. Change OPA_VARIANT=b for revocation-data + logs.
OPA_VARIANT=a docker compose -p latency-opa-a \
  -f gateway/latency001/compose-opa.yaml \
  -f gateway/latency001/compose-opa-native.yaml up --build -d
COMPOSE_FILE="$PWD/gateway/latency001/compose-opa.yaml:$PWD/gateway/latency001/compose-opa-native.yaml" \
COMPOSE_PROJECT_NAME=latency-opa-a OPA_VARIANT=a \
  python3 gateway/latency001/benchmark.py --mode opa-a --samples 1000 \
  --concurrency 1 --workloads transfer --clients persistent --output /tmp/latency-opa-a
OPA_VARIANT=a docker compose -p latency-opa-a \
  -f gateway/latency001/compose-opa.yaml \
  -f gateway/latency001/compose-opa-native.yaml down --volumes

# Stateful construction uses the same standing/benchmark overlay as Gateway.
docker compose -p latency-opa-stateful --profile openline \
  -f gateway/compose/docker-compose.yml \
  -f gateway/latency001/compose-openline.yaml \
  -f gateway/latency001/compose-stateful.yaml up --build -d
COMPOSE_FILE="$PWD/gateway/compose/docker-compose.yml:$PWD/gateway/latency001/compose-openline.yaml:$PWD/gateway/latency001/compose-stateful.yaml" \
COMPOSE_PROJECT_NAME=latency-opa-stateful \
  python3 gateway/latency001/benchmark.py --mode opa-stateful \
  --samples 1000 --concurrency 1 --workloads transfer --clients persistent \
  --output /tmp/latency-opa-stateful
```

Use the runner's documented output/profile options for persisted evidence and
concurrent samples. The native overlay requires Compose 2.24.4 or later for
`!override`. A cold OPA service returns fail-closed until ready; the benchmark
must run its functional readiness request before collecting warm samples.
Do not expose the OPA Data API publicly. The bearer strings in these lab
policies are fixed demonstration inputs, not production credentials.

For policy parity and error handling, start a real OPA server:

```bash
python3 -m pip install pytest  # needed only for the optional bound-authority tests below
docker run -d --rm --name latency-policy-parity \
  -p 127.0.0.1:8189:8181 \
  -v "$PWD/gateway/latency001/policy-stateful.rego:/policies/policy.rego:ro" \
  openpolicyagent/opa:1.10.1 run --server --addr 0.0.0.0:8181 /policies/policy.rego
python3 gateway/latency001/test_opa_policy.py \
  --url http://127.0.0.1:8189/v1/data/gateway_mandate/decision \
  --output /tmp/opa-policy-parity.json
LATENCY_OPA_URL=http://127.0.0.1:8189/v1/data/gateway_mandate/decision python3 - <<'PY'
from gateway.latency001.opa_stateful_authz import install_policy_engine
install_policy_engine()
import pytest
raise SystemExit(pytest.main(['-q', 'tests/test_bound_authority_falsifier.py']))
PY
docker stop latency-policy-parity
```

Parity validation covers 326 allowed, denied, exact boundary, randomized and
malformed cases, comparing the full assessment including hashes and reason
codes. Six error modes exercise the actual authorization boundary, verify the
signed refusal and assert that the nonce is unconsumed. The existing nine
bound-authority tests also run with the OPA assessment installed in the test
process; their spawned historical crash child continues to use its original
Python evaluator. This is mandate parity evidence, not a complete independent
security certification of the OPA construction.

Official plugin configuration and contract were checked against
[the project README](https://github.com/open-policy-agent/opa-envoy-plugin#configuration)
and [result handling](https://github.com/open-policy-agent/opa-envoy-plugin/blob/main/envoyauth/response.go).
The small native adapter returns the plugin's required `allowed` object field
and the historical policy's request headers, rather than treating a successful
REST response as an authorization allow.
