# Historical OPA shim rerun

The earlier report's **76.4 ms OPA-A median was not reproduced**. This rerun
uses real Linux Docker and the original OPA shim and mock API from merged base
`9461188f44a15766d35dcf034d386c682db403f7`, rather than the optimized shim/API or
native OPA plugin used by the main fair comparison. Source bytes inside the
original image match that Git commit, as recorded in
[metadata.json](evidence/local/historical-opa-shim/metadata.json).

Envoy 1.39.3 has two workers, the original `urllib` shim queries official OPA
1.10.1, and the frozen OPA-A Rego policy authorizes a fixed demonstration bearer
token. The original API retains HTTP/1.0, its five-entry accept queue and SQLite
DELETE/FULL. Only the shim's OPA URL is overridden at process startup to use
the Compose service hostname. Internal destinations bypass the cloud's external
HTTP proxy. Frozen source and policies remain untouched.

Each row contains 500 measured sequential requests transferring 100 simulated
cents, plus a separately recorded first-client request. The strict runner reads
the whole response and checks HTTP status, successful effects, unique effect
IDs, exact treasury/vendor deltas and durable effect counts. Errors are not
swallowed or retried. The first two rows start with a fresh stack and ledger;
the persistent row follows the close-client row. The second pair repeats on
the already running stack with ten transfer warmups before each measured row.
Functional readiness uses a real proxied balance read before the first row;
process startup is excluded. These are not four independent cold starts.

| Condition | Client connection | p50 ms | p95 ms | p99 ms | Successful requests/s | First transfer ms |
|---|---|---:|---:|---:|---:|---:|
| Fresh stack, no explicit transfer warmup | Close | 3.764 | 4.740 | 6.355 | 256.8 | 15.535 |
| Same stack, no explicit transfer warmup | Persistent | 3.556 | 7.188 | 10.487 | 246.7 | 6.157 |
| Warm repeat, ten warmups | Close | 3.623 | 5.425 | 7.639 | 254.9 | 16.915 |
| Warm repeat, ten warmups | Persistent | 3.268 | 4.117 | 5.719 | 295.3 | 5.463 |

All 2,000 measured requests passed. Including first requests and warmup, 2,024
durable effects moved exactly 202,400 simulated cents; total balances remained
1,050,000 cents. Each row's summary and all request samples are preserved in
[the evidence directory](evidence/local/historical-opa-shim).
[The final ledger](evidence/local/historical-opa-shim/ledger-final.json) and its
SQLite backup contain the actual final state, without receiver private keys.
The original API made no Gateway nonce records or signed receipts in OPA mode;
this is part of its documented security difference.

The earlier Gateway median also did not reproduce in the separate original
Gateway rerun: 5.841 ms with close-client connections and 5.653 ms with a
persistent client, at the same 500-request/100-cent scale. The corresponding
original OPA medians here are 3.764 and 3.556 ms. These host-local measurements
do not establish why the old host reported 218.3 versus 76.4 ms. Original host
hardware, filesystem timing, scheduling and request-level samples were not
preserved with that summary. A first-use cost exists, but neither these first
requests nor the modest warmup/connection-reuse changes reproduce the old
roughly 140 ms median gap. Attribution of that historical gap remains
inconclusive; the main matched Linux CI matrix supplies current measurements.

## Reproduce the original-source path

From the repository root, on Linux with Docker and Compose >=2.24.4:

```bash
# Build the exact original source once, outside the checkout.
set -o pipefail
latency_original_source="$(mktemp -d)"
git archive 9461188f44a15766d35dcf034d386c682db403f7 | tar -x -C "$latency_original_source"
docker build -t gateway-latency-original:9461188 \
  -f "$latency_original_source/gateway/compose/Dockerfile.gateway" "$latency_original_source"

export COMPOSE_FILE="$PWD/gateway/latency001/compose-opa.yaml:$PWD/gateway/latency001/compose-opa-historical-shim.yaml"
export COMPOSE_PROJECT_NAME=latency-historical-opa
export LATENCY_PORT=18081 OPA_VARIANT=a
docker compose up --no-build -d

# Observe actual policy and API readiness before starting measurement.
python3 - <<'PY'
import json, urllib.request
request = urllib.request.Request('http://127.0.0.1:18081/api/balance/treasury',
    headers={'Authorization': 'Bearer opaline-token-001'})
with urllib.request.urlopen(request, timeout=5) as response:
    assert response.status == 200
    assert json.load(response)['cents'] == 1000000
PY

python3 gateway/latency001/benchmark.py --mode opa-a \
  --url http://127.0.0.1:18081 --samples 500 --concurrency 1 \
  --clients close persistent --workloads transfer --amount 100 --warmup 0 \
  --output /tmp/historical-opa-shim/no-explicit-warmup
python3 gateway/latency001/benchmark.py --mode opa-a \
  --url http://127.0.0.1:18081 --samples 500 --concurrency 1 \
  --clients close persistent --workloads transfer --amount 100 --warmup 10 \
  --output /tmp/historical-opa-shim/warm-repeat

# Archive the summaries/raw samples and ledger before removing this project.
docker compose down
```

Use a fresh project/volume for the first pair. A previously used ledger will
correctly fail the initial 1,000,000-cent readiness assertion. The pinned Python
dependencies and versions are the same as the main benchmark instructions.

## Cloud-instance compatibility and limits

The local run used `.venv/bin/python` 3.12.14 and
`DOCKER_CONFIG=/workspace/upstream-restart-isolation-001/docker-config` because
the default Docker buildx directory is read only. The original image was already
built from the pinned offline wheels by the root investigation; this subtask
did not rebuild or replace dependencies. Its image ID and exact application
source hashes are recorded in metadata.

The cloud Docker daemon cannot reliably read these workspace bind mounts. The
local run added an external, measurement-only Compose overlay at
`/workspace/gateway-latency-scratch/compose-opa-historical-local.yaml`, using the
owned named volume `gateway-latency-historical-opa-config`. The four public
configuration files were copied into that volume and set to mode 0644. The
original Gateway's external Envoy configuration volume was not touched. On an
ordinary Linux Docker host, the tracked overlays above use standard read-only
bind mounts and need no compatibility overlay.

The exact local Compose selection was:

```bash
export DOCKER_CONFIG=/workspace/upstream-restart-isolation-001/docker-config
export COMPOSE_FILE="$PWD/gateway/latency001/compose-opa.yaml:$PWD/gateway/latency001/compose-opa-historical-shim.yaml:/workspace/gateway-latency-scratch/compose-opa-historical-local.yaml"
export COMPOSE_PROJECT_NAME=latency-historical-opa LATENCY_PORT=18081 OPA_VARIANT=a
```

The public cloud overlay is preserved as
[compose-cloud-local.yaml](evidence/local/historical-opa-shim/compose-cloud-local.yaml).
To recreate its named-volume configuration:

```bash
docker volume create gateway-latency-historical-opa-config
docker create --name gateway-latency-historical-opa-copy \
  -v gateway-latency-historical-opa-config:/bench \
  gateway-latency-original:9461188 sh -c 'chmod 644 /bench/*'
docker cp gateway/latency001/envoy-opa-compose.yaml \
  gateway-latency-historical-opa-copy:/bench/envoy.yaml
docker cp gateway/latency001/opa-config-a.yaml \
  gateway-latency-historical-opa-copy:/bench/opa-config-a.yaml
docker cp gateway/latency001/opa-data.json \
  gateway-latency-historical-opa-copy:/bench/opa-data.json
docker cp gateway/opa/policy-a.rego \
  gateway-latency-historical-opa-copy:/bench/policy-a.rego
docker start -a gateway-latency-historical-opa-copy
docker rm gateway-latency-historical-opa-copy
```

Copy that overlay to the recorded scratch path, or select its preserved path
as the third `COMPOSE_FILE` component. The historical project's config/state
volumes were retained after stopping its containers, and its public final
SQLite ledger backup and compressed container logs were archived as evidence.

This is a current-host rerun of original source, not a recreation of the unknown
historical host. The client timer also deliberately fixes the old benchmark's
error swallowing and incomplete response consumption. Those historical harness
defects prevent the old summary from establishing 500 successful effects, but
do not prove that its reported slow median came from failures. The main native
OPA comparison remains the appropriate policy-engine latency comparison because
it removes the extra Python adapter process and HTTP hop.
