# OPENLINE-GATEWAY-001: Quickstart

Install OpenLine's receiver-owned authorization gateway, protect a
working API, and test its security properties. No paid APIs, no
account, no prior OpenLine knowledge needed.

## 1. Start it

```bash
cd gateway
make quickstart
```

This builds three containers (Envoy 1.39.3, the OpenLine authorization
service, a mock business API) and runs 13 adversarial scenarios against
the live system. Expect `13/13 passed` in about a minute.

(Without Docker: `./up.sh` runs the same stack as local processes.
You need Python 3.12, `pip install -r requirements.txt`, and the Envoy
binary — see `docs/ARCHITECTURE.md`.)

## 2. Try it yourself

Provision an agent (the owner act — in production this is your
onboarding flow):

```bash
python3 gateway_admin.py provision-agent demo-worker --max-cents=5000
# save the printed private key
```

Send a signed transfer through Envoy:

```bash
python3 - <<'EOF'
import sys; sys.path.insert(0, '.')
from agent_client import AgentClient
c = AgentClient("demo-worker", "<paste private key>")
import urllib.request
req = urllib.request.Request("http://127.0.0.1:8080/api/transfer",
                             data=b'{}', method="POST")
for k, v in c.headers_for("authorize_payment", value_cents=100).items():
    req.add_header(k, v)
print(urllib.request.urlopen(req).read().decode()[:200])
EOF
```

Now replay the exact same request (reuse the headers): Envoy returns
403. Revoke the worker (`python3 gateway_admin.py revoke-agent
demo-worker`) and the next request is denied even with a fresh
signature.

## 3. See the evidence

Every decision is a signed receipt in the gateway DB:

```bash
python3 gateway_admin.py verify-receipts
```

## 4. Compare with OPA

```bash
make up-opa-a   # ordinary OPA baseline
make up-opa-b   # OPA with revocation list + decision logs
```

See `bench/HEAD-TO-HEAD.md` for the measured comparison: what OpenLine
adds, what OPA already does, and the latency cost of each.

## 5. Challenge it

Found a bypass? A scenario where OpenLine allows what it shouldn't, or
denies what it should allow? That's the point of this kit — open an
issue with the reproduction steps.

## Limits (read before piloting)

- The business API is simulated. No real money, credentials, or data.
- Decision receipts prove the receiver's decision, not downstream
  effects the gateway never observed.
- ~140 ms p50 overhead vs the OPA baseline on the test hardware
  (Python + durable sqlite). See `bench/HEAD-TO-HEAD.md`.
- Production non-bypassability depends on deployment (network
  isolation), not just this code.
- Full details: `docs/ARCHITECTURE.md`, `bench/HEAD-TO-HEAD.md`.
