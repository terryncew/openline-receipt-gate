# OpenLine Gateway: Adoption Guide

DRAFT. Public claims in this guide are pending measured demo evidence
from GATEWAY-SUBSCRIPTION-001. The subscription demo is the enterprise
gateway's first understandable consumer-facing use case, not a separate
product.

## What it is

The OpenLine gateway is a receiver-owned authorization layer that sits
in front of a consequential API. Every request passes through Envoy's
ext_authz filter and is evaluated at consequence time against a
mandate: who may do what, to which targets, within what limits. Allowed
requests carry a signed, single-use decision token the API verifies.
Everything else gets 403. Decisions are written as signed receipts in a
local database. See `gateway/docs/ARCHITECTURE.md`.

## Install

```bash
cd gateway
make quickstart
```

This builds three containers (Envoy 1.39.3, the OpenLine authz service,
a mock business API) and runs 13 adversarial scenarios against the live
system. Expect `13/13 passed` in about a minute.

Without Docker: `./up.sh` runs the same stack as local processes. You
need Python 3.12, `pip install -r requirements.txt`, and the Envoy
binary.

For the subscription demo stack, see the demo's own README when the
demo evidence agent delivers it. [PENDING MEASUREMENT]

## Configuration

Three files own the gateway's behavior.

- `gateway/config/policy.json`: the enforcement mode. `enforce`
  (default) allows only mandate-permitted requests. `observe` evaluates
  and records but never blocks. Labeled non-protective.
- `gateway/config/receiver.key`: the receiver's Ed25519 private key.
  Signs decision tokens and receipts. Protect this file as you would a
  CA key.
- Agent mandates: created with `python3 gateway_admin.py provision-agent
  <name> --max-cents=<limit>`. The owner act. Sets action types,
  targets, and the payment ceiling. The worker holds only its own
  private key and can never widen its own mandate.

Key commands:

```bash
python3 gateway_admin.py init                    # first-time setup
python3 gateway_admin.py provision-agent demo --max-cents=5000
python3 gateway_admin.py revoke-agent demo       # permission ends here
python3 gateway_admin.py set-mode observe        # needs admin + restart
python3 gateway_admin.py verify-receipts          # verify signed receipts
```

Changing the mode is an administrator action. Agent headers cannot
change it.

## Operating it

Provision and revoke are the runtime operations. Provision an agent
when the owner grants authority. Revoke the moment authority should end.
New authorizations stop immediately on revocation. [PENDING MEASUREMENT]

Backups: copy two files. `gateway/config/receiver.key` (the signing
key) and `gateway/state/gateway.db` (nonces, receipts, agent registry).
OpenLine has no external operational dependencies: sqlite file, one key
file. See `gateway/docs/ADOPTION-COST.md`.

Monitoring: each Check decision is a signed receipt in the database.
Run `verify-receipts` to confirm the receipt chain. Denied requests
surface as 403 from Envoy; fail-closed means authz-service outages
reject rather than pass.

## What it replaces, what it does not

It replaces the custom code a team would otherwise build to get
mandate-scoped authorization with replay protection, signed
decision-to-action binding, revocation, and signed receipts. It does
not replace the network isolation that makes the gateway the only path
to the API. It does not replace the business layer's own idempotency
logic. A capable team could build the combination from Envoy, OPA, a
stateful service, and custom app code. The claim is burden, not
exclusivity: one installable unit with fewer custom components to build
and operate.

## Measured costs

Latency overhead vs the OPA baseline on the build hardware (Python +
durable sqlite, 500 requests end-to-end through Envoy):

- p50: [PENDING MEASUREMENT] (gateway baseline: ~140 ms, ~218 ms
  absolute p50; see `gateway/bench/HEAD-TO-HEAD.md`)
- p95: [PENDING MEASUREMENT]
- p99: [PENDING MEASUREMENT]

The overhead is dominated by durable sqlite writes per Check. WAL mode
and batched commits would reduce it; not applied in this build. Not
suitable for latency-critical paths without optimization.

Demo subscription flow timings (charge, revocation, refusal):
[PENDING MEASUREMENT] from the demo evidence agent.

## What this does not do

- It does not force banks or merchants to honor mandates. A receiver
  that never integrated OpenLine will not refuse a charge on the
  strength of a mandate. The refusal happens only where the receiver
  enforces.
- Receipts prove the receiver's decision, not downstream effects the
  gateway never observed. A receipt is proof of what happened and who
  authorized what, not proof of what a downstream system did.
- Revocation is not instant for in-flight tokens. New authorizations
  stop immediately on revocation. Decision tokens already minted stay
  valid up to their 60 s TTL. Do not claim instant revocation.
- It does not prove exactly-once business execution. It stops duplicate
  authorizations; the business layer's idempotency is separate.
- It does not substitute for network isolation. Production
  non-bypassability depends on deployment: the gateway must be the only
  path to the API.
- It does not rewrite commercial terms. OpenLine settles what happened
  and who authorized what. It does not change the contract underneath.
