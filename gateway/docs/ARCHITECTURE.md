# OPENLINE-GATEWAY-001: Architecture

## The boundary

```
                    ┌─────────────────────────────────────────┐
                    │              Envoy 1.39.3 (:8080)       │
                    │                                         │
  agent ──signed──▶ │  ext_authz filter (fail-closed)         │
  headers           │       │ Check (gRPC)                    │
                    │       ▼                                 │
                    │  ┌─────────────┐    x-ol-decision       │
                    │  │  OpenLine   │───(signed token)──────▶│──▶ mock API
                    │  │ authz svc   │    added on allow      │    (:9000)
                    │  │  (:50051)   │                        │    verifies
                    │  └─────────────┘                        │    signature
                    │       │ writes                          │    single-use
                    │       ▼                                 │
                    │  sqlite: nonces, receipts, agents       │
                    └─────────────────────────────────────────┘
```

Every consequential request passes through the ext_authz filter before
reaching the API. The filter fails closed: if the authz service is
unreachable, requests are rejected.

## Who owns what

- **Owner** (offline): provisions agents (`gateway_admin.py
  provision-agent`), issuing a `principal_mandate/v1` with action
  types, targets, and `max_payment_cents`. Holds no runtime role.
- **Receiver** (the gateway): owns `receiver.key` (signs decision
  tokens and receipts), `policy.json` (mode, observe/enforce), and the
  agent registry. Evaluates every request at consequence time via
  `olp_gate`'s `compile_verified_commit_settings` + `mandate_preflight`.
- **Worker** (agent): holds only its own Ed25519 private key. Signs
  action claims. Cannot grant itself permission, change policy, mint
  decision tokens, or select the enforcement mode.
- **Mock API**: verifies the receiver-signed decision token, executes
  exactly the authorized params (never the body's), enforces
  single-use. Simulated ledger only.

## Decision token

Minted by the authz service on allow, verified by the mock API:

```json
{
  "decision_id": "…", "agent_id": "…",
  "action_type": "authorize_payment", "target": "ledger",
  "value_cents": 100, "nonce": "…",
  "issued_at": 1791697200, "ttl": 60,
  "sig": "<receiver Ed25519>"
}
```

Short-lived (60 s) and single-use (the API records spent IDs).
Replaying it is refused; forging it fails the signature check.

## OBSERVE vs ENFORCE

- **enforce** (default): only allowed requests reach the API, carrying
  a decision token. Everything else gets 403.
- **observe**: the service evaluates and records every decision but
  returns OK regardless, with an `x-ol-observe-decision` header telling
  the API what *would* have happened. Labeled non-protective.

Mode is an administrator action (`gateway_admin.py set-mode` +
restart). Agent headers cannot change it.

## ext_authz protocol note

The service speaks the real `envoy.service.auth.v3.Authorization/Check`
gRPC API using a minimal wire-compatible proto
(`proto/ext_authz.proto`). Field numbers were verified against Envoy
v1.39.3's actual definitions — including the non-obvious one:
`CheckResponse.ok_response` is field **3**, not 2.

## OPA baselines (for the head-to-head)

- **opa-a**: stock OPA 1.10.1 + `opa/policy-a.rego` (bearer token check).
  A gRPC→REST shim (`opa_shim.py`) adapts ext_authz to OPA's HTTP API;
  the decision logic is 100% Rego.
- **opa-b**: same + `valid_tokens`/`revoked_tokens` in OPA data (Data
  API) + decision logs. Revocation works: write + re-evaluation.

The mock API runs with `GATEWAY_AUTH_MODE=opa` for baselines, accepting
OPA's unsigned `x-opa-decision` header — the honest architectural
difference under test (see `bench/HEAD-TO-HEAD.md`).

## What the gateway does NOT do

- Prove downstream effects (receipts prove the decision, not execution).
- Provide exactly-once business execution (it stops duplicate
  *authorizations*; the business layer's idempotency is separate).
- Replace network isolation (defense in depth, not a substitute).
- Run at production latency without optimization (~140 ms p50 overhead
  measured; dominated by durable sqlite writes).
