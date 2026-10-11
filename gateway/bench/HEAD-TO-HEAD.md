# OPENLINE-GATEWAY-001: Head-to-Head Evaluation Report

Date: 2026-10-10. All tests run on the same VM through the real Envoy
1.39.3. No weakened baselines: OPA-B includes the stateful controls OPA
actually supports (revocation via the Data API, decision logs).

## Configurations

- **openline**: Envoy -> OpenLine authz service (ext_authz gRPC). Signed
  action headers, mandate evaluation, nonce replay protection, signed
  decision tokens, signed receipts.
- **opa-a**: Envoy -> OPA (ext_authz via gRPC shim -> OPA REST). Bearer
  token check in Rego. No external state. The honest "what most teams run."
- **opa-b**: Envoy -> OPA with valid_tokens allowlist + revoked_tokens
  revocation list (Data API) + decision logs. The honest "OPA done well."

## Scenario results

| Scenario | openline | opa-a | opa-b |
|---|---|---|---|
| valid-request allowed | PASS | PASS | PASS |
| bad-credential denied | PASS | PASS | PASS |
| revoked-credential denied | PASS | N/A (no revocation) | PASS |
| replay: 2nd identical denied | PASS | allowed (no replay check) | allowed (no replay check) |
| forged decision header refused | PASS | accepted (unsigned) | accepted (unsigned) |
| tampered amount: authorized wins | PASS (100) | body wins (999999) | body wins (999999) |

Notes:
- opa-a "revoked-credential" is N/A, not a failure: baseline A has no
  revocation mechanism by design. OPA-B proves OPA *can* do revocation
  when configured (Data API write + re-evaluation).
- "forged-header accepted" for OPA is the honest architectural
  difference: OPA's decision is not cryptographically bound to the
  action. A competent OPA deployment relies on network isolation
  (Envoy as the only ingress) instead. OpenLine adds the signature as
  defense-in-depth.
- "tampered-amount" for OPA: OPA authorized the request; the amount came
  from the unsigned body. OpenLine's decision token carries the
  authorized params and the API executes exactly those.

## Latency (500 requests each, end-to-end through Envoy, localhost)

| config | p50 | p95 | p99 | mean |
|---|---|---|---|---|
| openline | 218.3 ms | 258.9 ms | 283.5 ms | 194.7 ms |
| opa-a | 76.4 ms | 89.0 ms | 119.2 ms | 70.6 ms |

The OpenLine overhead (~140 ms at p50) is dominated by durable sqlite
writes per Check (nonce store + signed receipt, ~42 ms in-handler).
OPA's path is stateless. WAL mode / batched commits would reduce this;
not applied here — reported as measured.

## What OpenLine bundles (the actual claim)

A capable security team *could* combine Envoy, OPA, a stateful
authorization service, and an idempotent application to implement much
of this. We do not argue competitors can't do it. The question is
whether OpenLine delivers this combination with less custom
engineering and operational burden:

1. Replay protection via nonces (per-request state the team would
   otherwise build).
2. Cryptographic decision->action binding (signed token the API
   verifies; otherwise the team relies on network boundary alone or
   builds the signing themselves).
3. Signed, independently verifiable decision receipts (otherwise the
   team builds the receipt pipeline).
4. Mandate-scoped authority with limits evaluated at consequence time
   (otherwise encoded ad-hoc in Rego + app code).

See ADOPTION-COST.md for the component/step/dependency comparison.

## What OPA already does (do not claim otherwise)

1. Per-request authorization with fail-closed default.
2. Revocation via data/bundle updates (baseline B measured working).
3. Decision logs for audit (unsigned).
4. Policy as code (Rego) with a mature ecosystem.

## Negative results / limits

- OpenLine adds ~140 ms p50 latency on this hardware (Python
  implementation, sqlite durability). Not suitable for latency-critical
  paths without optimization.
- The mock API is simulated; no real money, credentials, or customer
  data. Production non-bypassability depends on deployment (network
  isolation), not just the gateway code.
- Decision receipts prove the receiver's decision, not downstream
  effects. The gateway never claims a receipt proves an unobserved
  effect.
