# OPENLINE-GATEWAY-001: Adoption Cost Comparison

The question is not whether a capable team *could* build these
protections from Envoy + OPA + custom services — they could. The
question is what it costs to install, verify, and maintain each
approach. Counted from the actual builds in this repo.

## Components per approach

| | OpenLine gateway | OPA-A (ordinary) | OPA-B (stateful) | "Build it all" |
|---|---|---|---|---|
| Ingress | Envoy 1.39.3 | Envoy 1.39.3 | Envoy 1.39.3 | Envoy |
| Policy engine | OpenLine authz service (Python) | OPA 1.10.1 | OPA 1.10.1 | OPA |
| Protocol adapter | none (native ext_authz gRPC) | gRPC→REST shim (~90 lines) | gRPC→REST shim | custom |
| Replay store | sqlite (built in) | — | — | custom (Redis/DB + code) |
| Decision binding | signed token (built in) | — | — | custom (signing + verification) |
| Receipts | signed sqlite (built in) | — | OPA decision logs (unsigned) | custom pipeline |
| Revocation | registry + per-request check (built in) | — | Data API writes | custom |
| Mandate/limits | olp_gate (built in) | Rego | Rego | Rego + app code |
| Business API | mock (verifies token) | mock (trusts header) | mock (trusts header) | idempotent app (custom) |

## Configuration steps (fresh install)

**OpenLine:** `gateway_admin.py init` → provision agents → `make
quickstart`. 3 steps. One policy file, one key file, one DB.

**OPA-A:** write Rego policy → start OPA → start shim → Envoy config →
mock API in OPA mode. 5 steps across 3 components.

**OPA-B:** OPA-A steps + seed `valid_tokens`/`revoked_tokens` via Data
API + decision log config + revocation runbook (who writes the Data
API, on what trigger, with what staleness bound). 8+ steps.

**"Build it all"** (replay + binding + receipts + revocation on OPA):
OPA-B steps + design and build the nonce store, token minting service,
receipt signing pipeline, and idempotent application logic. Weeks of
engineering, then owned forever.

## Operational dependencies

- **OpenLine:** none external. sqlite file, one key file. Backup =
  copy two files.
- **OPA-A:** none external. Policy file.
- **OPA-B:** the revocation writer (something must call the Data API;
  that something is a new operational dependency with its own failure
  modes and staleness bound).
- **"Build it all":** the nonce store, the signing service, the receipt
  store, and the idempotency layer — each with backups, monitoring,
  and rotation.

## What the measurements say

- OpenLine's bundle costs ~140 ms p50 vs OPA-A on the test hardware
  (Python + durable sqlite). That is the price of the bundle, measured.
- OPA-B's revocation works (measured: denied after Data API write),
  with a staleness bound set by the operator's write path — not by OPA.
- OpenLine's revocation bound is measured too: new authorizations stop
  immediately (scenario 16: 0/10 executed post-revoke); in-flight
  decision tokens remain valid up to their 60 s TTL (scenario 17).
  No instant-revocation claim is made.

## The product thesis

OpenLine doesn't invent a capability nobody else can reproduce. It
ships the combination — portable mandate, action-bound enforcement,
verifiable receipts, measured revocation bounds — as one installable
unit with fewer custom components to build and operate. If an
enterprise pilot finds that combination easier to install, verify, and
maintain than assembling it from parts, that's the win.
