# Verification report — WALLET-RECEIVER-INTEROP-001

## Verdict

**COMPATIBLE FOR THE SPECIFIED SYNTHETIC DOCUMENT RECEIVER.** No protected Wallet
format change or unsigned authority invention was needed. This is a repository
demonstration, not independent organizational adoption or production readiness.

The original kit rejected a valid Wallet export as `head_packet_shape_invalid`;
the native authorization validator rejected it as `mandate_authorization_shape_invalid`.
`evidence/rejection.json` preserves both results and an initial harness invocation
error, corrected before implementation. A format adapter, not a weaker signature
check, closes that mismatch.

## Source basis

- [Receiver formats at the pinned base](https://github.com/terryncew/openline-receipt-gate/blob/76f72ccccce79622f40163763cf614bd1d7ff776/examples/independent_receiver_kit/formats.py): native envelope, owner authorization and JWT checks.
- [Original kit PR #121](https://github.com/terryncew/openline-receipt-gate/pull/121), head `4d8565c844a26ad703a8f82332c1e18ec8acb5c1`; current base contains its lean successor via PR #125.
- [Pinned Wallet implementation](https://github.com/terryncew/openline-wallet/blob/f309aac8aecae36c4f354c7455281af6dbce486a/src/openline_wallet/wallet.py): `export_bundle`, `verify_bundle`, `replay_events`; root-signed bundle, certified epoch, signed events, exact scopes and expiries.
- [Pinned Wallet receiver](https://github.com/terryncew/openline-wallet/blob/f309aac8aecae36c4f354c7455281af6dbce486a/src/openline_wallet/receiver.py): receiver-owned trust and admission are separate from Wallet evidence.
- [Wire Canon](https://github.com/terryncew/olp-wire-canon/blob/3607996396e4a647213a4a67bc62d4ae07f998f4/SPEC.md): canonical bytes are not an authorization conversion rule.

## What was verified

| Layer | Evidence | What it does not establish |
|---|---|---|
| Authority verification | Externally pinned root; unchanged Wallet verifier; epoch and timeline signatures; scope and time checks | Merchant admission or execution |
| Receiver admission | Receiver-owned policy, exact worker proof, monotonic known history, revocation/freshness and replay checks | An external effect occurred |
| Decision signing | Receiver-pinned Ed25519 key; each application response checked | A signature alone proves durable effect |
| Effect commitment | Document, consumed nonce and signed decision commit in one SQLite transaction; separate verifier compares replay to actual rows | External payment atomicity or hidden effects outside this database |

The verifier runs in a separate process with public configuration and no signing
key. It does not import receiver dispatch/effect code. It checks signatures,
replays successful admissions and compares history, documents and nonce rows.
It shares adapter and cryptographic code, so this is **not an independently
implemented verifier or external audit**. Denial reasons generally remain signed
receiver testimony; no-effect claims are checked against captured database state.

## Results

Final `evidence/run-003`: **48 paired case executions**, 24 per mode, all matching
their expected outcomes. Forty-six snapshots verify; two deliberate document
tamper snapshots are correctly rejected. Two auxiliary authority-only snapshots
from the unrelated-scope setup also verify. Original kit regression: **32 tests
passed** (`evidence/regression.log`). Earlier 42-case run is preserved as run-001;
run-002 added expiry/principal/duplicate checks and timing. Its policy fixture left a SQLite connection open; final checkpointing changed one database hash after manifest capture. run-003 supersedes both after explicit connection cleanup; the earlier manifest discrepancy is preserved, not hidden.

Covered: authorized document; oversize, wrong target, money, wrong receiver and
principal; forged authority, untrusted root and forged worker; replay; request
and bundle expiry; duplicate without refresh; known revocation and rollback;
authorized provider succession across restart; unauthorized succession; skipped
snapshot delivery; stale authority; changed merchant policy; four simultaneous
replays (one effect); unsupported route; signed fork and persistent quarantine;
unrelated authentic scope; tampered committed document.

## Equivalent JWT comparison

Both arms use the same owner root, worker keys, exact scope, effective expiry,
receiver policy, 60-second freshness ceiling, history restrictions, nonce
storage, receiver signing key and effect/verification path. The conventional arm
uses owner-issued EdDSA JWTs carrying the same history projection. The receiver
does not issue the JWT or upgrade worker authority. Both produce identical
case-level effect counts and verifier outcomes; no superiority is demonstrated.

Representations differ: Wallet preserves epoch/event signatures; JWT has the
owner root directly attest equivalent snapshot authority. This is equivalent
effective permission and lifecycle policy, not identical credential machinery.
It intentionally includes a capable JWT history/revocation implementation,
not an expiry-only strawman.

Run-002 elapsed 25.789 seconds. One local run, not a throughput benchmark:

| Arm | Authority HTTP median / maximum | Submit HTTP median / maximum |
|---|---|---|
| Wallet | 7.319 / 32.443 ms (34 samples) | 9.070 / 14.397 ms (26 samples) |
| EdDSA JWT | 5.206 / 8.489 ms (34 samples) | 5.028 / 7.650 ms (26 samples) |

Samples mix success and refusal, include HTTP and client signature validation,
exclude startup and independent replay, and exclude concurrent requests from
these route timings. Case timings include verification and some restarts.
These measurements do not support broad cost or performance claims.

## Integration complexity and limitations

One explicit codec hook in the receiver and verifier, a bounded adapter, fixture
issuer, launcher, runner and verifier CLI. No core `src/` changes. Wallet is an
additional pinned dependency; both arms still need provisioning, trusted clock,
durable state, evidence retention and revocation delivery. Exact effort was not
instrumented and is not claimed as a reproducible integration-time metric.

- Unknown remote revocation is not instantly detectable. Freshness bounds the
  accepted snapshot; known revocation cannot be overwritten. No revocation
  push/poll service was built. Same-head re-exports cannot refresh standing;
  this conservative behavior limits availability for long-lived grants.
- Last-event selection restricts concurrent grants and may reject otherwise
  legitimate work. No general scope language or payment amount translation.
- Prefix replay is quadratic in timeline length. HTTP body limit is 64 KiB;
  large histories, denial-of-service hardening and production scaling are untested.
- Receiver administrators, SQLite write privileges and trusted time remain
  trusted. Whole-database rollback/omitted suffixes need an external checkpoint.
- Malformed transport may receive unsigned HTTP 400; signed decisions are for
  requests reaching application dispatch. No universal signed-transport promise.
- No external effect, crash/power-loss campaign, production credentials, paid
  API, organizational adoption, or cryptographic-suite superiority is claimed.
- Shared verifier primitives can share implementation defects. A separate
  implementation and independent review remain useful before production use.
