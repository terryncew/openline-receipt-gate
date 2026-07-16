# Compatibility

## OLP Wire Canon

Supported profile:

```text
receipt_version: 0.1
canonicalization_id: olp-canonical-json-int-v1
attestation: self
capture_status: provisional
```

Supported kinds:

```text
trace_receipt
coherence_input_receipt
amendment_receipt
capture_loss_amendment
```

The adapter checks strict kind-specific fields, Ed25519 signature, payload hash, safe-integer canonicalization, amendment order, parent continuity, and declared loss.

## Agent Receipts

Supported protocol versions:

```text
0.1.0
0.2.0
0.2.1
0.3.0
0.4.0
0.5.0
```

The adapter checks the published Agent Receipt envelope fields, embedded `Ed25519Signature2020` proof as implemented by Agent Receipts, integer-only RFC 8785 canonicalization, issuer/chain continuity, sequence, parent hashes, and terminal placement.

`tests/fixtures/agent-receipts-v050-runtime.json` is copied from the upstream Apache-2.0 cross-SDK vector at commit `df6833a39743e17127d5ad4b10cdc8f6734d8e03`. The test matches both its published receipt hash and its Ed25519 proof. This is a specific interoperability check, not a claim of generic W3C VC conformance.

Verification methods can be supplied through the external trust store. Ed25519 `did:key` values can also be resolved locally. Resolution proves which key signed; trust remains an external decision.

Agent Receipt extensions containing floating-point values return `canonicalization_unsupported`. The gate refuses to guess at ECMAScript number serialization.

## Pipelock

Supported phase-1 profile:

```text
ActionReceipt v1
pipelock-verify 0.2.x
stock envelope: version / action_record / signature / signer_key
```

This profile was implemented against Pipelock commit
`371893f0084ed693c1f69adf6da81c269e84aeff` and
`pipelock-verify-python` commit
`329f1c76fdfa5fc5b165a3794f7c62906a076c03`. The adapter delegates
individual signature/profile verification, chain verification, and native
receipt hashing to that official package. It does not reproduce Pipelock's
frozen Go-struct canonicalization locally.

Install this optional integration with
`pip install -r requirements-pipelock.txt`. If the official package is
absent or outside the supported range, all Pipelock assessment axes return
an explicit verifier-unavailable/version-unsupported result. There is no local
cryptographic fallback.

Published v0.1.1 exposes the same top-level API but does not reproduce signatures
for newer v1 action records whose canonical field set grew after that release.
It is therefore rejected rather than treated as compatible. The frozen benchmark
and integration suite use v0.2.0 from the exact source commit above.

The signer key must be pinned by an external OLP trust-store record carrying the
`source` role to establish provenance. Without that pin, the native verifier can
still establish signature self-consistency, but the adapter reports provenance
as unavailable and `signatures_verified: false` in the trusted-provenance sense.

Pipelock's action verdict is mapped into a separate `source_signal` assessment:

| Native action verdict | OLP source signal | Constraint |
|---|---|---|
| `allow`, `forward` | `pass` | advisory input; not an automatic `COMMIT` |
| `block` | `fail` | hard failure; never `COMMIT` |
| `warn`, `ask`, `strip`, `redirect`, `defer` | `partial` | cannot commit without an explicit future policy mapping |
| unknown | `fail` | fail closed |

EvidenceReceipt v2 is recognized by `record_type: evidence_receipt_v2` but is
outside phase 1. It returns the explicit reason
`pipelock_evidence_receipt_v2_phase1_unsupported`, with
`canonicalization_unsupported` at the integrity boundary. It is not reported as
a bad v1 signature.

The published interop fixture is copied from `agent-egress-bench` commit
`1a0d386f3d3d9370dbb6f9c86c92c403fb529cb4`. The adapter matches the official
verifier's `allow` result and receipt hash
`34f2780dcb510c03f55fc31387c993066fad23e328a2bf5f64b630b8d58a0dfb`.

## Interoperability boundary

The adapters consume Agent Receipts and Pipelock receipts as immutable source evidence. They do not rewrite them into OLP receipts or claim that the schemas mean the same thing.

The signed OpenLine decision references the original receipt hash and records the detected source format. This lets either receipt become an input to OpenLine policy without a format war.
