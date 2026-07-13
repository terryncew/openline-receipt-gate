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

## Interoperability boundary

The adapter consumes Agent Receipts as immutable source evidence. It does not rewrite them into OLP receipts or claim that the two schemas mean the same thing.

The signed OpenLine decision references the original receipt hash and records the detected source format. This lets an Agent Receipt become an input to OpenLine policy without a format war.
