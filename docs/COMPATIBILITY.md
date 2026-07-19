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

## OpenLine Half-Life / Verified Model Swap

The v0.5 integration is pinned to:

```text
openline-half-life 0.2.0rc5
commit 70121b53e86196d69b2c3457174b38ad32667b43
receipt bundle openline.half-life.receipt-bundle.v3
causal capsule openline.half-life.causal-capsule.v1
decision equivalence openline.half-life.decision-equivalence.v1
```

Install it with `pip install -r requirements-model-swap.txt`. The receiver must
also provide the succession-policy and compaction-policy public-key pins from
outside the Half-Life output. Receipt Gate delegates Half-Life artifact and
archive verification to the pinned package, then calls its independent raw
history replay and exact receiver projection. It does not accept the stored
equivalence boolean or a capsule signature as sufficient evidence by itself.

Other Half-Life versions are not release-qualified by this candidate. A missing
runtime skips the eight integration tests in an ordinary core test run and holds
the complete v0.5 release gate.

## Decision receipts / Verified Commit

The Python and Node verifiers accept signed decision receipt versions v0.2,
v0.3, and v0.4. Only v0.4 may carry `commit_authorization`; a legacy receipt
with that field populated fails semantic verification. Verified Commit uses the
existing receipt kind and `COMMIT` disposition.

The reference tool-side checker is Python and relies on `fcntl` locking plus
atomic replacement. It is intended for POSIX receiver processes sharing one
ledger path. Equivalent non-POSIX or distributed adapters must provide their
own atomic compare-and-consume boundary; signature verification alone is not an
enforcement substitute.

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

The v0.3.1 runner carries a byte-identical copy of the original frozen protocol
so a clean public clone can verify the freeze hash without the unpublished
intermediate Git commit. This portability fallback does not change fixtures,
expectations, scores, or the narrower OLP/Pipelock claim boundary.

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

## Assay

Supported profile:

```text
Assay Evidence Contract bundle schema_version: 1
Assay CLI: exactly 3.32.0
receiver descriptor format: assay_evidence_bundle_v1
```

The receiver descriptor is additive to the v0.2 proof-to-policy request:

```json
{
  "source_bundle": {
    "format": "assay_evidence_bundle_v1",
    "path": "assay/evidence-bundle.tar.gz",
    "sha256": "<receiver-declared archive hash>",
    "trust_basis_requirements": [
      "bundle_verified=verified"
    ]
  }
}
```

`source_bundle` and `source_receipts` are mutually exclusive. Bundle paths are
confined to the request base directory, symlink escapes are rejected, and the
archive is limited to 100 MB before execution. The request cannot select an
Assay executable. The trusted caller supplies it with the API argument,
`--assay-bin`, or `OLP_ASSAY_BIN`.

The adapter delegates to these official commands:

```text
assay evidence verify
assay evidence show --format json
assay trust-basis generate
assay trust-basis assert --format json
```

It checks the archive against the receiver-declared SHA-256, requires the exact
CLI version, records the manifest root and registered claim levels, and retains
only hashes and bounded metadata in the OLP decision. Raw Assay events are not
copied into the decision receipt.

An exact-level Trust Basis assertion failure maps to failing `coverage` and
`source_signal` checks. A passing assertion makes the source eligible as an
evidence input but remains partial coverage: it does not prove semantic
completeness for an arbitrary receiver policy. When the bundle's
`signing_evidence_present` level is `absent`, provenance is explicitly
unavailable rather than silently upgraded by successful content verification.

The frozen track pins Assay release commit
`04d3db10adbe191aa731d52a6c2b77dad8bc0ca7` and the official Linux archive
SHA-256
`243f5e3935530cb1405dbb54fa57acc944de2800d28537d08dfc305b2a117775`.
The scored runner verifies that the executed binary is the archive member and
regenerates the public OpenFeature fixture byte-identically before scoring.

Assay's DSSE attestation envelope is exercised as a benchmark capability
control, not accepted by this adapter as a substitute for receiver-policy
recomputation. The passing control establishes that arbitrary-predicate signing
is not unique to OLP.

## Interoperability boundary

The adapters consume Agent Receipts, Pipelock receipts, and Assay evidence
bundles as immutable source evidence. They do not rewrite them into OLP receipts
or claim that the schemas mean the same thing.

The signed OpenLine decision references the original receipt hash and records the detected source format. This lets either receipt become an input to OpenLine policy without a format war.
