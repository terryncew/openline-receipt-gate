# FOREIGN-STANDING-001

## Question

Can OpenLine consume two foreign governance-evidence representations, verify them at their own trust boundary, normalize them into one source-blind support object, and then apply unchanged standing / impact / gate semantics?

## Frozen claim

> After source-specific authenticity and integrity verification, equivalent foreign governance evidence can be normalized into a source-blind support object and processed by the same receiver-owned standing machinery. A later standing loss reopens the affected finalized decision, retains an independently supported decision, and blocks the next dependent action without source-specific OpenLine semantics.

This experiment does **not** claim that a foreign verdict itself confers standing.

The pipeline is:

```text
foreign representation
  -> source-specific authenticity/integrity verifier
  -> dumb normalization
  -> same OpenLine Claim Graph / standing / gate semantics
```

## Sources under test

### Microsoft Agent Control Specification representation

ACS exposes a deterministic verdict and may carry an opaque `evidence` object. ACS does not itself validate the evidence artifact or fetch its verification pointers. FOREIGN-STANDING-001 therefore requires a separately content-addressed and Ed25519-verified artifact before normalization.

The fixture uses the published ACS verdict/evidence shape plus an AGT-style offline signing bundle. The payload inside that signed artifact is an OpenLine interoperability fixture; it is **not** represented as a Microsoft-defined evidence payload schema.

### AIREP v0.1

AIREP defines a signed, hash-chained governance-decision record. The experiment enforces the relevant v0.1 boundaries used here: RFC 8785 canonical hashing, chain genesis, a pinned Ed25519 signer, `scope`, and at least one `evidence` entry with `resolvable: true`.

AIREP v0.1 is experimental and explicitly does not establish key trust. The local verifier in this benchmark covers only the frozen integer/string fixture subset needed for this interop test; it is not a substitute for AIREP's full conformance kit.

Exact OpenLine action binding is carried in the permitted namespaced AIREP profile `openline_foreign_standing_001`, rather than being smuggled into the AIREP core.

## Killer falsifier: source swap after normalization

The normalized support object intentionally excludes source identity. The source-specific verification receipt is retained separately for audit, but is not supplied to Claim Graph or Receipt Gate as standing input.

For semantically equivalent ACS and AIREP inputs, the normalized support bytes must be identical.

After normalization:

- the affected finalized decision must be `REOPEN`;
- the independently supported decision must be `RETAIN`;
- the next dependent action must be `BLOCK`.

If OpenLine needs to know whether the support came from ACS or AIREP to reach those results, protocol independence fails.

## Authority-laundering negatives

The suite must reject:

1. an ACS-shaped proceeding verdict whose pointed-to artifact is authentic but lacks the evidence needed to bind the exact action; and
2. a cryptographically valid AIREP record whose evidence is entirely `resolvable: false`.

A foreign system may attest that something happened. That does not force the receiver to grant the artifact standing.

## Verdict

Success:

`FOREIGN_GOVERNANCE_PROTOCOL_INDEPENDENCE`

Failure:

`FOREIGN_STANDING_PROTOCOL_INDEPENDENCE_NOT_ESTABLISHED`

`policy_authority: NONE`

## Claim boundary

This is a two-format, frozen-semantics interoperability experiment. It does not establish compatibility with every ACS deployment, every AIREP profile, Microsoft infrastructure as a whole, or arbitrary governance formats. It tests the separation between source verification and receiver-owned standing over the specific published representations described above.
