# OLP × Assay Frozen Head-to-Head

## Result

All five frozen expectations were met. Assay correctly verified its evidence
bundle, rejected the corrupted bundle, and rejected a receiver-registered Trust
Basis claim whose required level was absent. OLP did not replace those checks.

The broad proposed wedge was falsified: Assay v3.32.0 can Ed25519-sign a
caller-supplied receiver-style predicate in a DSSE/in-toto attestation. The
capability control independently verified that signature and preserved predicate:
`true`.

The narrower observed difference is product semantics. With the same unchanged,
Assay-valid source bundle, OLP read the receiver's separately required artifact
and emitted a signed `COMMIT` when it was present and `QUARANTINE` when it was
missing. That is a standardized post-ingest next-use decision in this OLP
profile. It is not evidence that Assay cannot implement the same policy, nor that
an arbitrary signed predicate is uniquely available to OLP.

## Frozen cases

| Case | Assay bundle | Assay Trust Basis | OLP signed decision | OLP scoring outcome |
|---|---|---|---|---|
| case-01-clean-with-receiver-evidence | valid | pass | VERIFIED → COMMIT | correct |
| case-02-receiver-evidence-missing | valid | pass | UNDECIDABLE → QUARANTINE | correct |
| case-03-tampered-bundle | rejected | unavailable | REJECTED → DENY | correct |
| case-04-assay-registered-claim-missing | valid | fail | REJECTED → DENY | correct |
| case-05-source-hash-substitution | valid | pass | REJECTED → DENY | correct |

## What each system did

- Assay remained authoritative for its bundle verification and registered
  Trust Basis assertions. A failed Assay assertion was propagated into OLP as a
  denial and was never laundered.
- OLP preserved the incoming archive byte-for-byte by hash, then applied a
  receiver-owned policy to a separately supplied artifact and signed what that
  receiver permits next.
- Case 5 isolates an explicit receiver byte pin. Assay's standalone bundle
  verifier correctly accepts the internally intact archive; OLP rejects the
  request because its declared source hash disagrees. A receiver could also add
  an external byte pin around Assay, so this is placement of a binding—not unique
  cryptography.

## Claim boundary

This controlled five-case run demonstrates behavior for Assay v3.32.0 and OLP
v0.4.0 under the frozen fixtures and policies. It does not establish that OLP
"beats" Assay, that Assay lacks receiver policy gates, that OLP has Assay's inline
MCP enforcement, or that signing proves the truth of a predicate. Timing values
are work-cost observations, not reproducibility claims.
