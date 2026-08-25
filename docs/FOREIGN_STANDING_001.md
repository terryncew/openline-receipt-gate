# FOREIGN-STANDING-001 — foreign evidence, receiver-owned standing

OpenLine should not need to own the runtime policy engine or the receipt envelope.

The remaining architectural question is whether foreign governance evidence can cross into OpenLine without importing the foreign system's policy semantics.

The experiment freezes four boundaries:

1. **Verdict is not evidence.** An ACS verdict is insufficient by itself because ACS treats its evidence object as opaque.
2. **Authenticity is not standing.** A foreign artifact can be authentic and still fail the receiver's evidence requirements.
3. **Normalization is not adjudication.** Adapters translate already-verified facts; they cannot decide whether standing survives.
4. **Source identity disappears from the decision path.** After normalization, OpenLine must produce the same impact and gate outcome for semantically equivalent inputs.

The common support envelope carries only the receiver-needed semantic facts:

- exact action hash;
- evidence key;
- assertion;
- coverage;
- policy basis;
- receiver verification status;
- receiver signature.

Source provenance remains in a separate verification receipt for audit. That receipt is deliberately withheld from Claim Graph / Receipt Gate when they compute standing. This makes the source-swap test mechanical rather than rhetorical.

The real OpenLine path remains unchanged:

```text
verified normalized support
  -> admitted Claim Graph dependency state
  -> later source-status event
  -> bounded impact
  -> standing projection
  -> Receipt Gate
```

Expected final state:

```text
affected finalized decision      REOPEN
independently supported decision RETAIN
next dependent action            BLOCK
```

The suite also proves a negative: valid cryptography is insufficient to manufacture standing when the underlying evidence is opaque or unresolvable.

## External-version boundary

The Microsoft side is a published-format interoperability fixture, not a live Microsoft AGT SDK integration. The AIREP side is a v0.1-format fixture checked against the normative fields needed by this experiment, not a claim of full AIREP conformance.

A later production adapter should replace each fixture verifier with the upstream project's own verifier / attestation surface where available. The OpenLine normalization and standing layers should remain unchanged.
