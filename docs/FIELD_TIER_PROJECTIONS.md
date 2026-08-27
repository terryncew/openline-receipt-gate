# Field-tier projections

Field-tier projections keep complete action parameters out of a mediator and
portable audit ledger without weakening the receiver-owned authorization
boundary.

The sequence is fixed:

1. Commit the complete parameters under OpenLine canonical JSON.
2. Apply the receiver's field definition.
3. Send only policy fields and named derived projections to the mediator.
4. Bind the signed public receipt to the existing gate decision hash.

The commitment is independent of the definition. Reclassifying a field changes
future disclosure while historical parameter hashes and receipts remain
byte-for-byte verifiable.

## Three tiers

| Tier | What crosses the workload boundary |
|---|---|
| `policy` | The declared raw field |
| `derived` | Outputs from explicitly named, receiver-installed projectors |
| `payload` | Nothing; the value exists only inside the complete commitment |

Fields absent from the definition are treated as payload. There is no
configurable default that can accidentally widen disclosure. A named projector
missing from the receiving build causes refusal.

Version 1 classifies top-level fields. Nested objects and arrays can be
committed, passed as a declared policy value, or projected as a whole; nested
path classification is outside the current claim.

## Define and minimize an action

```python
from olp_gate import minimize_parameters


definition = {
    "profile": "openline.field_tier_definition/v1",
    "definition_id": "send-email-disclosure",
    "version": "1",
    "action_type": "send_email",
    "fields": [
        {
            "field": "recipient",
            "tier": "derived",
            "type": "string",
            "optional": False,
            "projections": [{
                "attribute": "recipient_domain",
                "projector": "recipient_domain/v1",
                "type": "string",
            }],
        },
        {
            "field": "body_size_bytes",
            "tier": "policy",
            "type": "integer",
            "optional": False,
            "attribute": "body_size_bytes",
        },
        {
            "field": "subject",
            "tier": "payload",
            "type": "string",
            "optional": False,
        },
    ],
}

request = minimize_parameters(
    {
        "recipient": "Jane.Doe@Customer.COM",
        "body_size_bytes": 2048,
        "subject": "patient 778812 discharge summary",
    },
    definition,
)

assert request["attributes"] == {
    "body_size_bytes": 2048,
    "recipient_domain": "customer.com",
}
```

The receiver then calls `admit_minimized_request()` with its own registry. The
client cannot supply the governing definition inside the request. Admission
rebuilds the applied-tier hash, rejects additional request keys or attributes,
and validates values against the generated policy schema.

`generate_definition_artifacts()` produces the normalized tier view, policy
schema, and strict wire schema from the same source declaration.

## Public receipt

`issue_field_tier_receipt()` signs:

- the complete parameter hash and canonical byte count;
- the receiver's normalized definition and its hash;
- the applied-tier and minimized-attribute hashes;
- the decision, policy identity, and existing Receipt Gate decision hash; and
- explicit statements that raw parameters and minimized attributes were not
  retained.

The public receipt contains neither raw parameters nor the minimized attribute
values. `verify_field_tier_receipt()` checks its signature and structure. When
an auditor supplies candidate parameters, the verifier recomputes the complete
commitment and minimized-attribute hash and reports an exact match or mismatch.

The standalone Node verifier checks public integrity without importing the
Python package:

```bash
node verify-field-tier-node.mjs receipt.json \
  --gate-key "$TRUSTED_GATE_PUBLIC_KEY"
```

Candidate-preimage checking remains in the Python verifier because it requires
the exact versioned projector implementations named by the receipt.

The receipt has `EVIDENCE_ONLY` standing. A destination must still verify the
companion Receipt Gate/Verified Commit authorization before any effect.

## Boundaries

- A hash commits to a value; it does not hide a small or guessable value from a
  dictionary attack.
- The receipt discloses the canonical byte count of the complete parameter
  object. That is useful for exact audit checks and leaks approximate size.
- A remote workload can lie about the hidden parameters or projection unless
  an auditor later obtains the candidate parameters. Proving correct projection
  without disclosure requires an attested workload or a zero-knowledge proof.
- Receiver-installed custom projectors are declassifiers. Each needs a
  hand-written leakage corpus that searches the entire serialized output, not
  only the expected attribute.
- The embedded definition reveals field names and which fields the receiver
  considers sensitive. It reveals no field values.
- This controls the OpenLine mediation and ledger boundaries. It cannot stop a
  compromised workload from disclosing data through some other route.

## Provenance

The placement of the pre-minimization commitment and the three-tier vocabulary
are pressure-tested against Oswal and Cadeddu, *Separating Disclosure from
Authorization: Field-Tier Minimization for Agent Action Mediation*, arXiv
2608.25474v1 (August 2026).

The paper states that its reference implementation was still in preparation at
publication. This module is therefore an independent OpenLine implementation
of the disclosed mechanism, not a cold reproduction of the authors' code.
