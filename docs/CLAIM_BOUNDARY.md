# Claim Boundary

## Supported claims

Receipt Gate v0.2 demonstrates that signed action receipts can be converted into deterministic, signed policy decisions while keeping integrity, provenance, coverage, freshness, evidence, and outcome checks separate.

Inside the bundled fixtures:

- a valid signature with missing evidence becomes `UNDECIDABLE`;
- altered evidence, replay, and cross-run binding failures are rejected;
- a policy-supported action with bound evidence and a trusted orthogonal outcome commits;
- an unsupported score receives no badge;
- a harmful witnessed mutation requests rollback only when rollback support is declared.

The decision is independently recomputed from the signed assessment set and policy snapshot.

## Unsupported claims

This release does not establish:

- complete observation of real agent behavior;
- truth from signatures or hashes alone;
- production safety or regulatory compliance;
- calibrated COLE drift prediction;
- automatic rollback without an external actuator;
- operator independence when the operator controls the gate, key, trust store, and ledger;
- complete RFC 8785 support for Agent Receipt extensions containing floats;
- generic W3C Verifiable Credential interoperability;
- independent recomputation of source and evidence assessments from a decision receipt that intentionally omits raw evidence.

## Honest public claim

Most receipts make the past verifiable. Receipt Gate makes verified history usable by the next decision.
