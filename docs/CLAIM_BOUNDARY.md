# Claim Boundary

## Supported claims

Receipt Gate v0.3 demonstrates that signed action receipts can be converted into deterministic, signed policy decisions while keeping integrity, provenance, coverage, the source action signal, freshness, evidence, and outcome checks separate.

Inside the bundled fixtures:

- a valid signature with missing evidence becomes `UNDECIDABLE`;
- altered evidence, replay, and cross-run binding failures are rejected;
- a policy-supported action with bound evidence and a trusted orthogonal outcome commits;
- an unsupported score receives no badge;
- a harmful witnessed mutation requests rollback only when rollback support is declared.

The decision is independently recomputed from the signed assessment set and policy snapshot.

## Frozen Pipelock result

The five-case preregistered run at the pinned source commits found:

- all five Pipelock-native expectations and all five OLP expectations were met;
- the two official Pipelock verification paths agreed on validity for all five fixtures;
- Pipelock AARP correctly placed the authored downstream evidence-sufficiency claim in `claimed_unverified`;
- OLP read one 138-byte receiver-required artifact in the supported case and emitted a signed `COMMIT`; with that artifact absent it emitted `UNDECIDABLE` → `QUARANTINE`;
- a valid receipt carrying Pipelock's native `block` signal became `REJECTED` → `DENY`, never `COMMIT`.

This falsifies the strong preregistered claim that Pipelock's appraisal layer
would miss the unsupported assurance claim. The narrower supported claim is:

> In these frozen fixtures, AARP exposed the unsupported assurance claim, while
> OLP additionally read receiver-required evidence and emitted a signed
> `COMMIT` or `QUARANTINE` disposition.

The AARP companions were authored by OLP against Pipelock's public conformance
profile. They are not deployment captures and do not measure AARP coverage in a
real Pipelock installation.

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
- superiority over Pipelock, or replacement of Pipelock's inline enforcement boundary;
- production generalization from five public conformance fixtures;
- EvidenceReceipt v2 interoperability in the phase-1 Pipelock adapter.
- a live Pipelock benchmark rerun from `scripts/verify_pipelock_benchmark.py`; that script verifies the sealed artifacts, while `run_head_to_head.py` performs the source-pinned live run;
- compatibility with the currently published `pipelock-verify` v0.1.1 canonical field set. The integration is pinned to v0.2.0 source until PipeLab publishes it.

## Honest public claim

Most receipts make the past verifiable. Receipt Gate makes verified history usable by the next decision.
