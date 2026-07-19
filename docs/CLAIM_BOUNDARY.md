# Claim Boundary

## Supported claims

Receipt Gate v0.5.0rc2 demonstrates that signed action receipts and a pinned Assay
evidence bundle can be converted into deterministic, signed policy decisions
while keeping integrity, provenance, coverage, the source action signal,
freshness, evidence, and outcome checks separate.

Inside the bundled fixtures:

- a valid signature with missing evidence becomes `UNDECIDABLE`;
- altered evidence, replay, and cross-run binding failures are rejected;
- a policy-supported action with bound evidence and a trusted orthogonal outcome commits;
- an unsupported score receives no badge;
- a harmful witnessed mutation requests rollback only when rollback support is declared.

The decision is independently recomputed from the signed assessment set and policy snapshot.

The Verified Model Swap review candidate additionally demonstrates, inside the
disclosed deterministic Half-Life fixture, that:

- raw verified history and the verified causal capsule produce the same exact
  16-entry receiver decision table;
- the disclosed ordinary summary baseline omits seven negative-history
  tombstones while preserving the active commitments;
- all seven omitted decisions can be restored from a policy-pinned,
  hash-addressed archive; and
- Receipt Gate emits its existing signed `COMMIT` only after the independent
  replay, capsule comparison, archive recovery, source binding, orthogonal
  outcome, and receiver evidence predicates pass.

The candidate adapters, Half-Life compactor, and DSM display are not grading
authorities.

Verified Commit additionally demonstrates, inside the disclosed receiver-side
boundary, that:

- the existing signed `COMMIT` can bind one exact tool, target, settings hash,
  run, capsule, evidence set, policy, expiry, and one-use code hash;
- changed fields, a wrong code, expiry, and replay are blocked before the tool
  callback starts;
- two simultaneous uses of one authorization produce one authorized callback
  and one blocked attempt against the shared atomic ledger; and
- an ordinary `COMMIT` without the optional authorization grants no tool
  permission.

This is receiver-side exactly-once authorization, not globally exactly-once
execution. A crash after consumption fails closed and requires new permission.

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

The Pipelock vendor directly reproduced all five native classifications and all
three applicable AARP classifications with Pipelock's own verifiers. This is a
vendor boundary-accuracy confirmation, not the neutral third-party reproduction
requested in the public issue. Their review also produced the v0.3.1
clean-clone reproducibility correction.

## Frozen Assay result

The five-case preregistered run against the official Assay v3.32.0 Linux binary
and archive found:

- all five Assay-native bundle expectations, all five Assay Trust Basis
  expectations, and all five OLP expectations were met;
- Assay rejected a changed bundle and correctly failed an exact-level assertion
  requiring `signing_evidence_present=verified` when its compiled level was
  `absent`;
- OLP propagated that failed Assay claim to `REJECTED` → `DENY` and did not
  launder it with receiver evidence;
- with the same byte-identical, Assay-valid bundle, OLP emitted a signed
  `COMMIT` when the receiver-required artifact was present and signed
  `QUARANTINE` when it was missing; and
- Assay's official `evidence attest` command signed the frozen caller-supplied
  receiver-style predicate, and the benchmark independently verified the DSSE
  Ed25519 signature and predicate bytes.

The last control falsifies the broad proposed claim that OLP uniquely signs what
a receiving system may do next. The narrower supported claim is:

> In this frozen run, OLP preserved an Assay bundle, delegated Assay-native
> claims to Assay, applied a separate receiver policy, and signed a standardized
> next-use disposition.

Case 2 is not an Assay failure. Assay passed the two registered claims it was
asked to assert; the missing artifact belonged to OLP's separate receiver-owned
policy. Case 5 demonstrates an explicit OLP receiver byte pin, not unique
cryptography—an Assay receiver can add an external byte pin as well.

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
- independent proof of when the original protocol snapshot was created. The embedded snapshot proves exact bytes against the pre-existing freeze hash; the original intermediate Git commit was not published with v0.3.0.
- superiority over Assay, or replacement of Assay's inline MCP policy and
  kernel-enforcement boundary;
- that Assay cannot sign receiver-style decisions or arbitrary predicates;
- that Assay was wrong to pass the registered claims in the missing receiver
  artifact case;
- semantic verification by Assay of the OLP-authored arbitrary DSSE predicate;
- production generalization from the five-case Assay fixture set;
- a claim that the Assay-originated OpenFeature bundle was captured from a live
  deployment. The receiver policy, artifact, requests, and predicate are
  OLP-authored benchmark inputs.
- proof that the caller-declared source or target model identifiers correspond
  to a live commercial-provider execution;
- universal model portability, legal ownership of an agent identity, or
  preservation of private latent state;
- a claim that every ordinary summary loses the seven decisions observed in the
  disclosed baseline;
- semantic truth from exact decision equivalence; equivalence is limited to the
  disclosed receiver projection and policy pins;
- permission for DSM, a candidate model, or the compactor to certify its own
  output.
- controller independence merely because source, grader, and gate signatures
  use three different keys; custody and trust roles remain receiver
  configuration.
- enforcement of a destination tool that bypasses the Verified Commit checker;
- cross-host or cross-ledger replay protection without a shared atomic backend;
- globally exactly-once side effects, transactional rollback, or automatic
  retry after a callback or process failure;
- secrecy of a low-entropy caller-chosen one-use code. The reference generator
  produces 256 random bits, and production custody belongs to the receiver.

## Honest public claim

Most receipts make the past verifiable. Receipt Gate makes verified history usable by the next decision.
