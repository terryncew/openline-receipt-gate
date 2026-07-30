# Claim Boundary

## Supported claims

Receipt Gate v0.6.0rc5 demonstrates that signed action receipts and a pinned Assay
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

The v0.5.0rc6 warning-time benchmark additionally demonstrates, inside one
seeded synthetic three-agent fixture, that:

- the metric proxy receives observable trace state rather than a case or
  corruption label;
- a label-swap probe follows the observable mutation rather than the displayed
  case name;
- 40 clean calibration runs determine the frozen thresholds;
- the same 20 held-out seeds are paired across control, dropped-counterevidence,
  and contradiction conditions;
- 20 held-out clean controls produce zero warnings and end in `COMMIT`;
- 20 dropped-counterevidence runs produce no misses, +5 reference metric
  warning, +3 Receipt Gate lead, and final `QUARANTINE` decisions;
- 20 unflagged-contradiction runs produce no misses, +5 reference metric
  warning, +3 Receipt Gate lead, and final `DENY` decisions; and
- enforcement replay stops all 40 corrupted runs before the declared bad-action
  step.

The frozen profile points to a separate private file-library custody surface
created before held-out evaluation. The offline verifier pins the exact witness
key and anchor payload rather than accepting a signer selected by the anchor.
Existence and bytes of the referenced Library object remain an external evidence
check. This establishes bounded custody order, not public timestamping,
independent publication, or production trust. The
standalone verifier imports no warning-time benchmark modules and independently
recomputes the metrics, thresholds, trajectories, signed decision logs, and
aggregate results.

Warning time and final disposition remain separate measurements. Successful
separation shows predictive usefulness for the named failures on this exact
synthetic representation and agent stack. It does not prove that κ, Δ_hol, or
VKD describe a true or universal ontology, establish universal thresholds,
provide live COLE scoring, or authorize production actions.

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

The Verified Continuation experiment additionally demonstrates two separate
facts:

- its strict three-lane evaluator rejects unknown fields, mismatched receiver
  controls, discontinuous traces, incomplete terminal tests, and caller-supplied
  derived metrics;
- its bundled synthetic fixture satisfies the direct continuation rule but
  remains `UNDECIDABLE`, because harness conformance is not provider evidence;
- its DSM projection is display-only and leaves κ, Φ*, and VKD
  `UNDECIDABLE` when authoritative DSM snapshot state is absent; and
- its existing Verified Commit boundary permits one exact Git ref
  compare-and-swap while blocking wrong-branch, changed-commit, expired,
  replayed, and simultaneous duplicate attempts before ref mutation.

The exact-branch authorization result does not establish the separate
continuation-quality claim. An outside matched reproduction remains required.

The x402 Transaction Airlock additionally demonstrates, inside one disclosed
synthetic adapter and frozen hostile suite, that:

- the paper's SR1–SR8 rule labels map to explicit receiver controls;
- all 56 frozen cases meet their declared outcome;
- mutated network, asset, recipient, amount, and expired permissions fail before
  the settlement callback;
- stale verification context, changed payment or requirement hashes, used
  nonces, insufficient balance, and non-settleable state fail during the fresh
  receiver preflight;
- sequential replay, concurrent use, and two distinct signed COMMIT receipts
  carrying the same payment nonce produce only one settlement callback against
  the shared atomic ledger; and
- missing or mismatched settlement confirmation never releases the protected
  resource.

The standalone verifier checks the frozen source closure and serialized result
without importing Receipt Gate or benchmark modules. This does not authenticate
live chain observations or reproduce the study against a real facilitator.

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

## OpenLine Handoff Check boundary

The v0.6.0rc5 Handoff Check demonstrates a deterministic local mechanism, not
a live-provider continuation advantage. It can parse disclosed Claude Code,
Codex rollout, and generic JSON/JSONL shapes into bounded observable events;
preserve explicit semantic state without upgrading ordinary prose into a
trusted decision; bind a capsule to the supplied history hash, next action, and
optional Git state; require the receiver to pin that next action again during
inspection; and compare that capsule with a separate replay implementation over
the same supplied history. Restoration rederives its full explicit-state index
from the byte-matched source before returning any event.

`SAFE_TO_CONTINUE` means the capsule matches the explicit decision/evidence
state reconstructed from that supplied history. It does not mean the history is
complete or truthful, the next action is correct, the repository is bug-free,
or a real receiving agent will succeed. Hidden reasoning, omitted tool
activity, provider state outside the export, and unsupported natural-language
inference remain outside the claim.

## Role-Confusion Consequence Gate boundary

The v0.6.0rc5 Role-Confusion Consequence Gate demonstrates a deterministic
post-compromise mechanism over thirteen synthetic fixtures. The receiver sees an
exact action plus signed evidence; prompt text, attack labels, model reasoning,
and detector output are not appraisal inputs. Six authorization-valid hostile
cases leave a harmless protected-effect callback untouched. Three legitimate
controls invoke it once. A matched pair holds the action constant while
changing only whether receiver-pinned evidence supports it, and fresh trusted
negative evidence vetoes simultaneous positive support. A valid trusted receipt
bound to a different exact action also fails closed even when exact-action
positive support is present.

This does not show that a live model adopted a hostile instruction, reproduce a
published role-confusion attack, or cure role perception. The callback proves
the disclosed ordering boundary only; it is not an atomic replay ledger.
Production execution must compose appraisal with Verified Commit.

The model compromise is assumed, not reproduced. This demonstrates that
unsupported evidence can be stopped before consequence even when exact-action
authorization is otherwise valid.

## Unsupported claims

This release does not establish:

- complete observation of real agent behavior;
- truth from signatures or hashes alone;
- production safety or regulatory compliance;
- calibrated COLE drift prediction;
- universal warning-time thresholds or generalization from the synthetic DSM / Receipt Gate timing fixture;
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
- safety, compliance, or correct implementation of any deployed x402
  facilitator, wallet, chain, token, sponsor, or server SDK;
- truth of a receiver-supplied x402 snapshot or confirmation merely because its
  shape and bindings pass;
- atomicity between an off-chain fresh-state read and a later on-chain
  transaction beyond what the selected chain and settlement template enforce;
- protection for payment or resource routes that bypass the Transaction
  Airlock and shared one-use ledger.
- a claim that the bundled Verified Continuation traces came from a commercial
  provider, or that their favorable direct counts establish cross-model
  continuation;
- a claim that a provider-execution boolean authenticates a provider identity;
  outside reproducers must publish the raw traces and environmental hashes;
- permission for DSM or a strong authorization result to upgrade an
  `UNDECIDABLE` or failed continuation result.

## Honest public claim

Most receipts make the past verifiable. Receipt Gate makes verified history usable by the next decision.
