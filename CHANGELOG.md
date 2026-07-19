# Changelog

## 0.5.0rc2

- Fixed clean-runner CI wheel construction by installing the exact declared
  `setuptools` and `wheel` build prerequisites before the no-isolation release
  build. The release summary now names failed checks and includes their output
  tails instead of returning an opaque `passed: false` result.
- Added a read-only GitHub Actions release gate using Python 3.12 and Node 24.
  CI fetches the exact pinned Half-Life commit outside the repository, verifies
  its checkout, runs the complete release checker, and independently verifies
  the generated manifest.
- Added a release-check regression guard so a future archive cannot silently
  omit or weaken the required CI workflow.
- Hardened the source-receipt tamper fixture to alter a significant Base64URL
  character rather than trailing unused bits, guaranteeing signature failure.
- Added Verified Commit inside the existing `proof_to_policy_decision_receipt`;
  no receipt family, disposition, score, repository, marketplace, staking,
  certification, or predictive layer was added.
- Bound exact tool, target, settings hash, run, Half-Life capsule, evidence set,
  receiver policy, expiry, one-use code hash, action hash, and authorization hash
  into a v0.4 signed decision.
- Added Python and Node semantic recomputation for the authorization while
  retaining v0.2 and v0.3 decision verification.
- Added the receiver-side `VerifiedCommitLedger`, which atomically verifies and
  consumes permission before invoking a destination callback and records
  authorized, blocked, completed, and failed attempts.
- Added hostile controls for changed tool, target, settings, run, capsule,
  evidence, policy, wrong code, expiry, replay, receipt tampering, callback
  failure, and two simultaneous uses.
- Added a Model A → Model B → one approved write proof and an independent output
  verifier. The fixture remains offline and does not attest live provider calls.
- Kept the public claim to receiver-side one-use authorization within one shared
  atomic ledger. Global exactly-once execution and checker bypass remain outside
  the release boundary.

## 0.5.0rc1

- Added Verified Model Swap as a Receipt Gate profile rather than a new
  repository, score, disposition, or receipt family.
- Added an independently graded three-lane trial: full-history oracle, disclosed
  ordinary summary, and verified Half-Life causal capsule.
- Pinned OpenLine Half-Life at commit
  `70121b53e86196d69b2c3457174b38ad32667b43` as an optional integration.
- Recomputed the raw-history receiver decision table outside the compactor and
  required exact `COMMIT` / `QUARANTINE` / `DENY` equivalence.
- Added policy-pinned cold-archive authentication and rehydration, with explicit
  reporting of what the summary lost and what had to return.
- Bound the proof card to an Agent Receipt v0.5 source commitment, a distinct
  orthogonal outcome witness, and the existing signed proof-to-policy decision.
- Added a bounded DSM projection marked display-only; DSM is never a grading
  authority.
- Added hostile tests for capsule loss, proof-card/source/outcome/projection
  mutation, untrusted Half-Life policy pins, and source/grader/gate key collapse.
- Restored the two byte-exact, hash-matching frozen Assay decision logs that the
  v0.4 verifier referenced but the repository omitted; both signed runs now
  survive clean extraction.
- Kept the public claim limited to the deterministic fixture until a real
  provider adapter supplies separately verifiable execution evidence.

## 0.4.0

- Added an Assay Evidence Contract v1 bundle adapter pinned to the official
  Assay v3.32.0 CLI and release archive.
- Delegated bundle integrity, manifest interpretation, Trust Basis compilation,
  and exact-level claim assertions to Assay rather than reimplementing its
  canonicalization or bundle rules.
- Added fail-closed path confinement, archive-size limits, receiver SHA-256
  binding, exact CLI-version checks, and a trusted-caller-only Assay executable
  boundary.
- Added `source_bundle` input and `--assay-bin`/`OLP_ASSAY_BIN` configuration
  while keeping source receipts and source bundles mutually exclusive.
- Added seven Assay adapter tests: two dependency-independent boundary controls
  and five live official-binary integration tests that skip explicitly when the
  optional executable is absent.
- Added a hash-frozen five-case Assay head-to-head with separate native, Trust
  Basis, and OLP lanes; all three lanes met 5/5 frozen expectations.
- Demonstrated that a failed native Assay Trust Basis requirement remains a
  failed OLP source signal and can never be laundered by receiver evidence.
- Demonstrated signed `COMMIT` versus `QUARANTINE` from the same Assay-valid
  bundle depending on a separately required receiver artifact.
- Added a DSSE capability control that independently verifies Assay signing a
  caller-supplied receiver-style predicate. This falsifies the broad claim that
  arbitrary next-use signing is unique to OLP.
- Narrowed the supported comparison claim to OLP's standardized post-ingest
  receiver-policy decision contract, without claiming Assay cannot implement
  equivalent semantics or that OLP inherits Assay's enforcement boundary.
- Recorded the first partially started run and the single import-bootstrap fix
  in `AMENDMENT-001.json`; fixtures, expectations, commands, scoring, source
  pins, and protocol bytes remained unchanged.
- Added offline verification of the protocol freeze, fixture hashes, Assay
  attestation, five OLP decisions, and the explicitly falsified hypothesis.

## 0.3.1

- Fixed the clean-clone benchmark blocker reported by the Pipelock vendor: the runner now verifies an embedded byte-identical copy of the original frozen protocol when the unpublished intermediate Git commit is unavailable.
- Preserved the original freeze commit and hash instead of relabeling a later release commit as the preregistration point.
- Corrected the protocol wording to match the implemented comparison: boolean-validity disagreement is undecidable, while differing diagnostic strings between two rejecting verifiers are recorded but not scored.
- Resolved caller-supplied relative benchmark output paths against the repository root so a completed external run can serialize its decision-log path portably.
- Added a post-run amendment recording that fixtures, source pins, expectations, scoring, results, and the claim boundary remain unchanged.
- Classified the Pipelock vendor's successful direct rerun as boundary-accuracy confirmation rather than neutral independent reproduction.
- Added regression tests for clean-clone freeze fallback and corrupted-snapshot rejection.

## 0.3.0

- Added a Pipelock ActionReceipt v1 adapter that delegates cryptographic and chain verification to the official pinned `pipelock-verify` 0.2.x source release.
- Added `requirements-pipelock.txt` for the exact audited source dependency while PyPI remains on incompatible v0.1.1.
- Made the nine Pipelock integration tests skip cleanly when the optional verifier is absent, while retaining a fail-closed live test path for the pinned dependency.
- Added release-report test accounting for discovered, executed, and skipped tests in both dependency-present and dependency-absent modes.
- Split package verification into a recorded source-wheel build and an offline clean-wheel install, removing build-backend and network assumptions from the clean-install claim.
- Replaced the 652-character launch draft with a 411-character version that reflects the falsified AARP hypothesis.
- Added an explicit `source_signal` assessment so a Pipelock `allow` remains advisory and a verified `block` can never be laundered into `COMMIT`.
- Added external trust-key pinning and a distinct self-consistent-but-unpinned provenance result for Pipelock.
- Added explicit phase-1 rejection of EvidenceReceipt v2 as unsupported, rather than misclassifying it as a bad signature.
- Added a hash-frozen five-case head-to-head using pinned public Pipelock fixtures, Pipelock's native verifier, its in-repo reference verifier, and its AARP appraisal logic.
- Published the falsifying result: AARP caught the unsupported assurance claim; OLP's narrower demonstrated addition was receiver-artifact evaluation and a signed next-use disposition.
- Added independent Python and Node verification of v0.3 decision receipts while retaining v0.2 verification compatibility.

## 0.2.0

- Added proof-to-policy evaluation with separate integrity, profile, provenance, independence, coverage, freshness, evidence, and outcome assessments.
- Added strict OLP Wire Canon 0.1 verification.
- Added Agent Receipts v0.1–v0.5 verification for its current integer-only protocol fields.
- Added external trust-store roles and independence metadata.
- Added source-bound artifact verification and deterministic JSON evidence predicates.
- Added independently signed outcome receipts.
- Added one-time challenge, replay, run, session, sequence, parent, expiry, and source-hash binding.
- Added `VERIFIED`, `REJECTED`, and `UNDECIDABLE` verdicts.
- Added `DENY` and `ROLLBACK_REQUEST` enforcement decisions.
- Added signed decision receipts with policy snapshots and semantic recomputation.
- Added an independent Node verifier.
- Preserved the v0.1.1 context-manager and local hash-chain API without upgrading its trust claims.
