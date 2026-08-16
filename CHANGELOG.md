# Changelog

## 0.6.0rc6

- Adds a behavioral comparison against the official x402 repository pinned at
  commit `167a828e8319aa7b403f4f4312489e9cffadff10` and source SHA-256
  `49354704d6a59e2d075fa21e258693632b26074097784edef76d3f9b8b4fd36c`.
- Reproduces the official asynchronous Python MCP wrapper executing a durable
  tool effect before settlement and then returning an error when settlement
  fails. This is a real upstream code path, not a simulated native baseline.
- Runs a matched Receipt Gate failure in which settlement is attempted but the
  protected release callback remains untouched, plus legitimate native and
  airlock controls that each execute exactly once.
- Adds a standard-library independent verifier that rechecks the pinned Git
  commit, source bytes, AST call order, observations, and durable effect files
  without importing Receipt Gate code.
- Keeps the claim narrow: the finding covers the pinned Python MCP wrapper and
  disclosed local effect, not every x402 implementation, a live-chain exploit,
  or production safety.

## 0.6.0rc5

- Fails closed when a trusted, valid evidence bundle mixes exact-action support
  with a second trusted receipt bound to a different action. The candidate gate
  and independent verifier now agree on this previously uncovered input.
- Adds the mixed-action-binding condition to the frozen consequence suite,
  raising it to 13 cases and proving the protected-effect callback remains
  untouched for that bundle.
- Keeps unrelated *untrusted* evidence non-blocking, preserving the existing
  false-positive control.
- Adds installed-wheel coverage for the role-confusion command and exposes the
  additive command in top-level CLI help.

## 0.6.0rc4

- Consolidates the self-contained Half-Life release gate from rc3 with the
  Role-Confusion Consequence Gate; the feature no longer ships on a sibling
  branch whose own complete gate is red.
- Adds a frozen twelve-case post-compromise suite. The gate receives no prompt,
  attack label, model reasoning, or detector score; it appraises exact-action
  structure and receiver-pinned evidence provenance, freshness, and binding.
- Exercises a real harmless callback in every frozen case. Five
  authorization-valid hostile cases and all other blocked cases invoke it zero
  times; the three committed controls invoke it exactly once.
- Adds a matched exact-action pair, unrelated-untrusted-content control, and a
  fresh trusted positive/negative conflict that must fail closed.
- Rejects duplicate evidence IDs, unsigned nested signature extensions,
  duplicate JSON keys, unsafe canonical integers, malformed matrix shapes, and
  missing named controls without leaking raw validation exceptions.
- Extends the independent verifier to validate frozen source closure and
  recompute conflict handling, decisions, and effect expectations without
  importing the candidate consequence-gate module.
- Keeps the boundary explicit: this is a synthetic consequence test, not a live
  role-confusion reproduction; production effects must compose appraisal with
  Verified Commit's atomic ledger.

## 0.6.0rc3

- Makes the root-ready archive genuinely self-contained for its complete
  deterministic release gate by bundling the exact Half-Life v0.2.0rc5
  pure-Python wheel, frozen fixture, public policies, and upstream MIT license.
- Adds a stdlib-only verifier that pins the wheel, fixture tree, policy tree,
  license, source version, and source commit. Tampered wheel, fixture, policy,
  or metadata inputs fail closed.
- Uses the verified bundle only when no explicit `OLP_HALF_LIFE_ROOT` is
  supplied. An invalid explicit dependency remains a release failure and
  cannot silently trigger the fallback.
- Extends CI to fetch the pinned Half-Life commit independently and compare its
  package sources, fixture, policies, and license byte-for-byte with the
  vendored bundle. Local hashes are not represented as independent provenance.
- Adds five regression tests for offline activation, tamper rejection,
  self-reference rejection, and explicit-root fail-closed behavior.

## 0.6.0rc2

- Separates capsule extraction from receiver reference replay. The capsule
  builder now uses a reverse traversal in `core.py`; the receiver replay uses
  its own forward traversal and validator in `reference_replay.py`. A forced
  extractor omission therefore produces `EVIDENCE_MISSING` instead of
  certifying itself.
- Requires the receiver to pin the intended next action during
  `handoff-inspect`. Omitting the pin through the Python API or supplying a
  different action returns `UNDECIDABLE`.
- Compares the complete semantic boundary—not only statement and evidence
  IDs—including status, action scope, provenance event IDs, item identity,
  support status, and missing/incompatible evidence.
- Replaces one-token action overlap with a fail-closed scoped match and rejects
  evidence whose declared action scope is incompatible with the receiver's
  intended action.
- Binds optional Git state to tracked diff bytes and the bytes or link targets
  of untracked files, rather than hashing only the porcelain status shape.
  Repository state is sampled on both sides of capsule construction and
  inspection.
- Rebuilds the restoration index independently from the original byte-matched
  history before restoring anything. The v2 index covers all explicit semantic
  state, including state left outside the bounded capsule, and rejects a
  rewritten item-to-event mapping even if its local hash is recomputed.
- Treats every oversized unparsed JSONL record as undecidable. A record can no
  longer earn an exemption merely by carrying a known image-event marker in
  its prefix. Duplicate canonical event IDs also fail closed.
- Re-hashes history after parsing to detect concurrent source mutation, adds
  structured CLI errors, and rejects ambiguous restore item collections.
- Adds eleven focused Handoff Check regressions plus 435 adversarial capsule
  mutations. The package suite now discovers 158 tests; all 134 available
  tests pass and 24 optional external integrations skip when their pinned
  fixtures are absent.

## 0.6.0rc1

- Adds **OpenLine Handoff Check**, a local continuation tool for Claude Code,
  Codex rollout JSONL, and a generic explicit-state JSON/JSONL format.
- Adds `olp-gate handoff-check`, `handoff-inspect`, and `handoff-restore`.
- Canonicalizes vendor histories without promoting ordinary model prose into
  trusted decisions. Only explicit OLP semantic markers or structured
  `semantic` objects can become decision/evidence state.
- Builds a bounded fresh-agent capsule, then separately replays the full
  canonical history before returning `SAFE_TO_CONTINUE`, `DECISION_CHANGED`,
  `EVIDENCE_MISSING`, or fail-closed `UNDECIDABLE`.
- Binds the capsule to source-history SHA-256, next-action SHA-256, and optional
  Git HEAD/worktree state. A capsule never certifies its own fidelity.
- Emits `capsule.json`, `capsule.md`, `reference_replay.json`,
  `archive_index.json`, `handoff_report.json`, `continuation_receipt.json`, and
  a local shareable `proof-card.html`.
- Adds optional Ed25519 signing for the continuation receipt; unsigned runs are
  explicitly labeled `UNSIGNED_LOCAL_HASH_BOUND`.
- Streams JSONL with a bounded per-record parser and fails closed on malformed
  or unknown oversized records while recognizing known oversized Codex image
  events as non-semantic telemetry.
- Replays bounded operational state from source history as part of capsule
  comparison, so a recomputed self-hash cannot make forged operational context
  earn `SAFE_TO_CONTINUE`.
- Adds 16 Handoff Check tests covering vendor adapters, stale-capsule decision
  changes, missing evidence, parse failures, unsafe control characters, signed
  receipts, restore binding, HTML escaping, CLI output, shape fuzzing, semantic
  reference hardening, and operational-state tamper rejection.

## 0.5.0rc8

- Closes the external-lane validator boundary found by independent type/shape
  fuzzing. Non-string JSON values for `evidence_class`, trace `kind`, trace
  `status`, and terminal-test `status` now produce bounded
  `VerifiedContinuationError` rejections instead of leaking raw unhashable-type
  exceptions.
- Rejects a missing or non-sequence lane collection with the domain error
  `lane_results_not_sequence` before iteration.
- Adds regression coverage across every non-string JSON type for all four enum
  fields, plus `None`, text, bytes, and bytearray lane collections.
- Leaves the frozen trial, synthetic results, exact-action authorization, and
  claim boundary unchanged: authorization passes; real cross-model
  continuation remains `UNDECIDABLE` until an outside reproduction.

## 0.5.0rc7

- Adds the frozen Verified Continuation three-lane trial inside Receipt Gate:
  producer self-summary, no prior state, and a Half-Life bounded capsule.
- Enforces identical receiver model, repository, task, tools, terminal tests,
  and budget across lanes; unknown fields and discontinuous traces fail closed.
- Computes only direct repeated-exploration, trace-error, terminal-defect, and
  budget counts. The bundled synthetic fixture remains `UNDECIDABLE` by
  construction and cannot be promoted into provider evidence.
- Separates continuation quality from authorization. One claim cannot conceal
  failure or missing evidence in the other.
- Adds a real Git compare-and-swap Verified Commit trial. Wrong-branch,
  changed-commit, expired, replayed, and simultaneous duplicate writes are
  blocked before ref mutation; exactly one bound write executes.
- Emits a display-only DSM trajectory projection. κ, Φ*, and VKD remain
  `UNDECIDABLE` because the fixture lacks authoritative DSM snapshot state.
- Adds a stdlib-only independent verifier and frozen source closure for the
  continuation harness.

## 0.5.0rc6

- Adds the x402 Transaction Airlock as a profile inside the existing Verified
  Commit authorization; no repository, receipt type, disposition, or score was
  added.
- Binds the normalized payment requirements, payment authorization, execution
  template, receiver policy, expiry, and one-use code into the signed
  `COMMIT`.
- Adds a receiver-owned fresh-state preflight immediately before settlement for
  authorization authenticity, nonce, balance, settleability, and exact
  verification-context hashes.
- Atomically reserves a receiver-ledger replay scope over the payment's scheme,
  network, asset, payer, signature model, and nonce, blocking sequential and
  simultaneous reuse across distinct valid COMMIT receipts.
- Requires separate settlement confirmation to match the submitted transaction
  hash, network, asset, amount, recipient, and nonce before resource release,
  followed by a closed positive release acknowledgment for the exact target and
  transaction hash.
- Freezes a 56-case synthetic hostile suite mapped to SR1–SR8 from
  arXiv:2607.19545v1. All required network, asset, recipient, amount, expiry,
  replay, and verification-settlement divergence cases fail at the declared
  boundary.
- Adds a standard-library independent verifier, source-closure hashes,
  byte-exact reproduction test, report-tamper control, and CI/release-gate
  enforcement.
- Keeps the claim bounded to the disclosed adapter and trusted receiver
  providers; no live facilitator, wallet, chain, or SDK is certified.

## 0.5.0rc5

- Corrects the release source closure: the three frozen warning-time decision
  logs were present and hash-correct in the root-ready archive but omitted by
  Git because a repository-wide `decision_receipts.jsonl` ignore rule lacked a
  warning-time exception. The exception is now explicit.
- Adds a checkout-level CI guard that requires all three frozen decision logs
  to be tracked and not ignored before the independent benchmark verifier runs.
- Adds a regression test for the exact ignore-rule failure. The benchmark
  thresholds, signed calibration, held-out episodes, and reported results are
  unchanged.
- Pins the exact warning-time external-anchor witness public key and payload
  hash in both the benchmark verifier and the standalone independent verifier.
  A correctly signed replacement anchor under an attacker-selected key now
  fails closed.
- Adds an adversarial signer-substitution test for the external custody anchor.
- Expands Verified Commit concurrency evidence from two threads to a
  32-process POSIX race and requires exactly one executor invocation.
- Keeps the custody claim bounded: the offline checks validate the pinned
  anchor and declared chronology, while the referenced Library object's
  existence and bytes remain an external evidence check.

## 0.5.0rc4

- Rebuilt the warning-time calibration after an adversarial audit showed the
  prior proxy accepted the ground-truth case label. The metric function now
  accepts only the observable current and previous trace state plus seed and
  step; it cannot receive the case, corruption label, injection step, or
  expected outcome.
- Added a label-swap falsifier. A clean observable trace relabeled as corrupted
  does not warn, while a corrupted observable trace relabeled as control does.
  The same 20 held-out seeds are paired across all three conditions so the seed
  cannot encode the case.
- Calibrated κ, Δ_hol, and VKD proxy thresholds from 40 clean runs only. The
  thresholds and signed profile were frozen before the 60 held-out runs and
  bound to a private external-custody anchor. That anchor proves custody order
  inside the connected file library; it is not a public transparency timestamp
  or production trust authority.
- Replaced the old verifier with an independent implementation that imports no
  warning-time benchmark modules. It parses the metric source signature,
  independently recomputes observable features, all 40 clean traces,
  thresholds, all 60 held-out trajectories, receipt signatures, decisions,
  warning times, and artifact hashes.
- Added profile future-skew and expiry checks, real creation/evaluation
  timestamps, and signed bindings for the calibration evidence, thresholds,
  freeze publication, external custody anchor, metric source, and observable
  fixture.
- Corrected all stale five/six-run claims. The held-out fixture reports 0/20
  clean false alarms, 0/40 missed corruptions, +5 reference metric warning,
  +3 Receipt Gate lead, and separate final counts of 20 COMMIT, 20 QUARANTINE,
  and 20 DENY.
- Preserved the hard claim boundary: this synthetic result shows predictive
  usefulness for two named failures on one disclosed representation and agent
  stack. It does not prove the ontology is true, establish universal
  thresholds, provide production COLE scoring, or authorize downstream action.

## 0.5.0rc3 — rejected calibration candidate

- The original signed calibration candidate is retained only as audit history.
  Its metric proxy accepted the ground-truth case label, so its reported
  warning-time separation was not valid evidence of predictive usefulness.
  Do not release or cite its 0/40 miss or +4-step warning claims.

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
