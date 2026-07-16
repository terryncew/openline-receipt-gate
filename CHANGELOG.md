# Changelog

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
