# OLP × Pipelock Frozen Head-to-Head

## Result

All five frozen native and OLP expectations were met. The strongest proposed
wedge was falsified in the fair comparison: Pipelock AARP did flag the case-2
claim `downstream_claim_evidence_sufficient` as claimed but unverified.

OLP still added a narrower, concrete mechanism. It read the receiver-required
artifact, checked its hash, binding, and declared predicate, then emitted a
signed next-use disposition. With the artifact present it returned `COMMIT`; with
the same native `allow` receipt and the artifact absent it returned
`QUARANTINE`. AARP described the assurance boundary; OLP enforced a receiver's
evidence policy at the next decision.

| Case | Pipelock receipt / action | AARP | OLP | OLP benchmark outcome |
|---|---|---|---|---|
| case-01-clean-allow | valid / allow | appraised | VERIFIED → COMMIT | correct |
| case-02-allow-missing-evidence | valid / allow | appraised | UNDECIDABLE → QUARANTINE | correct |
| case-03-broken-chain | rejected / — | not_applicable_after_native_rejection | REJECTED → DENY | correct |
| case-04-native-block | valid / block | appraised | REJECTED → DENY | correct |
| case-05-malformed-v1 | rejected / — | not_applicable_after_native_rejection | REJECTED → DENY | correct |

The native outcome counts were 5 correct,
0 incorrect, and
0 undecidable. OLP's were
5 correct, 0 incorrect,
and 0 undecidable. AARP had
2 structurally inapplicable cases.

## What the result supports

The run supports this narrower claim: In these frozen fixtures, AARP exposed the unsupported assurance claim, while OLP additionally read receiver-required evidence and emitted a signed COMMIT or QUARANTINE disposition.

It does not show that OLP replaces Pipelock's inline mediation, that Pipelock's
`allow` was wrong, or that either system establishes real-world truth. The
fixtures are public conformance artifacts plus one OLP-authored downstream
evidence companion. Timing and byte counts are reported per lane without a
combined score.

## Post-publication verification

On 2026-07-16, the Pipelock vendor reran all five native fixtures and the three
applicable AARP companions directly with Pipelock's own verifiers. Their native
validity results, action verdicts, and AARP `claimed_unverified` classification
matched this report. They also confirmed the key interpretation: AARP flagged a
producer claim it could not verify; OLP separately read and evaluated the
receiver-required evidence artifact.

This is vendor boundary-accuracy confirmation rather than neutral independent
reproduction. The review found that the original freeze commit was unavailable
in the public Git history. v0.3.1 adds a byte-identical embedded copy of the
original frozen protocol and records the snapshot's temporal limitation, so a
clean clone can now complete the runner without rewriting the original freeze
identifier or changing any scored result.

## Social excerpt

Pipelock caught the network action. Its AARP profile also caught the overclaim.
OLP added the next step: it checked the receiver's actual evidence and decided
whether the claim could move. Same valid receipt, two evidence states: commit or
quarantine.
