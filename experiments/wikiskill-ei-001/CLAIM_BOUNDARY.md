# WikiSkill-EI-001 Claim Boundary

WikiSkill-EI-001 is a `PAPER_SPEC_RECONSTRUCTION`, not a cold integration. The
pinned external source is WikiSkill v1 (`arXiv:2608.27454v1`, submitted
2026-08-27). No author implementation is imported or reconstructed beyond the
published artifact contract needed for this representation test.

The experiment asks one post-hoc question the paper does not claim to solve:
after raw experience has already been consolidated into persistent wiki
knowledge and skills, can a later correction, revocation, or supersession of
one raw trace be propagated selectively using only WikiSkill's published
persisted representation?

Published WikiSkill receives `OUT_OF_SCOPE_POST_HOC_EXPERIENCE_INVALIDATION`.
That arm is recorded and never scored as a failure.

The minimal extension may read the published Raw, Wiki, and Skills artifacts,
receive one standing update naming an existing raw trace, and follow explicit
references already serialized in those artifacts. It may not re-run an LLM,
semantically re-derive historical wiki edits, add a persistent trace-to-pattern
edge, reverse index, dependency graph, hidden derivation table, or per-pattern
support record. Otherwise the extension would quietly import the mechanism
under test.

The main fixture contains two sealed provenance worlds with byte-identical
published artifacts and the same invalidated trace. Their hidden derivation
relations are opposite, so the representation-blind oracle requires opposite
selective reopen outcomes. This is an indistinguishability test: a deterministic
paper-artifact-only method cannot use information that the persisted
representation does not contain.

A positive provenance control adds only explicit `source_trace_ids` to pattern
records. If the same minimal resolver then matches the oracle, the failure is
localized to missing source lineage rather than to the standing evaluator.

If the minimal extension matches both sealed worlds without forbidden state,
the earned verdict is `WIKISKILL_EXTENSION_PARITY`. If it cannot resolve the
worlds while the explicit-support arm does, broad recall over-reopens, and the
positive provenance control succeeds, the earned verdict is
`WIKISKILL_POST_HOC_PROVENANCE_GAP`.

That gap claim is deliberately narrow. It means the published required artifact
shape does not guarantee enough deterministic source lineage for selective
post-hoc invalidation. It does not claim WikiSkill is unsafe, incorrect, or
incapable of being extended; it does not score its reported benchmark results;
and it does not establish that OpenLine is the only possible provenance design.

Historical Raw, Wiki, and Skills bytes are immutable evidence in every scored
arm. Reopen changes current standing only.

`policy_authority: NONE`
