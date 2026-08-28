# WikiSkill-EI-001 — Experience Invalidation

**Verdict:** `WIKISKILL_POST_HOC_PROVENANCE_GAP`

**Evidence tier:** `PAPER_SPEC_RECONSTRUCTION`

**Policy authority:** `NONE`

WikiSkill separates immutable raw execution traces, persistent wiki knowledge,
and executable skills. The published Skills layer maps each skill back to its
motivating wiki patterns, but the required Wiki Maintainer artifact contract
does not require the reverse source edge from a pattern to the raw traces that
established it.

This experiment asks whether that distinction matters after the fact: if one
already-consolidated raw experience is later corrected, revoked, or superseded,
can a faithful extension identify exactly which persistent knowledge and active
skills should lose current standing without rewriting history?

## Frozen result

The sealed fixture contains two raw traces, two wiki patterns, and two accepted
skills. It then defines two possible provenance worlds. The worlds have
byte-identical published WikiSkill artifacts and receive the same later event:
`trace-A` loses standing. What differs is the historical derivation relation
that WikiSkill's required persisted artifact shape does not serialize.

| Arm | World A | World B | No-op | Scored? |
|---|---|---|---|---:|
| Published WikiSkill | Out of scope | Out of scope | Out of scope | No |
| Broad recall | reopens both chains | reopens both chains | preserves both | Yes |
| Minimal WikiSkill extension | unresolved provenance | unresolved provenance | preserves both | Yes |
| OpenLine selective standing | reopens left only | reopens right only | preserves both | Yes |

The representation-blind oracle requires opposite answers in the two event
worlds. Because the minimal extension receives identical serialized WikiSkill
artifacts and the identical standing update in both worlds, it fails closed as
`UNRESOLVED_PROVENANCE` rather than inventing lineage.

OpenLine's explicit t0 support relation distinguishes the worlds and matches the
oracle in both. Broad recall has enough information to stop everything, but
fails selectivity by reopening the unaffected chain.

Every scored arm leaves the Raw, Wiki, and Skills historical bytes unchanged.
Only current standing changes.

## Mechanism control

A positive control adds exactly one missing kind of information to the same
published fixture: explicit `source_trace_ids` on the pattern records. The
unchanged minimal resolver then matches the World A oracle exactly.

That control matters. The result is not "WikiSkill cannot support invalidation."
It is narrower: its **required published representation does not guarantee the
source lineage needed for deterministic selective post-hoc invalidation**.
A conforming implementation that persists explicit provenance can close the
gap without adopting OpenLine's particular graph representation.

## Evidence boundary

The external source is WikiSkill v1, submitted August 27, 2026
(`arXiv:2608.27454v1`). It explicitly defines the Raw/Wiki/Skills separation,
immutable raw traces, persistent wiki patterns, PURPOSE.md pattern links, and
skill-only rollback while the wiki persists. The published Wiki Maintainer
output contract requires pattern content and evidence analysis but does not
require source trace identifiers.

No author implementation is used here. Published WikiSkill receives
`OUT_OF_SCOPE_POST_HOC_EXPERIENCE_INVALIDATION`; the experiment never grades a
feature the paper did not claim.

## Reproduce

```bash
python experiments/wikiskill-ei-001/scripts/run_experiment.py
python experiments/wikiskill-ei-001/scripts/verify_result.py
python -m unittest discover -s experiments/wikiskill-ei-001/tests -v
python experiments/wikiskill-ei-001/scripts/verify_release.py
```

The independent result verifier imports neither the runner nor any arm. It
checks the pre-outcome design lock, the two-world indistinguishability witness,
the representation-blind oracle, the minimal-extension source boundary, the
no-op controls, historical-byte preservation, and the explicit-provenance
positive control.
