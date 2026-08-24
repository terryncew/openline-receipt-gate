# CPG-002 — GDPa1 Candidate Promotion Replication

## Why this experiment exists

CPG-001 already tested a receiver-owned hard-veto promotion policy against a frozen equal-weight composite ranker on the 137-antibody Jain 2017 panel. The canonical run returned `NO_COMPENSATION_SIGNAL`: the composite ranker's selected candidates did not expose the predeclared masked-liability pattern required by the frozen success rule.

CPG-002 does not repair, rename, or rerun CPG-001. It asks whether the same candidate-promotion hypothesis appears on a different, larger public antibody measurement substrate: Ginkgo Bioworks' versioned GDPa1 benchmark file.

## Frozen question

Does receiver-owned hard-veto promotion reduce masked, predeclared developability liabilities without destroying candidate yield or orthogonal held-out developability quality, compared with the same frozen composite-ranking family over the same measured candidates?

## Source

The external source is fetched at execution time from:

- repository: `ginkgobioworks/abdev-benchmark`
- commit: `cc6d3b69afc92695445695345399d9c91b0d14a4`
- path: `data/GDPa1_v1.2_20250814.csv`
- git blob: `923c38b1a7b7d2421bd4c6fa7461febc797c446c`
- expected bytes: `862134`

The dataset is not vendored. CI verifies the commit, git blob identity, byte length, required columns, and computes a SHA-256 receipt over the exact bytes used.

No exact antibody count is preregistered. The runner reports observed rows and unique IDs from the pinned bytes and fails closed on duplicate antibody IDs.

## Receiver policy

The policy uses the central values of the Ginkgo 2025 warning thresholds published in Table 2 of DOI `10.1080/19420862.2025.2593055`.

Primary groups:

- thermal stability: `Tm1`, `Tm2`
- hydrophobic/colloidal: `HIC`, `SMAC`
- self-association: `AC-SINS_pH6.0`, `AC-SINS_pH7.4`
- polyreactivity: `PR_CHO`, `PR_Ova`

`HAC` is excluded before full benchmark execution because the published 2025 threshold is supported by only 31 approved antibodies, materially less threshold support than the primary panel. Titer, purity, SEC monomer, and Tonset lack a Table-2 Ginkgo threshold and are also out.

This is a policy-transfer historical replay. The Ginkgo thresholds were themselves estimated from approved antibodies in the broader Ginkgo study, and the public competition CSV is another representation of Ginkgo-generated measurements. CPG-002 therefore does **not** claim an independent prospective threshold validation.

## Arms

For each leave-one-property-group-out fold:

1. **Composite control** — exclude the held-out group from the score, rank every complete-case candidate by the equal-weight direction-aligned z-score, and take top K.
2. **Receiver hard-veto** — exclude the held-out group from both score and eligibility; remove any candidate crossing a warning threshold in any remaining group; rank survivors by the identical composite score; take up to K.
3. **Authority parity control** — a separately evaluated conventional constrained ranker using the same vetoes and score must select exactly the same rows as the treatment.

The held-out group is used only for orthogonal evaluation.

Clinical-stage and approval-status columns are forbidden from the primary analysis.

## Composite

For assay `j`:

`z_ij = d_j * (x_ij - mean_j) / sample_sd_j`

where `d_j = +1` when larger is favorable and `d_j = -1` when smaller is favorable.

The score is the equal-weight arithmetic mean across the fold's gated assays. Means and sample SDs are computed once on the complete-case eight-assay cohort. Zero-variance assays contribute `z=0` to ranking while their veto remains active. Ties break by `antibody_id` ascending.

Missing values are never imputed.

## Budgets

Run 10%, 25%, and 50%. `K = ceil(N * budget)`.

The 25% budget is primary. Other budgets are descriptive and cannot rescue the primary verdict.

## Primary success rule

The numerical bar is intentionally inherited from CPG-001 rather than redesigned after its negative result.

At 25%:

- gated property-group liability rate must fall by at least 10 percentage points in at least 3/4 folds;
- treatment must fill at least 80% of K in at least 3/4 folds and at least 80% pooled;
- treatment held-out flag rate must be no more than 5 points worse in at least 3/4 folds and pooled treatment must be no worse than pooled control;
- complete-case coverage must be at least 70% of observed unique candidates;
- authority parity must hold in all four primary folds.

Verdict priority:

1. `INCONCLUSIVE_COVERAGE`
2. `INVALID_AUTHORITY_PARITY`
3. `NO_COMPENSATION_SIGNAL`
4. `FRICTION_ONLY`
5. `SUPPORTED_REPLICATION_WITHIN_SCOPE`

A negative scientific verdict is a valid result and must not make CI fail. CI fails only on source, mechanics, freeze, or independent-replay failure.

## Falsifier and stop rule

If CPG-002 also returns `NO_COMPENSATION_SIGNAL`, the "hard gate exposes compensation hidden by this composite baseline" research line is stopped for these historical antibody panels. No threshold, score, group, budget, or success criterion may be tuned to rescue it.

If CPG-002 returns `SUPPORTED_REPLICATION_WITHIN_SCOPE`, the earned claim remains narrow: under this exact versioned GDPa1 source and predeclared warning policy, hard-veto promotion reduced masked declared developability liabilities without crossing the frozen yield/held-out-quality bars.

Neither result predicts clinical success.

## Freeze disclosure

The public GDPa1 schema and a small number of source rows were inspected to construct a correct adapter. No full CPG-002 benchmark score was executed before this freeze, and no source value was used to tune thresholds, weights, folds, budgets, or success criteria. The first repository-visible full score is produced by CI.
