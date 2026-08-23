# CPG-001 — Candidate Promotion Gate

## Question
Does receiver-owned hard-veto promotion reduce masked, predeclared **developability** liabilities without destroying candidate yield or held-out developability quality, compared with a frozen composite ranker over the same measured candidates?

## Boundary
This is a promotion-authority experiment, not a clinical-success predictor and not evidence that any individual Jain assay is clinically dispositive. “Liability” means a condition declared by the frozen receiver policy.

**Affinity/potency is out of scope for CPG-001.** Jain 2017 does not contain a cross-candidate comparable affinity variable. Clinical-stage inclusion is context, not an affinity measurement. The original “great affinity buys out bad developability” example motivated the architecture; this historical replay tests compensation only among measured developability properties.

## Arms
For each leave-one-group-out fold, both arms use the same candidate cohort and the same frozen score.

1. **Control:** rank every complete-case candidate by the equal-weight direction-aligned z-score composite over the gated assays; take top K.
2. **Treatment:** apply every gated hard veto first. Only eligible candidates may advance. Rank those survivors by the **identical composite score**; take up to K.
3. **Authority parity control:** a conventional constrained ranker with the same vetoes and score must select exactly the same clean historical rows as treatment. Expected parity means OpenLine is not claiming a superior antibody scoring algorithm.

The ranker does not see or modify the promotion policy after outcomes are available.

## Frozen composite baseline
For gated assay `j`:

`z_ij = d_j * (x_ij - mean_j) / sample_sd_j`

where `d_j = +1` when larger values are favorable and `d_j = -1` when smaller values are favorable. The candidate score is the equal-weight arithmetic mean across gated assays. Means and sample SDs are computed on the complete-case assay matrix **before publication-era approval/phase labels are read**. Ties break by `candidate_id` ascending. If an assay has zero sample variance, it contributes `z=0` to ranking while its hard veto remains active.

No weights, normalization rule, imputation rule, or tie breaker may change after source binding.

## Cohort
The confirmatory cohort is complete-case across all 10 Jain Table-1 thresholded assays. `Fab_Tm` and `transient_HEK_titer` remain outside the original flag analysis and outside confirmatory ranking/gating. Missing values are never imputed. Coverage attrition is reported; if fewer than 70% of the published 137 candidates remain, a positive result is downgraded to `INCONCLUSIVE_COVERAGE`.

Historical missingness is not used to prove Receipt Gate UNKNOWN behavior. UNKNOWN/stale/revoked/identity handling remains the job of the adversarial native-receipt suite.

## Gate semantics
- threshold failure: `DENY`
- missing / `UNKNOWN` / stale required native evidence: `QUARANTINE`
- identity, target, units, method, revocation, duplicate-receipt, or evidence-integrity failure: `DENY`
- complete current passing evidence: `COMMIT`

A passing dimension can never compensate for a failing veto dimension.

## Identity binding
Native assay receipts bind `candidate_id + sequence_sha256 + construct_id + batch_id`, plus target, assay type, measurement, units, method/version, verifier, timestamp, and raw evidence SHA-256.

The Jain replay is dataset-bound historical evidence. It may bind exact supplement files, candidate rows, published sequences, and measurements, but it may not invent native wet-lab batch/run receipts that were never published.

## Confirmatory Jain design
Jain Table 1 supplies four frozen property groups. Run four folds; one entire group is excluded from **both** ranking and Gate eligibility and used only for orthogonal evaluation.

Report 10%, 25%, and 50% selection budgets. **25% is the preregistered primary budget.** The other budgets cannot rescue a failed primary result.

At the 25% budget, `SUPPORTED_WITHIN_SCOPE` requires all of the following:

- **Compensation signal:** treatment gated-property-group liability rate is at least 10 percentage points lower than control in at least 3/4 folds. Treatment's zero gated failures is an implementation invariant, not by itself evidence of value.
- **Yield:** treatment fills at least 80% of K in at least 3/4 folds and at least 80% pooled across folds.
- **Held-out quality:** treatment held-out property-group flag rate is no more than 5 percentage points worse than control in at least 3/4 folds, and pooled treatment held-out flag rate is no worse than pooled control.
- **Coverage:** complete-case coverage is at least 70% of the 137 published candidates.

If liabilities fall but yield or held-out quality fails, verdict = `FRICTION_ONLY`. If the frozen composite baseline fails to expose the required compensation signal, verdict = `NO_COMPENSATION_SIGNAL` rather than moving the goalposts.

## Correlation audit
Jain's assay axes need not be statistically independent. Before status labels are read, publish pairwise Spearman correlations across the 10 thresholded assays and list every pair with `|rho| >= 0.70`. This audit is descriptive only and cannot change thresholds, weights, folds, or success criteria.

Headline liability measures are candidate-level **property-group** flags rather than counts of individual assay failures, so correlated assays are not treated as separate wins. Statistical independence of measurements is distinct from independence of evidence authority/provenance.

## Outcome labels
Freeze publication-era status/approval labels from the exact bound `sd01` artifact. Do not update candidates using later approvals or failures. Because Jain's Table-1 thresholds were derived from the 48 approved antibodies, approval enrichment is secondary/descriptive and cannot determine the primary verdict.

## Source binding and execution order
1. Bind exact `pnas.1616408114.sd01.xlsx`, `sd02.xlsx`, and `sd03.xlsx` with SHA-256.
2. Normalize the assay matrix without reading status labels.
3. Seal the complete-case cohort and correlation audit.
4. Seal normalized assay artifact + design-lock hashes.
5. Load frozen publication-era status labels.
6. Run four folds at 10/25/50% with no tuning.
7. Emit the result and falsifier/verdict receipt.

GDPa1 remains untouched until this replay is finished.
