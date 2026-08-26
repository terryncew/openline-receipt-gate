# RGV-PILOT — Reality Gate, Source-Derived GDPa1 Pilot

This page is the canonical pre-run description. CI produces `rgv-pilot-report.md`, the single post-run page containing the source receipt, cohort derivation, observed N, clean/bad composition, all arms, frozen bars, verdict, interpretation, prior-work ledger, claim boundary, and stop rule.

## Why this replaces the P34 framing

`RGV-P34` hard-coded a remembered sample count before reproducing that count from the pinned Ginkgo bytes. That was a bookkeeping error. Its coverage failure was not a biological result.

`RGV-PILOT` removes remembered N from the experiment entirely.

## Cohort rule

From pinned GDPa1, include every unique antibody with:

- an `antibody_id`;
- non-empty VH and VL sequences;
- a valid source cluster/isotype fold;
- finite HIC, PR_CHO, and AC-SINS pH 7.4 measurements.

No Jain-overlap exclusion is used because this is a within-Ginkgo toxic-tail prediction question, not the old Jain-vs-Ginkgo transport comparison.

The source decides N.

## Truth

A candidate is experimentally clean only if all three hold:

- HIC <= 3.18
- PR_CHO <= 0.38
- AC-SINS pH 7.4 <= 17.51

There is no `PASS` output. The model can only emit `VETO` or `UNKNOWN`.

## Leakage barrier

The source-provided `hierarchical_cluster_IgG_isotype_stratified_fold` is the outer holdout. Ridge alpha and the residual-confidence quantile are selected using only the remaining source folds.

## Arms

1. matched-random veto;
2. simple sequence descriptors;
3. Ginkgo TAP features + linear prediction;
4. RGV sequence k-mers + confidence veto.

## Frozen pilot bar

Signal requires all of:

- >=90% clean retention;
- >=20% experiments avoided;
- one-sided matched-random enrichment p <=0.10;
- >=10 clean and >=5 bad candidates;
- no nonrandom baseline meeting the retention floor Pareto-dominates RGV.

A null closes the learned selector/veto line. RGV-001 stays frozen as the independent GDPa3 test if that truth becomes accessible.

This is exploratory internal evidence only. It does not predict clinical success and cannot validate a generative antibody design system.
