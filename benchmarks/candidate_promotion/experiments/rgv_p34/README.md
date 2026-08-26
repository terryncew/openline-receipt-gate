# RGV-P34 — Reality Gate 34-Candidate Pilot

This experiment reuses the exact cohort constructor from `TRIAL-SELECTOR-EXTERNAL-001`.

That older external selector required at least 40 complete non-Jain-overlap GDPa1 candidates. The usable cohort was only 34, so the selector confirmation stopped as `INCONCLUSIVE_EXTERNAL_COHORT`.

RGV-P34 does not pretend 34 became enough for that old claim. It asks a smaller question: is there any held-out toxic-tail veto signal inside those 34 worth taking seriously?

## Cohort

Membership is inherited, not redesigned:

- exclude exact normalized Jain-name overlaps;
- require complete measurements across the eight frozen external-selector assays:
  `AC-SINS_pH6.0`, `AC-SINS_pH7.4`, `HIC`, `PR_CHO`, `PR_Ova`, `SMAC`, `Tm1`, `Tm2`;
- require the constructor to return exactly 34 rows.

The primary viability truth then uses the already-frozen RGV boundaries:

- HIC <= 3.18
- PR_CHO <= 0.38
- AC-SINS pH 7.4 <= 17.51

## Leakage barrier

Outer leave-one-antibody-out evaluation. Inside every outer training set, model alpha and the one-sided residual confidence quantile are chosen from an inner leave-one-antibody-out replay.

The outer candidate never helps define its own veto.

## Pilot bar

`PILOT_VETO_SIGNAL` requires:

- >=90% clean-candidate retention;
- >=20% of the 34 candidates vetoed;
- one-sided exact hypergeometric enrichment versus random veto at the same rejection count, p <= 0.10;
- enough truth support (>=10 clean, >=5 bad);
- no nonrandom baseline Pareto-dominates RGV while itself meeting the same clean-retention floor.

Otherwise the result is `NO_PILOT_VETO_SIGNAL`, unless the exact cohort/data contract fails, which yields `INCONCLUSIVE_PILOT_COVERAGE`.

A null closes this selector/veto line. No third relabeling.
