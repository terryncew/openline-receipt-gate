# Preregistration — TERRYNCE-EARLY-WARNING-001

Status: STRUCTURE FROZEN / DATA MAPPING PENDING PREFLIGHT

## Claim under test

A pre-relief **Recoverability Margin (RM)** contains held-out information about subsequent
recovery beyond ordinary state, trend, drought severity/history, and established
pre-relief resilience indicators.

This is not an event-timing claim.

## Experimental unit

One published severe-drought episode in one river basin.

`t0` is the end of the severe-drought episode as represented by the released event table.
The relief episode is the post-`t0` easing of meteorological drought. The recovery response
is measured in terrestrial water storage (TWSA), using the released data and the authors'
published recovery logic wherever it can be reproduced without future leakage.

If the author bundle does not support an unambiguous causal mapping from drought episode
to pre-relief state and post-relief outcome, the experiment stops rather than substituting
a convenient definition.

## Time split

Primary split is fixed by relief date:

- training: 2003-01 through 2015-12
- validation: 2016-01 through 2018-12
- final holdout: 2019-01 through 2022-12

Events after 2022-12 are excluded from the primary 24-month recovery endpoint because
the released record runs through 2024 and would create unequal right-censoring.

If the preflight shows the released time support cannot sustain this split, that is a
design failure requiring a new experiment ID. Do not silently move the dates.

## Primary endpoint

Binary recovery within 24 months after `t0`, reconstructed from released TWSA using the
authors' recovery criterion. Exact code/threshold mapping must be frozen before holdout.

Secondary endpoint: time to recovery among episodes with adequate follow-up.

## Causal feature boundary

For each episode, features must use timestamps <= `t0`.

Candidate causal components, subject only to exact schema mapping:

- normalized TWSA deficit at `t0`
- recent pre-relief TWSA slope / adverse momentum
- drought duration and cumulative/severity burden from SPEI
- pre-relief water-availability state
- causal history of prior drought/recovery episodes
- response-lag and recovery-capacity priors estimated from training episodes only
- lag-1 autocorrelation and variance of the pre-relief TWSA window

Forbidden as RM inputs:

- recovery status
- recovery time
- any TWSA, WA, SPEI or other measurement timestamped after the episode's `t0`
- any statistic normalized with validation/holdout values
- later episodes from the same basin when scoring an earlier episode
- author figure summary fields that already encode the recovery outcome

## Recoverability Margin structure

With all terms placed on training-only standardized scales:

    future_burden
      = state_deficit
      + max(0, adverse_momentum) * response_lag
      + drought_burden

    available_recovery
      = historical_recovery_capacity * max(0, 24 months - response_lag)

    RM = available_recovery - future_burden

History parameters use only information available from earlier/training episodes.
Fallback hierarchy for sparse basin history is frozen:

1. prior same-basin history, only if adequate
2. training-only basin-class history, if the released attributes permit a class
3. global training-only history

The exact minimum-history count and standardization transforms are frozen in the
episode-lock receipt before validation/holdout.

## Baselines

At minimum:

- state-only
- trend-only
- drought severity/duration-only
- best single causal observable, selected training-only
- prior-history/persistence
- critical-slowing indicators: pre-relief lag-1 autocorrelation + variance
- conventional multivariable baseline: ordinary state + trend + severity/history

Every learned baseline gets the same train/validation information budget as RM.

## Scoring

Primary discrimination/calibration:
- Brier score
- AUROC
- AUPRC

Operational warning comparison:
- sensitivity at a validation-frozen false-positive budget
- false-positive rate
- abstention/missing-history rate

Incremental test:
compare the conventional multivariable model against the same model augmented with RM
on the untouched holdout.

## Success / falsifier

The RM claim survives this domain only if:

1. RM has the expected monotonic direction on holdout (larger RM -> more recovery);
2. adding RM improves held-out Brier score over the conventional baseline; and
3. a basin-clustered bootstrap 95% interval for that Brier improvement excludes zero.

If RM fails to add held-out information beyond the conventional baseline, the claim
fails in this domain.

No threshold, feature, normalization, horizon, split, or formula rescue after holdout.

## Secondary robustness

After the primary result is frozen:
- leave-basin-out / basin-clustered analyses
- alternate released TWS products
- alternate published recovery thresholds (90/95/100)
- alternate drought products

These cannot overwrite the primary result.


## Calibration lock amendment — before holdout opening

The following details are frozen before any 2019–2022 recovery labels are constructed:

- first 20 chronological training episodes are history burn-in only
- basin-specific history requires at least 2 prior completed training episodes; otherwise
  the prior pool is global training history
- RM has fixed equal component weights after training-only median-positive scaling
- simple baselines use deterministic L2 logistic regression with lambda 0.1
- the best single observable is selected by five-block chronological training CV
- conventional and conventional+RM logistic baselines choose lambda from
  {0, 0.01, 0.1, 1, 10} on validation Brier score
- warning thresholds are frozen on validation at a 10% false-positive budget
- all holdout probabilities and warning decisions are generated and SHA-256 locked
  before holdout labels are opened

Validation performance cannot declare success. The primary claim is decided only by the
untouched held-out replay and the preregistered basin-clustered uncertainty test.


## Pre-holdout amendment — warning semantics

Before any 2019–2022 labels were opened, the first green Calibration Lock exposed an
implementation semantics error: fitted probabilities represent **recovery**, while the
operational alert had been thresholding high recovery probability as a warning.

This amendment does not alter RM, features, fitted models, regularization, probability
predictions, the holdout rows, or the primary Brier/cluster-bootstrap success rule.
It changes only the operational warning score to:

    failure_risk = 1 - P(recovery)

Validation now selects a warning threshold by maximizing sensitivity to non-recovery
subject to a <=10% false-warning rate among episodes that recover.

The SHA-256 of the original 112-row probability-only holdout lock is pinned in source.
The amended calibration must reproduce that hash exactly or fail before holdout opening.


## Final held-out replay lock — before outcome opening

The exact amended green Calibration Lock is committed under `frozen/` before holdout
outcomes are opened. Model regeneration is forbidden during replay.

For the previously stated monotonic-direction condition, `direction passes` is now frozen
as both:

- mean raw RM among episodes that recover within 24 months is greater than mean raw RM
  among episodes that do not; and
- AUROC of raw RM for the recovery outcome is greater than 0.5.

The primary incremental statistic is:

    ΔBrier = Brier(conventional) - Brier(conventional + RM)

The uncertainty test is a two-sided percentile 95% bootstrap with 10,000 replicates,
resampling basin `ID` clusters with replacement using deterministic seed 20260829.
The confidence interval passes only if its lower endpoint is greater than zero.

A final survival verdict requires direction, positive point ΔBrier, and positive
cluster-bootstrap lower bound. No post-holdout rescue is allowed under this experiment ID.

Transparency limitation: outcome-side schema and published recovery fields were inspected
globally during the earlier Science Lock solely to verify the published label mapping.
Holdout outcomes were not used for RM scaling, fitting, feature selection, model selection,
regularization, or warning thresholds.
