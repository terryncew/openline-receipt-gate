# TERRYNCE-EARLY-WARNING-001

## Recoverability Margin — basin drought recovery

This experiment tests a correction forced by TERRYNCE-KILAUEA-001.

Kīlauea asked whether a multichannel transition signal could predict the event clock.
This family asks a different question:

> Before pressure is relieved, can we estimate whether an admissible path to recovery still exists?

The public-facing layer is **Terrynce Early Warning**.
The state variable under test is **Recoverability Margin (RM)**.

RM is not a countdown. It is a control-state claim: how much recovery room remains after
current burden, adverse momentum, and intervention/response lag are accounted for.

## First substrate

Global river-basin recovery from severe droughts, using the open Xu & Zhang Zenodo v2 bundle:

- severe drought events and ensemble SPEI
- terrestrial-water-storage anomalies (TWSA)
- water availability
- basin attributes
- published TWS recovery assessments
- author analysis code

The bundle is small enough to run in GitHub Actions and requires no account or outreach.

## Frozen causal boundary

For an episode ending at relief time `t0`:

- RM inputs for that episode must be observable at or before `t0`.
- Post-`t0` observations may define the recovery outcome.
- Training episodes may teach global/history parameters, but a test episode can never
  teach its own margin from its own future.
- Final holdout is chronological and opened once.
- No threshold rescue after holdout.

## RM structural form

The exact dataset-to-variable mapping is locked only after the data preflight, but the
structure is already frozen:

    future_burden = state_deficit + adverse_momentum × response_lag + drought_burden
    available_recovery = historical_recovery_capacity × max(0, horizon - response_lag)
    RM = available_recovery - future_burden

All components are normalized with training-only scales.

Positive RM means the frozen model says enough recovery capacity remains within the fixed
horizon. RM near zero is the warning region. Negative RM means the old recovery target is
not supported by the learned dynamics within that horizon.

This is an empirical score, not a claim that a natural system has a literal scalar
"amount of recoverability."

## Hard baselines

RM must beat:

1. current state/deficit alone
2. recent pre-relief trend alone
3. drought severity/duration alone
4. best single causal observable selected on training only
5. history/persistence baseline
6. conventional resilience indicators from the pre-relief series (lag-1 autocorrelation
   and variance), where estimable
7. a conventional multivariable model using ordinary state + trend + severity/history

The decisive test is incremental: adding RM to the conventional model must improve
held-out recovery prediction. If it does not, the recoverability-margin claim fails here.

## Stage now

`DATA_PREFLIGHT`

Run the GitHub Actions workflow:

**TERRYNCE-EARLY-WARNING-001 Data Preflight**

It downloads and hash-checks the exact Zenodo archive, inventories the author schema,
captures sample rows/headers from the key tables, scans the author code for the recovery
definition, and emits a small receipt artifact.

No holdout is scored in this stage.


## Causality correction after preflight

The released `TWSA_recovery_one_95.csv` contains outcome-side dates and recovery metrics.
They are never allowed to define the predictor cutoff. `relief_t0` is anchored to
`severe_drought_events_ensemble.csv:EndDate` using the `(ID, group)` episode key.

The Science Lock Diagnostic verifies this join and identifies the exact released TWSA
series that reproduces the authors' recovery values before we freeze the outcome
reconstruction.


## Episode Lock

After the Science Lock passed, the experiment freezes a stricter predictor boundary:
only observed CSR/GSFC/JPL center values timestamped at or before `relief_t0` may supply
the TWSA state/trend/resilience features. Filled and STL-derived series are outcome-only
or quarantined.

The primary label is recovery of 90% of the TWS loss within 24 months after meteorological
drought relief. Its reconstruction is verified against the released author outcome on
training + validation before any model is fitted. Holdout labels are not created in this
stage.


## Calibration

`TERRYNCE-EARLY-WARNING-001 Calibration Lock` turns the frozen episode definition into
a true pre-outcome prediction lock. It trains on the training period, consumes validation
once, then emits `holdout_predictions.lock.csv` before constructing any holdout labels.

That file is the line in the sand: the held-out replay may join outcomes to those rows;
it may not regenerate better predictions after seeing the outcomes.
