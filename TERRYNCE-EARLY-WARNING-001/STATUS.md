# STATUS

Experiment: TERRYNCE-EARLY-WARNING-001
Layer: Terrynce Early Warning
State variable: Recoverability Margin (RM)
Substrate: global river-basin drought recovery
Current stage: DATA_PREFLIGHT

Kīlauea remains frozen as a negative event-timing result. This experiment does not
reinterpret or retune it.

Next gate:
1. acquire and hash exact Zenodo v2 data/code archives
2. inventory released tables and author code
3. prove a causal episode mapping exists:
   pre-relief features -> relief timestamp -> post-relief recovery outcome
4. freeze that mapping before any primary holdout scoring

If the released bundle cannot support that separation, stop.


## After DATA_PREFLIGHT

The actual preflight confirmed that the required drought, TWSA, WA, basin-attribute,
recovery-assessment tables and author figure code are present.

The next gate is `SCIENCE_LOCK_DIAGNOSTIC`. It exists because the recovery table contains
dates that can encode the recovery outcome itself. The experiment therefore locks relief
`t0` from the independent severe-drought event table and treats all post-`t0` recovery
fields as labels only.

No RM fitting or holdout scoring occurs in this gate.


## Science Lock result

The Science Lock Diagnostic passed:

- 531 severe-drought episodes and 531 recovery rows
- 531/531 exact `(ID, group)` joins
- the recovery table's `EndDate_dgt` was proven outcome-derived
- `TWSA_deseason_mov` reproduced the authors' `init_TWSA` and `min_TWSA` exactly across
  1,062 checked values
- raw chronological counts: 251 train / 103 validation / 112 holdout

The next gate freezes the actual episode table and 24-month outcome reconstruction using
train + validation only. Holdout labels remain unopened.


## Next: Calibration Lock

After Episode Lock passes, training-only history constructs response lag and historical
recovery capacity. Validation is consumed once to freeze conventional-model
regularization and the 10% false-positive warning thresholds.

Crucially, the workflow then writes and hashes every 2019–2022 prediction while the
holdout recovery labels remain unopened. The next stage may score only those frozen
predictions.


## Pre-holdout warning-semantics correction

The first Calibration Lock was green and kept the holdout sealed, but its operational
`warn` bit pointed in the wrong direction: high `P(recovery)` triggered the alert.

`PRE_HOLDOUT_WARNING_SEMANTICS_001` fixes only that presentation/control decision.
The fitted models and all 112 frozen recovery probabilities must remain byte-for-byte
equivalent under the pinned probability-only SHA-256.


## Final gate: One-Shot Heldout Replay

The amended Calibration Lock is now pinned in `frozen/`. The 112 held-out predictions
and every fitted recovery probability are immutable by SHA-256 before this workflow is
merged or run.

The held-out replay does not import or call calibration. It verifies the frozen hashes
first, acquires the same public data, opens the 2019–2022 recovery outcomes, joins them to
the already-frozen predictions, computes all baselines, and applies the preregistered
basin-clustered bootstrap.

The result of this run is the canonical TERRYNCE-EARLY-WARNING-001 result whether it wins
or loses.
