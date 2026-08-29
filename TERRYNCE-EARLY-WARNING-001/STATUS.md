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
