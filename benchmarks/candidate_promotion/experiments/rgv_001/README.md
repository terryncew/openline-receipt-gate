# RGV-001 — Reality Gate: Held-Out Viability Veto

## The inversion

Poor ranking does not imply poor vetoing.

A model can be bad at ordering candidates from best to worst and still be useful if it can identify a high-confidence toxic tail. RGV-001 asks whether sequence-only prediction can allocate scarce experimental capacity by stopping candidates likely to violate a joint developability viability region.

There is deliberately **no PASS** state:

- `VETO` = high-confidence predicted violation;
- `UNKNOWN` = worth measuring;
- `PASS` = forbidden.

## Why this is not CPG-001/002 again

CPG-001 tested composite ranking versus a hard declared-liability gate and found `NO_COMPENSATION_SIGNAL`. CPG-002 replicated on GDPa1 and reached `INCONCLUSIVE_COVERAGE`; both composite and veto arms showed zero declared gated-liability promotions.

RGV-001 changes the object under test. It predicts the *continuous assay values* from sequence, constructs one-sided uncertainty bounds using only GDPa1 out-of-fold residuals, and vetoes only when the bound itself lies beyond a frozen viability boundary. If this also fails on the untouched external holdout, the selector/veto line closes.

## Frozen primary truth

Experimentally clean means simultaneously:

- HIC <= 3.18
- PR_CHO <= 0.38
- AC-SINS_pH7.4 <= 17.51

Tm2 < 77.71 C is secondary only. Titer is excluded from the primary endpoint.

## External test

Train / tune only on GDPa1. Evaluate once on GDPa3 (80 OAS-derived held-out antibodies from the Ginkgo competition). The script refuses to choose model hyperparameters, residual confidence, or viability thresholds from GDPa3 labels.

## Primary bar

`HELDOUT_VIABILITY_VETO_SIGNAL` requires all of:

1. >=95% of experimentally clean GDPa3 antibodies retained;
2. >=50% of external experiments avoided;
3. >=10 percentage points more experiments avoided than the best nonrandom baseline that also retains >=95% clean antibodies;
4. at least 60 evaluable GDPa3 rows and at least 20 clean rows;
5. the primary direction survives the predeclared ±5% threshold stress probe.

Otherwise the learned-veto claim is killed, unless the external data contract itself is incomplete, in which case the verdict is `INCONCLUSIVE_EXTERNAL_COVERAGE`.

The ±5% stress probe is a preregistered robustness test, **not** a claim that published assay uncertainty is ±5%.
