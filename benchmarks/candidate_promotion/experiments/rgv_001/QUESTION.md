# QUESTION — RGV-001

Can sequence-derived information be more useful for **vetoing likely developability failures** than for ranking antibody candidates?

Primary endpoint:

> Fraction of external experiments avoided at the single operating point selected on GDPa1 out-of-fold predictions, subject to retaining at least 95% of experimentally clean GDPa3 antibodies.

The holdout is never used to choose the model, alpha, confidence quantile, feature representation, viability threshold, or rejection rate.

The hypothesis is falsified if the learned gate fails the frozen bar in `FREEZE.json`.
