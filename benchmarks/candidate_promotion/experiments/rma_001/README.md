# RMA-001 — Reality Measurement Allocation

RGV-PILOT found no evidence that the learned sequence gate deserved direct veto authority.

RMA-001 asks a different question: can prediction still reduce the number of physical measurements by choosing which assay to run next?

The model has **routing authority only**. It cannot produce the final disposition.

- VETO requires an observed assay failure.
- RETAIN requires all three observed assays to be clean.

The primary cost model is one unit per assay reveal because the frozen Ginkgo source does not provide a defensible assay cost schedule.

The strongest fixed baseline is not an arbitrary order. For every held-out fold, the benchmark searches all six fixed assay permutations on the training folds and uses the cheapest one on the held-out fold.

Verdicts:

- `SEQUENCE_ADAPTIVE_ROUTING_SIGNAL`
- `HISTORY_ONLY_ROUTING_SIGNAL`
- `NO_MEASUREMENT_ROUTING_SIGNAL`
- `INCONCLUSIVE_MEASUREMENT_COVERAGE`

A null closes the three-assay routing hypothesis on this substrate.
