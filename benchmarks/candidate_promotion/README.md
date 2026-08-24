# Candidate Promotion Gate

This benchmark family asks when measured evidence earns a candidate the right to advance.

## CPG-001 — Jain 2017 — complete and frozen

CPG-001 compared a frozen equal-weight composite ranker with receiver-owned hard-veto promotion over the canonical 137-antibody Jain 2017 panel.

Canonical receipt:

`results/jain_canonical_01/JAIN_2017_CANONICAL_RUN_RECEIPT.json`

Scientific signal:

`NO_COMPENSATION_SIGNAL`

The composite control did not promote the masked declared-liability pattern required by the preregistered success rule. Yield, held-out quality, coverage, and authority parity passed, but the compensation hypothesis did not.

CPG-001 remains frozen. Its thresholds, score, folds, budgets, and success rule must not be retuned.

## CPG-002 — Ginkgo GDPa1 — external replication ready

`gdpa1_002/` carries a frozen replication on the versioned public GDPa1 source.

It preserves the CPG-001 baseline family and numerical success bars while applying the central Ginkgo 2025 warning thresholds to eight primary developability readouts. Clinical-stage/approval labels are excluded from the primary analysis.

Installation status:

`EXTERNAL_REPLICATION_READY_UNRUN`

The first full score is produced in CI from the exact pinned upstream Git commit/blob. The dataset is not vendored.

A negative result is allowed. If CPG-002 also returns `NO_COMPENSATION_SIGNAL`, this historical "hard gate exposes compensation hidden by this composite" line stops rather than changing the ranking or thresholds.

## Native Receipt Gate semantics

Candidate-promotion architecture remains broader than this historical replay:

- threshold failure: `DENY`
- missing/UNKNOWN/stale mandatory evidence: `QUARANTINE`
- identity/integrity/revocation failure: fail closed
- complete current passing evidence: `COMMIT`

Historical datasets cannot manufacture batch-, run-, verifier-, or freshness receipts that were never published.

## Separate experiment: sequential assay selection

`../trial_selector/` asks a different question: whether scarce assays can be ordered dynamically to expose a predeclared liability with fewer measurements.

The Jain panel is its discovery set. It does not rescue CPG-001 and does not establish a candidate-promotion advantage.
