# CPG-001 — Jain real-evidence run

This stage executes the already-frozen Jain 2017 confirmatory design. It does not change thresholds, folds, weights, budgets, or success criteria.

## Source authority

Only the exact three published PNAS supplementary XLSX files may enter the confirmatory run. Acquisition tries publisher and NCBI archival URLs from `JAIN_2017_SOURCE_URLS.json`. Every accepted artifact must retain the canonical filename, pass XLSX container validation, and receive a SHA-256 binding. A processed CSV, Hugging Face derivative, GitHub data mirror, or reformatted workbook is never silently substituted when a canonical source is unavailable.

## Label firewall

Acquisition treats all three workbooks as opaque bytes. `preflight_jain_assays.py` opens SD03 only, creates the assay-only normalization/correlation audit, and writes a preflight receipt. `unseal_jain_labels.py` must reload those persisted files and verify the sealed `assay_only_sha256` before it is allowed to open SD01. SD02 remains unopened by the confirmatory selection analysis; its bytes are nevertheless bound into the source set.

## Execution

The dedicated GitHub Actions workflow runs only after this code is on `main` (or by explicit manual dispatch). It deliberately does not run the real evidence replay on pull requests. That keeps source acquisition and outcome exposure downstream of the merged design and execution code.

A negative scientific verdict is not a CI failure. `FRICTION_ONLY`, `NO_COMPENSATION_SIGNAL`, and `INCONCLUSIVE_COVERAGE` are valid experiment outcomes. CI fails only when source authority, preflight, binding, label unseal, or execution integrity fails.

The workflow uploads JSON evidence artifacts; raw publisher XLSX files are not committed.
