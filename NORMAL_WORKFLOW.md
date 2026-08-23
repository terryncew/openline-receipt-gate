# CPG-001 Canonical Source Bind — Normal Workflow

Base observed before build: `main@d8fc8824ca8d032afb7340bff54c7d79840ae971`

## Working Copy

1. Switch `openline-receipt-gate` to `main` and pull.
2. Create branch `test/cpg-001-jain-canonical-bind`.
3. Overlay the ZIP at repository root. The first paths must be `.github/`, `benchmarks/`, `tests/`, and `NORMAL_WORKFLOW.md`.
4. Commit with `test(cpg): add canonical Jain source bind`.
5. Push and open a PR to `main` titled `CPG-001: add canonical Jain source bind`.
6. Merge only after `release-check`, `candidate-promotion-001`, and `cpg001-jain-canonical-bind-harness` are green.

## What this merge does

- Retires automatic R1-R4 publisher-source acquisition from push-triggered CI.
- Retires the 143-row mirror from push-triggered CI and freezes it as `SOURCE_COHORT_MISMATCH` with no scientific verdict.
- Adds a network-free canonical runner for one-time manually acquired SD01/SD02/SD03 workbooks.
- Does **not** change the frozen CPG thresholds, baseline, folds, budgets, or verdict criteria.

## After merge

Acquire the exact three XLSX files through a normal browser session and keep them outside the public repo by default:

- `pnas.1616408114.sd01.xlsx`
- `pnas.1616408114.sd02.xlsx`
- `pnas.1616408114.sd03.xlsx`

Fill `JAIN_2017_MANUAL_ACQUISITION_TEMPLATE.json` with the exact HTTPS source URLs and retrieval timestamp. Then run:

```bash
python benchmarks/candidate_promotion/run_jain_canonical_bind.py \
  --source-dir /path/to/jain-source \
  --attestation /path/to/JAIN_2017_MANUAL_ACQUISITION.json \
  --out-dir /tmp/cpg001-jain-canonical
```

A scientific negative is a valid completed experiment. A source/cohort mismatch exits blocked with no scientific verdict.
