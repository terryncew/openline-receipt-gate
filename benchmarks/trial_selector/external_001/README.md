# TRIAL-SELECTOR-EXTERNAL-001

External confirmation of the frozen Jain sequential assay selector on the pinned Ginkgo GDPa1 source.

Installation status:

`EXTERNAL_CONFIRMATION_READY_UNRUN`

The source dataset is not committed. CI fetches the exact upstream Git commit and blob.

Run locally only with the exact source:

```bash
python benchmarks/trial_selector/external_001/run_external.py \
  --csv /path/to/GDPa1_v1.2_20250814.csv \
  --out-dir /tmp/trial-selector-external-001

python benchmarks/trial_selector/external_001/verify_external_result.py \
  --csv /path/to/GDPa1_v1.2_20250814.csv \
  --result-dir /tmp/trial-selector-external-001 \
  --output /tmp/trial-selector-external-001/independent-verification.json
```

The first full external selector score belongs to CI.

Allowed scientific dispositions:

- `INCONCLUSIVE_EXTERNAL_COHORT`
- `EXTERNAL_GENERALIZATION_NOT_SUPPORTED`
- `EXTERNAL_ALLOCATION_SIGNAL`

A negative scientific disposition is not a CI failure.
