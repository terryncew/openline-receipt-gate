# CPG-002

Frozen external replication of the CPG-001 candidate-promotion question on Ginkgo GDPa1.

Installation status: `EXTERNAL_REPLICATION_READY_UNRUN`.

The source dataset is intentionally absent from this repository. Run against the exact pinned Ginkgo source:

```bash
python benchmarks/candidate_promotion/gdpa1_002/run_replay.py \
  --csv /path/to/GDPa1_v1.2_20250814.csv \
  --out-dir /tmp/cpg002

python -I benchmarks/candidate_promotion/gdpa1_002/verify_result.py \
  --csv /path/to/GDPa1_v1.2_20250814.csv \
  --result-dir /tmp/cpg002 \
  --output /tmp/cpg002/independent-verification.json
```

`SUPPORTED_REPLICATION_WITHIN_SCOPE` is only one allowed result. `NO_COMPENSATION_SIGNAL`, `FRICTION_ONLY`, and `INCONCLUSIVE_COVERAGE` are scientifically meaningful negative/narrowing outcomes and do not justify retuning.
