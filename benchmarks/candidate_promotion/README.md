# Candidate Promotion Gate — CPG-001

This benchmark adds a candidate-promotion policy profile to Receipt Gate without creating a new subsystem.

The synthetic fixture is an architecture self-test, not the scientific result. It pressure-tests non-compensation, missing/UNKNOWN evidence, stale/revoked evidence, exact candidate identity binding, evidence-class independence, and policy timing.

The Jain 2017 design lock is merged. The next stage is an **assay-only source preflight**: bind all three exact PNAS supplements, open SD03 only, resolve the 10 frozen assay columns, seal the complete-case cohort and correlation audit, and keep SD01 publication-era status labels unopened until that artifact is hashed.

Key commands:

```bash
python benchmarks/candidate_promotion/verify_jain_design_lock.py
python benchmarks/candidate_promotion/verify_jain_preflight_contract.py
pytest -q tests/test_candidate_promotion.py tests/test_candidate_promotion_jain_design.py tests/test_candidate_promotion_jain_preflight.py
python benchmarks/candidate_promotion/run_replay.py
```

Place the three exact PNAS supplements in the local, gitignored `benchmarks/candidate_promotion/jain_sources/` directory, then run the assay-only preflight:

```bash
python benchmarks/candidate_promotion/preflight_jain_assays.py \
  benchmarks/candidate_promotion/jain_sources \
  --out-dir benchmarks/candidate_promotion/results/jain_preflight
```

Required filenames are pinned in `JAIN_2017_SOURCE_REQUIREMENTS.json`. The source binder hashes and validates all three XLSX containers without opening worksheet cells. The preflight then opens **SD03 only**. SD01 and SD02 cells remain sealed. The command emits a deterministic source-set hash, an assay-only normalized artifact, the preregistered Spearman correlation audit, and a preflight receipt. It returns nonzero if SD03 does not contain exactly the published 137 candidate rows.

Do not run the confirmatory replay until `JAIN_2017_ASSAY_PREFLIGHT_RECEIPT.json` says `ready_for_label_unseal: true`, and the assay-only artifact plus design/threshold hashes are sealed. The subsequent label-unseal stage must read status only from the already-bound SD01 and may not change cohort, thresholds, folds, or weights.

CPG-001 Jain scope is developability only. Affinity/potency is absent from Jain 2017 and cannot be inferred from clinical-stage inclusion. GDPa1 remains untouched until the Jain replay is complete.
