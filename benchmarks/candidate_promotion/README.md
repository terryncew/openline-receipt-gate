# Candidate Promotion Gate — CPG-001

This benchmark adds a candidate-promotion policy profile to Receipt Gate without creating a new subsystem.

The synthetic fixture is an architecture self-test, not the scientific result. It pressure-tests non-compensation, missing/UNKNOWN evidence, stale/revoked evidence, exact candidate identity binding, evidence-class independence, and policy timing.

The Jain 2017 branch is a **design lock**, not an outcome run. It freezes the claim boundary, composite baseline, complete-case rule, leave-one-property-group-out folds, correlation audit, and numeric falsifier before publication-era status labels are used.

Key commands:

```bash
python benchmarks/candidate_promotion/verify_jain_design_lock.py
pytest -q tests/test_candidate_promotion.py tests/test_candidate_promotion_jain_design.py
python benchmarks/candidate_promotion/run_replay.py
```

After the design lock is merged, bind the three exact PNAS supplements:

```bash
python benchmarks/candidate_promotion/bind_jain_sources.py /path/to/jain-files \
  --out benchmarks/candidate_promotion/JAIN_2017_SOURCE_MANIFEST.json
```

Required filenames are pinned in `JAIN_2017_SOURCE_REQUIREMENTS.json`.

Do not run the confirmatory replay until a normalized artifact carries the exact source hashes plus the frozen `design_lock_sha256` and `thresholds_sha256`. `run_jain_confirmatory.py` rejects hash drift.

CPG-001 Jain scope is developability only. Affinity/potency is absent from Jain 2017 and cannot be inferred from clinical-stage inclusion. GDPa1 remains untouched until the Jain replay is complete.
