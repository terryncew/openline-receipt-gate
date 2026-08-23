# Candidate Promotion Gate — CPG-001

This benchmark adds a biologically meaningful policy profile to Receipt Gate without creating a new subsystem.

The synthetic fixture is an architecture self-test, not the scientific result. It contains a high-ranking candidate with a declared HIC failure and a high-ranking candidate with UNKNOWN mandatory evidence. The treatment arm must remove both from promotion eligibility while retaining enough passing candidates to fill top-K.

Run:

```bash
python benchmarks/candidate_promotion/run_replay.py
pytest -q tests/test_candidate_promotion.py
```

Before Jain/GDPa1 confirmatory replays, bind the exact data artifact SHA-256 and freeze a dataset-specific profile containing the preregistered veto dimensions, thresholds, acceptable methods, and held-out dimensions. Do not tune those values against the final outcomes.
