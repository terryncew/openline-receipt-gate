# DPL-001 — Decision-Permission Link

The link is a proof obligation, not a score threshold.

```text
optimizer / planner
    |
    | exact proposal + advisory_hash
    v
receiver-owned obligation compiler
    |
    | policy_hash + effect_hash + state_hash + requirements
    v
receiver evidence verification
    |
    | VERIFIED authority/evidence receipts
    v
COMMIT_ELIGIBLE / QUARANTINE / DENY
    |
    | deterministic decision_permission_link/v1 settings
    v
Verified Commit
    |
    | exact-action hash + TTL + one-use consumption
    v
side effect
```

The optimizer may be better or worse. It may be replaced. Its rank, confidence,
rationale, or utility estimate is represented only by `advisory_hash` and never
appears in the requirement-satisfaction path.

`COMMIT_ELIGIBLE` is deliberately weaker than permission to execute. The
existing Verified Commit mechanism still binds the exact tool, target,
settings hash, policy hash, evidence hashes, expiry, and one-use code and spends
the authorization atomically at the effect boundary.

Run:

```bash
python -m unittest tests.test_authority_link -v
python benchmarks/decision_permission_link/run_suite.py
```
