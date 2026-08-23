# DPL-002 — End-to-End Authority Acquisition Falsifier

This is the strong control DPL-001 did not have.

The workflow is automated B2B settlement. An optimizer may rationally prefer an immediate Tier-2 payment to avoid a large late fee. The receiver mandate permits immediate settlement only when independent standing evidence establishes the required authority, Tier-1 status, current liquidity, and an open invoice. A lower-ranked net-30 route remains available.

The control is intentionally **not** OAuth scopes or toy RBAC. Capability systems do not inherently bind authorization to caller identity; bearer capabilities and macaroon-style caveats can be receiver-issued and conditioned on third-party discharge evidence. DPL therefore competes against a receiver-issued caveated bearer capability with exact-effect hashing, state binding, freshness/revocation caveats, expiry, and one-use replay protection.

The falsifier is simple:

> If that control reproduces DPL on all permission and execution seams, DPL is not a new authorization primitive.

That outcome does not make the implementation useless. It narrows the surviving claim to an OpenLine-specific, receipt-native application profile for translating untrusted optimizer proposals into receiver-owned, evidence-conditioned authorization that existing Verified Commit can spend exactly once.

Run in the repository root:

```bash
python -m unittest tests.test_decision_permission_link_002 -v
python -m unittest tests.test_dpl002_verified_commit_integration -v
python benchmarks/decision_permission_link_002/run_suite.py
```
