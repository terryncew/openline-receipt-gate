# Agent-Mesh-Identity-001 Claim Boundary

Agent-Mesh-Identity-001 is a `PAPER_DERIVED_REGRESSION_FIXTURE_PACK`, not a
cold integration or a reproduction of the paper's production incidents. The
pinned source is Agent Mesh v1 (`arXiv:2608.26225v1`), especially Section V and
Table II. No author fault harness or incident corpus is imported.

The experiment translates the five identity-adequacy failures in Table II into
five sealed pairs of Receipt Gate decision proposals. The representation-blind
oracle says whether each pair denotes the same consequential effect or two
effects that must remain distinguishable.

The scored production arm is the existing `olp_gate.authority_link.effect_hash`
from base commit `0d5666a1b0097ef2bac316a99cc1834ba73460bf`. The experiment
may import that function but may not change it, wrap it with case-specific
logic, or add a new identity primitive. The paper-failed-identity arm hashes
only the inadequate identity named by Table II and serves as a reproduction
control.

If the existing effect binding matches all five oracle relations while the
paper-failed identities reproduce all five collision/split errors, the earned
verdict is `CURRENT_EFFECT_BINDING_COVERS_ALL_FIVE_CASES`. That means no new
Receipt Gate mechanism is justified by this fixture pack.

If any existing effect binding relation disagrees with the oracle, the earned
verdict is `SEMANTIC_IDENTITY_GAP_DETECTED`. The result must name the exact
case. No repair is permitted inside this experiment.

The fixtures explicitly declare which fields are semantically load-bearing.
This test therefore establishes representational adequacy only. It does not
show that Receipt Gate can infer the correct semantic object from arbitrary
agent payloads, that an adapter cannot choose the wrong target or state hash,
or that the five private production incidents are fixed.

Cryptographic validity is not scored as semantic adequacy. Both a good and a
bad identity can be hashed perfectly.

`policy_authority: NONE`

