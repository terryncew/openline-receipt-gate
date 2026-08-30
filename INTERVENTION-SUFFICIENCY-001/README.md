# INTERVENTION-SUFFICIENCY-001

This gate comes **before** any future recoverability model.

Program-level result:

`NO_DOMAIN_INDEPENDENT_RECOVERABILITY_MARGIN_SIGNAL`

The recoverability line is closed until a candidate dataset can support the actual
counterfactual object:

```text
(state/history, action, lag) -> outcome distribution
```

This preflight deliberately does no predictive modeling. It asks whether the evidence
contains enough intervention variation to make the next experiment identifiable.

## What PASS means

`PASS_INTERVENTION_SUFFICIENCY` requires, under frozen defaults:

- at least 50 matched contexts;
- at least 150 context/action/lag transition cells;
- at least 2 actions and 2 lags;
- at least 25 matched context+lag groups where multiple actions were tested;
- at least 10 matched context+lag groups with genuine remedy divergence;
- at least 25 matched context+action groups with multiple lags;
- at least 10 lag-driven contractions;
- at least 20 clearly success-like and 20 clearly failure-like transition cells.

A remedy-divergence case is stronger than "same apparent risk, different remedy":
within the same frozen matched context, target, constraint set, and lag, at least one
action is empirically feasible while another is empirically infeasible.

A lag contraction means the same matched context and action is feasible at an earlier
lag and infeasible at a later lag.

PASS does **not** support a recoverability claim. It only authorizes the next scientific
step: benchmark a strong direct action-conditioned transition model.

## Canonical dataset

Required identity columns:

```text
context_id, action_id, lag, target_id, constraint_set_id
```

For `deterministic_rollout` and `stochastic_rollout`, include:

```text
trial_id, outcome_success
```

For `validated_dynamics_model`, include:

```text
success_probability
```

and the manifest must pin a model-validation receipt SHA-256.

`context_id` must mean either exact state/history identity or a domain-justified matched
state/history defined before outcome analysis. Matching target and constraints is also
required before a pair counts as an intervention contrast.

## Decision rule

Failure status:

`UNTESTABLE_FOR_RECOVERABILITY`

That is a design result, not a negative result about the underlying domain. The correct
response is to reject the substrate, not invent a better scalar.

## After PASS

The next experiment must begin with a direct action-conditioned comparator. A future
Terrynce-style curve or margin may only be computed downstream from that domain model and
must earn its role through transfer, calibration, robustness, compression,
interpretability, or safer decisions.
