# INTERVENTION-TRANSITION-001 Stage B preregistration

## Question

Can intervention-conditioned transition outcomes be learned on unseen G1 states once exact counterfactual action×lag evidence exists?

## Frozen split

The split is outcome-blind and deterministic. Sort all 50 Stage A context IDs by:

`SHA256(stage_a_dataset_sha256 + "|" + context_id)`

Then assign the first 30 contexts to training, the next 10 to validation, and the last 10 to holdout. Every action×lag branch from a context stays in the same split.

The exact context IDs are frozen in `config/stage_b.frozen.json`.

## Predictors

For each context, reconstruct the exact Stage A state and require both Stage A state hashes to match before using it. Predictors are the current MuJoCo integration state and frozen controller state, including recurrent LSTM hidden/cell state. Perturbation-generation metadata are excluded.

Standardization and PCA are fit on training contexts only.

## Models

All learned models use the same inverse-distance nearest-context probability estimator and the same `k ∈ {3,5,7,9}` validation search.

- state only
- state + lag
- state + action
- direct state + action + lag
- global action + lag with no state

Target is failure probability. A remedy is classified feasible only when `P(success) >= 0.95`.

## Primary falsifiers

`SUPPORTS_ACTION_CONDITIONED_TRANSITION_CLAIM` requires all of:

1. Action gain: heldout `Brier(state+lag) - Brier(direct) > 0` with 10,000-context-bootstrap 95% lower bound above zero.
2. Lag gain: heldout `Brier(state+action) - Brier(direct) > 0` with the same lower-bound rule.
3. On heldout remedy-divergent context×lag groups, direct feasible-set mean Jaccard exceeds both state+lag and state-only.

If heldout contains fewer than 20 failure cells or fewer than 5 remedy-divergent context×lag groups, return `INSUFFICIENT_HELDOUT_SUPPORT` instead of interpreting the test.

## Secondary matched-risk test

Use state-only predicted failure risk for `CONTINUE@0ms` as nominal scalar danger. For heldout state pairs within 0.10 absolute predicted risk, identify cases whose oracle feasible action sets differ at a given lag. If at least five such pair×lag units exist, report whether each model preserves the set difference.

## Boundary

This experiment concerns the frozen Unitree G1 controller, MuJoCo model, action vocabulary, lag grid, target, and horizon. It neither establishes a universal recoverability scalar nor proves physical impossibility under untested controllers.
