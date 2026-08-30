# INTERVENTION-TRANSITION-001 — Stage B

Stage A passed. The simulator produced exact cloned counterfactuals with remedy divergence and lag contraction. Stage B asks the next question:

> Can a learner recover intervention-conditioned outcomes on unseen states, or are action and lag redundant once state is known?

This stage is deliberately downstream of the counterfactual oracle. It does not fit a universal margin or Terrynce scalar.

## Frozen evidence

The workflow downloads only the immutable Stage A artifact from GitHub Actions run `33288841294` and verifies:

- transition dataset SHA-256 `50bdcc13dff766fc13f9694347bfaef3f12b6951a85340ae96cd1cc5abb4c94c`
- context receipt SHA-256 `9fb1b1d661c48bdd19e4db9fd97d5e219b767d54b1168f494ee64f1d59fb204e`
- manifest SHA-256 `3410f5e13ae835ccc88c40624f60fe961f8bb81b1fdcc1e3abc16fb3d197fb45`

The 50 contexts are split by a deterministic hash of the frozen dataset SHA and context ID: 30 train, 10 validation, 10 holdout. Entire action×lag families stay together.

## State reconstruction

Stage A stored binding hashes rather than the full high-dimensional robot/controller state. Stage B therefore replays the frozen, seeded context-generation procedure to reconstruct features. A reconstructed context is accepted only if both its MuJoCo integration-state hash and full wrapper/LSTM-state hash match the Stage A receipt exactly.

The learner sees the current control state only: MuJoCo integration state, previous action, target joint positions, observation vector, command, controller counter, and recurrent hidden/cell state. Perturbation-generation metadata are excluded from predictors.

## Learner

The state vector is standardized and projected with PCA fit on the 30 training contexts only. The learned transition probability is an inverse-distance k-nearest-context estimate over the state manifold.

The direct model conditions on exact action and exact lag. Four frozen comparators remove information one piece at a time:

- state only;
- state + lag, without action;
- state + action, without lag;
- global action + lag, without state.

Each kNN model selects `k ∈ {3,5,7,9}` using validation Brier score only. Holdout predictions are then written and hashed before holdout labels are consumed.

## Primary falsifiers

A cell is called feasible only when the learned model assigns `P(success) ≥ 0.95`, frozen before holdout.

The direct model receives support only if all three hold on the one-shot 10-context holdout:

1. **Action conditioning adds information:** `Brier(state+lag) − Brier(direct) > 0` and the 10,000-replicate context-bootstrap 95% lower bound is above zero.
2. **Lag conditioning adds information:** `Brier(state+action) − Brier(direct) > 0` with the same bootstrap requirement.
3. **Remedy-set recovery:** on held-out context×lag groups where some actions work and others fail, the direct model's mean feasible-set Jaccard exceeds both state+lag and state-only.

A secondary test looks for pairs of held-out states with continuation risk within 0.10 but different oracle feasible sets, then asks whether the direct model preserves that difference.

## Interpretation boundary

A positive result means intervention-conditioned outcomes are learnable in this frozen Unitree G1 / MuJoCo / controller regime. It does not establish a domain-independent recoverability quantity and it does not establish physical impossibility under every possible controller.
