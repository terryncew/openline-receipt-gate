# INTERVENTION-TRANSITION-001 preregistration

## Scientific target

Test whether a controlled simulator can supply the missing counterfactual evidence for
remaining control by evaluating exact cloned state/history under different actions and
execution lags.

Stage A is an evidence-sufficiency experiment, not a model-performance experiment.

## Frozen counterfactual unit

The unit is `context_id`, a complete cloned controller state consisting of:

- MuJoCo `mjSTATE_INTEGRATION`;
- previous policy action;
- target joint positions;
- current observation vector;
- controller step counter;
- current command.

All action and lag arms for one `context_id` must restore that same snapshot before
branching.

## No adaptive boundary hunting

The perturbation distribution, number of contexts, action set, lag grid, target, and
horizon are frozen before outcomes are generated. They may not be changed after seeing
Stage A outcomes under this experiment ID.

## Controller scope

The oracle identifies operational feasibility under the released Unitree G1 locomotion
controller. It does not identify the physical viability kernel of the robot.

## Stage A success criterion

The resulting transition dataset must return `PASS_INTERVENTION_SUFFICIENCY` under the
already frozen `INTERVENTION-SUFFICIENCY-001` gate.

Failure means the substrate/regime is insufficient for the remaining-control claim.
No Terrynce scalar, transition learner, or matched-risk analysis may be fit under
`INTERVENTION-TRANSITION-001` after such a failure.

## Future Stage B, only after PASS

Split by `context_id`, never by action/lag branch. Train a strong direct
action-conditioned transition model and compare it against state-only/default-risk
baselines using proper scoring rules on untouched contexts.
