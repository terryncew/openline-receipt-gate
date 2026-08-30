# INTERVENTION-TRANSITION-001

This is the first experiment after the program-level closure:

`NO_DOMAIN_INDEPENDENT_RECOVERABILITY_MARGIN_SIGNAL`

It does not search for another margin.

It constructs the evidence the previous experiments lacked:

```text
(state/history, action, lag) -> outcome
```

The primary substrate is Unitree's released G1 locomotion policy running in MuJoCo.
A full control snapshot contains both the MuJoCo `mjSTATE_INTEGRATION` state and every
mutable Python-side variable used by the released deployment loop: previous action,
target joint positions, observation buffer, controller counter, and current command.

For each frozen perturbed context, every action × lag arm starts from the exact same
snapshot.

## Stage A only

This handoff performs four gates:

1. **Upstream inventory** — pin and hash the released policy, deployment config, XML,
   and deployment script.
2. **Snapshot fidelity** — restore the same full snapshot into two branches, run identical
   controls for 300 physics steps, and require numerical identity within 1e-12.
3. **Counterfactual oracle** — generate 50 frozen perturbed G1 contexts and execute all
   6 actions × 5 lags from every exact cloned state.
4. **Intervention Sufficiency** — feed those deterministic transition cells into
   `INTERVENTION-SUFFICIENCY-001`.

No learner is trained here.

## Claim boundary

A failed remedy means:

> this remedy failed for this cloned state under the released G1 controller, frozen
> action semantics, model constraints, delay, recovery target, and horizon.

It does **not** mean no physically possible controller could recover the robot.

Controller robustness is a later experiment. A second independently constructed competent
controller must reproduce a contraction before we call it controller-robust.

## Actions

The intervention arms are command-level remedies understood by the released locomotion
policy:

`CONTINUE`, `SLOW`, `STOP`, `RETREAT`, `LATERAL_LEFT`, `LATERAL_RIGHT`

The lag grid is:

`0, 40, 80, 120, 160 ms`

During the delay the robot continues under its pre-intervention command. The intervention
takes effect on the first 50 Hz policy update at or after the frozen delay.

## What green means

A green GitHub workflow means the plumbing is scientifically usable:

- source pins verified;
- complete snapshot cloning is deterministic;
- all counterfactual branches were generated;
- the resulting dataset passed `INTERVENTION-SUFFICIENCY-001`.

It still does not establish the remaining-control claim.

If the intervention-sufficiency stage returns `UNTESTABLE_FOR_RECOVERABILITY`, freeze that
receipt and stop. Do not tune the pushes, actions, lags, or recovery definition under this
experiment ID to manufacture remedy divergence.
