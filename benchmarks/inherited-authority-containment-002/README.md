# Inherited Authority Containment 002 (IAC-002)

**Status:** `PROTOCOL_CONFORMANCE_UNRUN` before CI  
**Policy authority:** `NONE`

IAC-002 tests the consequence layer after IAC-001 earned controlled-ground-truth selective containment.

Question:

> After compromise is detected mid-workflow, can a receipt-aware receiver reduce post-detection unauthorized actions while preserving unaffected work better than blunt revocation baselines?

This is still a controlled simulation. It does not touch AWS, Slack, GitHub credentials, production IAM, or real external side effects.

## Four arms

- `NODE_ONLY` — only the compromised agent loses authority.
- `GLOBAL_KILL` — all downstream work is stopped.
- `TIME_WINDOW` — all post-compromise/pre-detection descendants are stopped.
- `OLP_SELECTIVE` — tainted descendants are revoked, clean descendants retained, unresolved descendants quarantined.

## Frozen workflow model

Each trial contains:

- 24 agents/tasks arranged as a DAG;
- one agent compromised after an initial valid phase;
- authority delegation before detection;
- detection lag of 4 to 8 simulated steps;
- mixed tainted and clean descendants;
- partial dependency visibility.

At detection, each policy classifies already-created descendant state. The workflow then runs 12 more simulated steps.

## Primary outcomes

- post-detection unauthorized actions;
- clean actions incorrectly blocked;
- residual tainted authority accepted;
- time-to-containment;
- useful-work preservation;
- weighted consequence score.

The important comparison is not "can OLP stop everything." `GLOBAL_KILL` can do that trivially. OLP must stop tainted continuation while preserving substantially more clean work.

## Frozen pass bar

`OLP_SELECTIVE` must satisfy all of:

- unauthorized post-detection action rate <= 0.03;
- residual tainted authority acceptance <= 0.03;
- useful-work preservation >= 0.70;
- at least 0.30 more useful-work preservation than `GLOBAL_KILL`;
- weighted consequence score lower than `NODE_ONLY`, `GLOBAL_KILL`, and `TIME_WINDOW`;
- median containment lag <= 1 simulated step.

If any condition fails:

`MACHINE_SPEED_CONTAINMENT_NOT_EARNED`

If all conditions pass, maximum verdict:

`CONTROLLED_MACHINE_SPEED_AUTHORITY_CONTAINMENT`

## Claim boundary

A passing IAC-002 does not establish:

- real cloud containment;
- credential revocation outside a receipt-aware perimeter;
- compromise detection;
- reversal of already-completed external side effects;
- protection against all transitive delegation patterns;
- replacement for IAM, CIEM, EDR, SIEM, or incident response;
- policy authority.

It establishes only a controlled consequence-level separation under a frozen simulated authority workflow.
