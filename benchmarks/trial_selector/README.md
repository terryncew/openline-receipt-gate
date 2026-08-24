# Sequential assay selector

This benchmark asks a different question from Candidate Promotion Gate.

Instead of deciding which antibody advances after all required evidence is available, it asks which assay should be measured next when measurement itself is scarce.

## Jain discovery — frozen

The frozen continuous-value conditional-risk selector was evaluated by leave-one-antibody-out replay on the same 137-antibody, 10-assay Jain 2017 panel used by CPG-001.

Among the 70 antibodies with at least one frozen Jain warning-threshold crossing:

- continuous selector: **2.37 assays** on average to first declared liability;
- threshold-only dynamic logistic baseline: **2.79**;
- uniformly random order: **2.97** expected;
- greedy fixed coverage: **3.06**;
- fixed prevalence: **3.26**.

At budget 3, the continuous selector exposed 52/70 declared-liability cases. Its residual hidden-liability rate among candidates still appearing clean was 18/85 (21.2%).

**Disposition: hypothesis-generating signal only.**

Jain is exhausted as a discovery set. No further Jain tuning is allowed.

## External confirmation — installed, unrun

`external_001/` freezes the required cross-panel test on the pinned Ginkgo GDPa1 source.

Primary analysis:

- excludes exact normalized antibody-name overlaps with the frozen Jain 137-candidate cohort;
- uses eight already-frozen Ginkgo developability warning thresholds;
- requires complete measurements across those eight assays;
- executes the exact frozen Jain selector code hash;
- retains the four frozen Jain comparators;
- adds a preregistered myopic expected-information-gain comparator;
- uses one assay as one cost unit;
- treats budget-3 false reassurance as the safety endpoint.

Installation status:

`EXTERNAL_CONFIRMATION_READY_UNRUN`

Possible dispositions:

- `INCONCLUSIVE_EXTERNAL_COHORT`
- `EXTERNAL_GENERALIZATION_NOT_SUPPORTED`
- `EXTERNAL_ALLOCATION_SIGNAL`

A negative disposition is a valid scientific result and cannot justify retuning.

## Interpretation boundary

A "liability" means only a crossing of a predeclared historical developability warning threshold. It is not a clinical-failure label.

One assay is one cost unit because assay-specific dollar and elapsed-time costs are unavailable.

Even a positive external result would establish only a historical allocation signal on the exact external cohort, not a universal wet-lab scheduling policy.
