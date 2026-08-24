# TRIAL-SELECTOR-EXTERNAL-001 — GDPa1 external confirmation

## Question

Does the already-frozen Jain continuous-value conditional-risk selector retain an assay-allocation advantage on a separately sourced Ginkgo antibody panel when Jain-overlap antibodies are excluded from the primary analysis?

This is the external confirmation required by `JAIN_SELECTOR_FREEZE.json`. It does not alter the discovery selector.

## Discovery boundary

The Jain discovery result is frozen:

- continuous selector: 2.37 assays on average to first declared liability among liability-positive antibodies;
- strongest reported dynamic comparator: 2.79;
- at budget 3, the continuous selector's false-reassurance rate was 21.2%;
- the Jain panel may not be tuned again.

Those values are hypothesis-generating only. This experiment asks whether the mechanism transports.

The exact discovery selector source is bound by SHA-256:

`4f959c4bec0de3ccd9b640aa367159bf8785c1e4bfbb94290e0da2cc10ddb44d`

Any source change aborts this external run.

## External source

Use the exact source already bound for CPG-002:

- repository: `ginkgobioworks/abdev-benchmark`
- commit: `cc6d3b69afc92695445695345399d9c91b0d14a4`
- path: `data/GDPa1_v1.2_20250814.csv`
- git blob: `923c38b1a7b7d2421bd4c6fa7461febc797c446c`
- expected bytes: `862134`

The source is fetched in CI and is not vendored.

CPG-002 already established that the public file contains substantial missingness across the broader eight-assay promotion panel. That source-feasibility fact is known before this freeze. No trial-selector score on the external panel is used to choose the cohort, thresholds, comparator set, or success rule.

## Primary identity exclusion

Primary analysis excludes every GDPa1 row whose `antibody_name`, after `strip()` and Unicode `casefold()`, exactly equals one of the 137 frozen Jain candidate IDs.

The frozen Jain candidate-ID set must recompute to:

`a67946700a7b4a98cb46c3bd1ba205a708c04544e55591540b5d8bfe084a633f`

No fuzzy name matching, alias inference, clinical-status inference, or sequence-based rescue is introduced after scoring.

The result reports the exact overlap count and identities.

## External assays and thresholds

Use the eight assay columns already frozen in the CPG-002 Ginkgo policy:

- `Tm1`
- `Tm2`
- `HIC`
- `SMAC`
- `AC-SINS_pH6.0`
- `AC-SINS_pH7.4`
- `PR_CHO`
- `PR_Ova`

Thresholds come only from the already-frozen Ginkgo policy file. They may not be modified after this protocol.

The external assay names are passed to the exact frozen selector implementation as the prospectively declared external assay surface. Model form, scaling, regularization, solver, first-step rule, conditional-risk logic, and tie-breaking remain unchanged.

## Missingness

Primary cohort:

1. exclude exact Jain-name overlaps;
2. require finite measurements on all eight frozen external assays;
3. never impute.

Before any allocation claim, the primary cohort must contain at least:

- 40 candidates total;
- 10 candidates with at least one declared liability;
- 10 candidates with no declared liability.

Failure produces `INCONCLUSIVE_EXTERNAL_COHORT`.

These are cohort-admissibility bars, not success bars.

## Cost

One observed assay equals one cost unit.

This experiment has no assay-specific dollar or elapsed-time cost data. It therefore cannot claim dollar savings or faster laboratory turnaround.

## Frozen selector

The external runner executes the exact `benchmarks/trial_selector/jain_selector.py` implementation after verifying its frozen SHA-256.

Only two external inputs change:

1. the prospectively frozen eight-assay `ASSAY_ORDER`;
2. threshold objects translated mechanically from the frozen Ginkgo policy.

Ginkgo `LOWER` warnings become a frozen selector `>= threshold` pass rule.  
Ginkgo `UPPER` warnings become a frozen selector `<= threshold` pass rule.

Nothing else changes.

## Comparators

The four Jain comparators remain:

1. fixed prevalence;
2. greedy fixed coverage;
3. analytic uniform-random expected order;
4. binary dynamic conditional-risk selector.

A fifth comparator is preregistered here before the external score:

### Myopic expected information gain

At each step, use the same conditional liability probabilities produced by the continuous logistic model.

For each remaining assay with predicted liability probability `p`, compute Bernoulli entropy:

`H_b(p) = -p log2 p - (1-p) log2(1-p)`

Observing that assay resolves its binary liability variable, so `H_b(p)` is the one-step expected information gain for that variable.

Choose the assay with maximum `H_b(p)`. Assay name ascending breaks ties.

This is intentionally myopic. It does not simulate future assay sequences and is not presented as a universal optimal-design algorithm.

## Primary metrics

Efficiency:

`mean assays to first declared liability`

computed only among liability-positive primary candidates.

Safety:

`false reassurance after 3 assays`

Among candidates for which a method has not exposed a liability in its first three assays, what fraction actually contains a liability in an unrevealed assay?

## Strongest admissible baseline

Among the five preregistered baselines, choose the baseline with:

1. lowest mean assays to first liability;
2. if tied, lower budget-3 false reassurance;
3. if still tied, baseline name ascending.

This baseline is the efficiency champion.

## Statistical gate

For every liability-positive primary candidate, form:

`champion_cost - selector_cost`

Run a deterministic paired bootstrap over liability-positive candidate IDs:

- 5,000 replicates;
- seed `20260824`;
- percentile 95% interval;
- champion identity fixed from the full primary sample before bootstrap.

## Verdict

`EXTERNAL_ALLOCATION_SIGNAL` requires all three:

1. continuous selector mean cost is strictly lower than **every** preregistered baseline;
2. paired-bootstrap 95% lower bound for `champion_cost - selector_cost` is greater than zero;
3. selector budget-3 false reassurance is no higher than the champion baseline.

Otherwise:

`EXTERNAL_GENERALIZATION_NOT_SUPPORTED`

If the primary cohort fails its frozen admissibility bar:

`INCONCLUSIVE_EXTERNAL_COHORT`

A negative scientific verdict is a valid result. CI must stay green if mechanics, source binding, and independent replay are valid.

## Claim boundary

A positive result can establish only an external historical allocation signal on this exact non-Jain-overlap complete-case GDPa1 cohort.

It does not establish clinical prediction, universal antibody developability, dollar savings, elapsed-time savings, or a real laboratory scheduling policy.

## Stop rule

After this run, do not retune the Jain selector, Ginkgo thresholds, overlap rule, missingness rule, information-gain comparator, or verdict gate against the result.

If external generalization is unsupported, record it and stop this cross-panel selector claim.
