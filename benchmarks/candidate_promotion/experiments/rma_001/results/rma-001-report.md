# RMA-001 — Reality Measurement Allocation

**Verdict:** `NO_MEASUREMENT_ROUTING_SIGNAL`  
**Evidence grade:** `EXPLORATORY_HELD_OUT_SIMULATION`  
**Policy authority:** `NONE`

## Question

Can prediction help decide **where reality should look next** even when it cannot safely replace reality?

## Evidence boundary

The model never declares VETO or RETAIN. It only chooses the next assay. VETO requires an observed failure; RETAIN requires all three observed clean.

## Cohort

- Source rows: **246**
- Evaluable antibodies: **197**
- Clean: **143**
- Bad: **54**
- Cohort receipt: `f2c079f26f316e5b46607b5dd7b6c4994514ff77f010505e153398ca4791fc5a`

## Unit-cost measurement results

| Policy | Assay reveals | Final concordance |
|---|---:|---:|
| Exhaustive | 591 | 1.000 by full measurement |
| Best fixed order, chosen on training folds | 518 | 1.000 |
| History-only adaptive | 518 | 1.000 |
| Sequence + history adaptive | 514 | 1.000 |
| Oracle upper bound | 483 | 1.000 |

## Paired savings

- Best static vs exhaustive: **12.4%**
- History adaptive vs best static: **0.0%** (95% bootstrap CI 0.0% to 0.0%)
- Sequence adaptive vs best static: **0.8%** (95% bootstrap CI -2.1% to 3.7%)
- Sequence adaptive vs history adaptive: **0.8%** (95% bootstrap CI -2.1% to 3.7%)
- Sequence adaptive vs exhaustive: **13.0%**
- Oracle vs exhaustive: **18.3%**

## Frozen bar

- Sequence routing signal: >=10% fewer reveals than best static, CI lower bound >0; AND >=5% fewer than history-only adaptive, CI lower bound >0.
- History-only routing signal: >=10% fewer reveals than best static, CI lower bound >0.
- Every executable policy must have 100% final-disposition concordance.

## Interpretation

Adaptive routing did not clear the frozen savings bar over the strongest fixed-order baseline. On this three-assay substrate, there is no measurement-allocation mechanism worth promoting.

## Prior result

NO_PILOT_VETO_SIGNAL on 197 evaluable GDPa1 antibodies (143 clean / 54 bad). Direct learned veto authority is therefore closed under its frozen stop rule.

## Claim boundary

No clinical-ranking claim. No sequence-only veto claim. No dollar-savings claim. This is a held-out GDPa1 simulation of measurement allocation under unit assay cost.

## Stop rule

If NO_MEASUREMENT_ROUTING_SIGNAL, close the three-assay routing hypothesis on this substrate. Do not rescue it by changing thresholds, source cohort, fold assignment, savings bars, or cost weights after observing the result.

