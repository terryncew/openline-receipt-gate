# Jain sequential assay selector — frozen discovery result

**Disposition: HYPOTHESIS-GENERATING SIGNAL. EXTERNAL CONFIRMATION REQUIRED.**

The selector was evaluated by leave-one-antibody-out replay on the same 137-antibody, 10-assay Jain 2017 panel used by CPG-001. Seventy antibodies contain at least one crossing of the already-frozen Jain Table-1 warning thresholds; 67 contain none.

The frozen continuous-value dynamic selector required **2.37 assays** on average to expose the first declared liability among the 70 liability-positive antibodies. Comparator means were **2.79** for the threshold-only dynamic logistic baseline, **2.97** for a uniformly random assay order in expectation, **3.06** for the leave-one-out greedy fixed-coverage order, and **3.26** for leave-one-out highest-prevalence-first.

At an assay budget of three, the continuous selector exposed **52/70 (74.3%)** of all declared-liability cases. Fixed prevalence exposed **38/70 (54.3%)** and greedy fixed coverage exposed **41/70 (58.6%)**.

The safety trapdoor moved in the same direction. Among candidates still showing no revealed liability after three assays, **18/85 (21.2%)** secretly contained a declared liability under the continuous selector, versus **32/99 (32.3%)** for fixed prevalence and **29/96 (30.2%)** for greedy fixed coverage. After five assays the continuous selector's residual hidden-liability rate was **5/72 (6.9%)**.

The scientific interpretation is narrow. Jain has now been used to discover and freeze the selector, so these numbers cannot establish generalization. "Liability" means only a frozen historical developability warning-threshold crossing, not clinical failure. "Cost" means number of assays, not dollars or elapsed time.

The next legitimate test is a separately sourced antibody panel. The model form, C=1.0 L2 regularization, liblinear solver, StandardScaler usage, feature encoding, tie break, Jain thresholds, 137-candidate identity, and the four existing comparator definitions are frozen. No further Jain tuning is allowed.
