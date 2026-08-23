# CPG-001 — Candidate Promotion Gate

## Question
Does receiver-owned hard-veto promotion reduce masked, predeclared developability liabilities without destroying candidate yield or held-out assay quality, compared with composite ranking over the same measured candidates?

## Boundary
This is a promotion-authority experiment, not a clinical-success predictor and not evidence that any individual assay is clinically dispositive. “Liability” means a condition declared by the frozen receiver policy.

## Arms
1. **Control:** sort the fixed cohort by the supplied rank score and take top K.
2. **Treatment:** evaluate the same cohort and evidence under the frozen candidate-promotion profile. Only `COMMIT` candidates are eligible, then use the **same rank score** to take top K.

The ranker does not see or modify the policy after candidate outcomes are available.

## Gate semantics
- threshold failure: `DENY`
- missing / `UNKNOWN` / stale required evidence: `QUARANTINE`
- identity, target, units, method, revocation, duplicate-receipt, or evidence-integrity failure: `DENY`
- complete current passing evidence: `COMMIT`

A passing dimension can never compensate for a failing veto dimension.

## Identity binding
Every assay receipt binds `candidate_id + sequence_sha256 + construct_id + batch_id`, plus target, assay type, measurement, units, method/version, verifier, timestamp, and raw evidence SHA-256.

## Non-tautological evaluation
Gate dimensions are not enough to declare success. At least one measured assay must be held out of promotion and preregistered as an evaluation dimension. Report held-out pass rate and selection yield alongside masked declared-liability promotion.

## Historical replay
- **Primary:** Jain et al. 2017, 137 matched-IgG1 clinical-stage antibodies, 12 assays.
- **Replication:** Ginkgo GDPa1. The dataset is gated and its public card currently contains a row-count/version ambiguity; bind the exact accepted artifact and SHA-256 before replay.
- **Prior art:** TAP is treated as threshold-style developability flagging, not as Receipt Gate authority.

Real-data thresholds and gate/held-out assay split must be frozen before outcome inspection. No retrospective threshold tuning is allowed in the confirmatory run.

## Evidence-class boundary
Historical replay is **dataset-bound evidence**, not native receipt evidence. CPG-001 must report these separately. The Jain replay can test whether a frozen veto policy changes selection on published measurements. It cannot prove that the 2017 assays carried sequence/construct/batch receipts that did not exist. Native identity, stale/revoked evidence, duplicate receipts, and UNKNOWN handling are therefore tested in the adversarial policy suite.

## Confirmatory Jain split
Use the four property groups published in Jain Table 1 as fixed leave-one-group-out folds. In each fold, one entire group is withheld from Gate eligibility and used as orthogonal survivor evaluation. Report 10%, 25%, and 50% selection budgets. This prevents choosing one flattering held-out assay or one flattering top-K after seeing results.
