# Warning-Time Calibration and Held-Out Protocol v2

1. Load `scenario.json`, fixed prompts, metric versions, and the declared seed partitions.
2. Require calibration and held-out seeds to be disjoint.
3. Derive `calibration-evidence.json` from clean calibration runs only.
4. Derive `thresholds.json` from that calibration evidence only.
5. Build and Ed25519-sign `calibration-profile.json`, binding the graph structure, prompt hashes, metric source and versions, calibration evidence, thresholds, seed split, and the limited actions the thresholds may govern.
6. Freeze all three artifacts before any held-out run executes.
7. Refuse to test if the frozen profile or its bound artifacts do not reproduce exactly.
8. Run held-out clean controls and each corruption separately; never combine injections.
9. Record κ, Δ_hol, and VKD at each step with deterministic timestamps.
10. Evaluate Receipt Gate only at declared handoff boundaries.
11. In observe-only mode, continue to the hypothetical bad-action step.
12. In enforcement mode, stop at the first non-COMMIT decision.
13. Report held-out warning time, clean false alarms, missed corruptions, and final Receipt Gate decisions separately.

The profile may trigger an early warning or require Receipt Gate reappraisal. It may not issue COMMIT, QUARANTINE, DENY, authorize a tool call, or retire a model.

Changing the graph, prompts, metric implementation/version, policy, calibration evidence, thresholds, or seed partition requires a new signed profile. Held-out success establishes predictive usefulness on the named fixture only; it does not prove the metric ontology is true.
