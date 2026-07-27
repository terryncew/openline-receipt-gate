# DSM / Receipt Gate Warning-Time Benchmark

This benchmark asks one narrow question:

> How much warning exists between the first observable-state metric threshold crossing and the step where a corrupted handoff would cause a bad action?

It lives inside `openline-receipt-gate`; it is not a new product, score, receipt family, or receiver policy system. DSM supplies the disclosed representation. Receipt Gate supplies the receiver decision.

## Observable-state boundary

The metric entry point is:

```python
metrics_for_observation(seed, step, observation, previous_observation)
```

It cannot receive a case label, corruption name, injection step, bad-action step, or expected outcome. The corruption changes only the observable trace: one run drops an evidence item; the other introduces an unflagged constraint conflict. A label-swap probe verifies that changing the displayed case label does not change the metrics.

The same 20 held-out seeds are paired across control and both corruption conditions. Calibration uses a separate set of 40 clean seeds. This prevents condition-specific seed ranges from acting as a hidden label.

## The portable object

The portable object is not a supposedly universal threshold. It is the signed `calibration-profile.json`, which records:

- the exact graph, prompt, observable-fixture, and metric-source hashes;
- metric versions and input boundary;
- all 40 clean calibration traces and their hashes;
- the frozen thresholds;
- paired held-out seed design;
- profile creation, expiry, and future-skew limits;
- the Receipt Gate policy tested beside the profile;
- the actions the profile may govern and the changes that invalidate it.

The profile permits only `emit_early_warning` and `require_receipt_gate_reappraisal`. It cannot issue COMMIT, QUARANTINE, or DENY and cannot authorize downstream execution.

## Freeze chronology

The clean-only evidence, thresholds, signed profile, and signed freeze publication were created first. The freeze publication was then deposited in a separate private ChatGPT file-library custody surface. Only after that custody timestamp did the held-out runner execute.

This proves bounded private custody order across separate storage surfaces. It is not a public transparency log, GitHub timestamp, independent third-party attestation, or production trust anchor. The included `calibration-freeze-anchor.json` binds the custody metadata and is signed by a one-time synthetic witness whose private key is not distributed. Both verifiers pin that witness public key and the exact anchor payload hash; an anchor cannot select a replacement signer. The referenced Library object's existence and exact bytes remain an external evidence check.

## Calibration and held-out split

```text
40 clean calibration runs
20 paired held-out clean controls
20 paired held-out dropped-counterevidence runs
20 paired held-out unflagged-contradiction runs
```

The fixture contains 100 runs. That is an initial disclosed design choice, not a law, universal minimum, or substitute for power analysis on another stack.

## Formula

```text
warning_time_steps = bad_action_step - first_warning_step
gate_lead_time_steps = bad_action_step - gate_intervention_step
```

Positive means advance warning. Zero means detection at failure. Negative means late detection. Metric timing and Receipt Gate disposition are always reported separately.

## Run

```bash
python -m benchmarks.warning_time.run_benchmark \
  --output benchmarks/warning_time/results
python scripts/verify_warning_time_benchmark.py
```

The runner refuses held-out evaluation when the external custody anchor is missing or invalid. `--write-calibration` deliberately creates a new calibration version and must not be used to rewrite this frozen profile in place.

## Held-out result

```text
held-out clean false alarms          0 / 20
held-out missed corruptions          0 / 40
corruptions without advance warning  0 / 40
reference metric warning             +5 steps
reference Receipt Gate lead          +3 steps
final decisions                      20 COMMIT / 20 QUARANTINE / 20 DENY
```

The standalone verifier imports no warning-time benchmark modules. It parses the metric source signature and independently recomputes observable features, 40 calibration traces, thresholds, 60 held-out trajectories, decision receipt signatures, final dispositions, warning times, chronology, and artifact hashes.

## Claim boundary

The benchmark uses deterministic synthetic proxy values for κ, Δ_hol, and VKD over a chosen graph representation. Successful held-out separation shows predictive usefulness for two named failures on this exact synthetic agent stack. It does not prove the ontology is true, establish a universal threshold, provide live COLE scoring, validate production safety, or authorize any downstream action.
