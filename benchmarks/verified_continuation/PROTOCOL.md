# Verified Continuation — frozen first outside trial

This experiment asks one question:

> Given only a different inherited state, can the same receiving model reduce
> repeated exploration or terminal defects without exceeding the same budget?

It does **not** claim that the bundled synthetic traces are provider runs. They
exist only to prove that the evaluator, claim boundary, and DSM projection
behave correctly. The synthetic fixture must remain `UNDECIDABLE` even though
its OLP lane has better direct counts.

## Fixed controls

Run three clean checkouts with the same:

1. receiving model and model settings;
2. receiver configuration, including system prompt and sampling settings;
3. producer history from which the summary and capsule were derived;
4. starting repository tree;
5. task;
6. tool manifest;
7. terminal-test manifest; and
8. tool-call budget.

Change only the inherited state:

1. `self_summary` — the producer model's ordinary self-summary;
2. `no_prior_state` — no inherited state; and
3. `olp_capsule` — a Half-Life bounded capsule after receiver appraisal.

Every lane receives a distinct `run_id`. Do not expose final tests, a human
verdict, an evaluation report, or a completion label before the run ends.

## Direct outcome rule

The evaluator derives, rather than accepts:

- tool calls: trace length;
- repeated exploration: a repeated `search` or `read` of the same target;
- trace errors: events whose status is `error`; and
- terminal defects: terminal tests whose status is `FAIL`.

The continuation claim passes only when the OLP lane:

- stays within budget;
- is no worse than both baselines on repeated exploration and defects; and
- is strictly better than each baseline on at least one of those outcomes.

A synthetic fixture, absent provider attestation, mismatched control, unknown
field, discontinuous trace, missing terminal test, or invented derived metric
cannot pass.

## Separate authorization trial

The authorization claim is evaluated independently. Receipt Gate issues the
existing signed decision with an existing Verified Commit authorization bound
to:

- `git.update_ref`;
- `refs/heads/receiver-approved`;
- the exact expected old commit;
- the exact approved new commit;
- the Half-Life capsule, evidence, receiver policy, expiry, and one-use code.

The tool-side checker must block wrong-branch, changed-commit, expired,
replayed, and simultaneous duplicate uses before mutation. Exactly one bound
compare-and-swap update may execute.

## DSM boundary

DSM receives a display-only projection after Receipt Gate evaluates the
recorded traces. The fixture does not contain DSM's authoritative snapshot
state, so κ, Φ*, and VKD are explicitly `UNDECIDABLE`. DSM must not grade or
upgrade either claim.

## Reproduce

Harness conformance:

```bash
olp-gate evaluate-continuation \
  benchmarks/verified_continuation \
  --output /tmp/verified-continuation
```

For an outside trial, copy the three lane JSON files, replace only the recorded
run values, set `evidence_class` to `external_reproduction`, set the provider
execution attestation truthfully, and retain the frozen spec. Publish the raw
lane files, repository/task/tool/test hashes, evaluator output, and Receipt
Gate authorization evidence.
