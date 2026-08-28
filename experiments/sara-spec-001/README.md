# SARA-SPEC-001 — Post-Task Standing Composition

**Verdict:** `SARA_EXTENSION_PARITY`

**Evidence tier:** `PAPER_SPEC_RECONSTRUCTION`

**Policy authority:** `NONE`

SARA already separates where an action came from from whether the user
authorized it. This experiment asks the next temporal question: after a task
ends, can SARA's own recorded state identify which completed decisions should
be reopened when one legitimate authorization root later loses standing?

The answer in this sealed reconstruction is yes.

## Frozen result

Two authorization roots produced two independent evidence records. Decision
`D1` relied on the record produced under `K1`; `D2` relied on `K2`. The task
ended before either post-task control ran.

| Arm | K1 revoked | No-op control | Scored? |
|---|---|---|---:|
| Published SARA | Out of scope after task end | Out of scope after task end | No |
| Broad recall | D1 reopen; D2 reopen | both preserved | Yes |
| Minimal SARA extension | D1 reopen; D2 preserve | both preserved | Yes |
| OpenLine selective recall | D1 reopen; D2 preserve | both preserved | Yes |

Every arm left the historical K/F/H and decision artifacts byte-for-byte
unchanged.

## Why arm 3 matters

The minimal extension persisted only SARA's published `K`, `F`, and `H`, then
added one standing update for `K1`. At evaluation time it scanned the existing
calls and observations in `H`. It stored no new edge type, reverse index,
descendant table, causal graph, or per-decision support record.

That full scan found the runtime value connecting `K1`'s successful action to
`D1`. It found the separate `K2` chain for `D2`. The same representation also
passed the no-op control.

OpenLine's persisted support relations reached the same answer more directly,
while broad recall reopened an unrelated decision. The result therefore
narrows the novelty claim: selective post-task standing recall was already
latent in SARA's K/F/H representation. This experiment does not establish a
unique OpenLine mechanism.

## Evidence boundary

The external source is SARA v1, submitted August 27, 2026. The paper explicitly
defines task-local K/F/H state and clears it when the task terminates. It also
describes H as successful audited calls and observations used for chain and
argument support.

No public author implementation was identified on the canonical paper record
or in the paper. The executable SARA arm here is consequently a paper-spec
reconstruction rather than a cold external integration. Published SARA receives
`OUT_OF_SCOPE_AFTER_TASK_END`; it is never scored as failing a feature it did
not claim.

Source: [When Tool Outputs Become Commands](https://arxiv.org/abs/2608.27146v1)

## Reproduce

```bash
python experiments/sara-spec-001/scripts/run_experiment.py
python experiments/sara-spec-001/scripts/verify_result.py
python -m unittest discover -s experiments/sara-spec-001/tests -v
python experiments/sara-spec-001/scripts/verify_release.py
```

The independent verifier imports neither the runner nor any arm. It verifies
the pre-outcome design lock, recomputes the representation-blind oracle from
the sealed fixture, audits the minimal-extension source boundary, and checks
all eight serialized arm/control rows.
