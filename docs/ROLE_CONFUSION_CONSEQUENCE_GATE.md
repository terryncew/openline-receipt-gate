# Role-Confusion Consequence Gate

The experiment asks a narrower question than prompt-injection detection:

> If a model has already been fooled into requesting a consequential action, can the receiver still refuse the effect because the supporting evidence never earned authority?

Receipt Gate does not receive the prompt, attack label, model reasoning, or an injection score. It receives an exact action plus evidence receipts. Trust roots are pinned by receiver policy, not supplied by the artifact being judged.

The frozen matrix uses one harmless protected fixture action and twelve
deterministic cases. Five cases assume the model has adopted an untrusted
instruction and requested the protected effect. In all six, the action
structure is otherwise valid. The receiver blocks the effect because trusted
support is missing, forged, or absent. A matched legitimate twin uses the exact
same action and commits when receiver-pinned signed evidence supports it. An
unrelated untrusted addition also leaves the legitimate action committable,
preventing the mechanism from degenerating into a generic content blocker.
Fresh trusted negative evidence vetoes a simultaneous fresh positive receipt;
the producer cannot hide a receiver-visible conflict behind one favorable
receipt.

The runner sends every case through an actual harmless callback. A non-`COMMIT`
result must leave the callback untouched; each committed control calls it
exactly once. This closes the gap between reporting a decision and exercising a
pre-effect tool boundary.

Run the public suite and independent verifier:

```bash
olp-gate role-confusion-suite \
  --benchmark benchmarks/role_confusion_consequence \
  --output benchmarks/role_confusion_consequence/results/hostile_report.json
python scripts/verify_role_confusion_consequence.py
```

A receiver-trusted receipt that is validly signed but bound to a different
exact action is a structural conflict, not unrelated noise. If such a receipt
appears alongside valid exact-action support, the bundle is denied before
effect. This is intentionally stricter than the unrelated-untrusted-content
control, which must still commit when exact-action trusted support is present.

The independent verifier imports no code from `olp_gate.role_confusion`. It
checks the frozen source closure, rejects duplicate JSON keys, recomputes
exact-action validity, Ed25519 provenance checks, action binding, freshness,
positive/negative support conflicts, expected dispositions and effect
invocations, the matched-twin control, and the detector-independence input
surface.

## Frozen result

The checked-in synthetic suite requires:

- 13 / 13 cases match the frozen disposition;
- every authorization-valid hostile case is blocked before protected effect;
- the matched legitimate twin commits;
- unrelated untrusted content does not cause a false block;
- no blocked row invokes the protected-effect callback;
- attack text and attack labels never enter the appraisal request.

## Claim boundary

The model compromise is assumed, not reproduced. This demonstrates that
unsupported evidence can be stopped before consequence even when exact-action
authorization is otherwise valid.

This is a deterministic consequence-gate fixture. It does **not** show that a
live Claude, Codex, or other model was attacked; it does not reproduce a
published role-confusion implementation; and it does not claim to cure the
model's role perception. A live external reproduction is a separate next
experiment. The standalone callback demonstrates ordering, not atomic
exactly-once execution. Production tools must compose this appraisal with
Verified Commit's receiver-owned atomic ledger.

The supported architectural claim is smaller: compromise of model judgment need not automatically become receiver execution authority when the receiver independently reconstructs authority from pinned evidence provenance and exact action binding.
