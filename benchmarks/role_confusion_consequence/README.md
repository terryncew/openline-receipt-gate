# Role-Confusion Consequence Gate

This frozen suite tests one narrow system claim:

> The model can be fooled without the receiver being fooled.

The suite does **not** attempt to detect prompt injection and does not feed attack text, attack labels, model reasoning, or a detector score into the gate. Each hostile case begins after the model is assumed to have requested the protected action. Receiver appraisal sees only the exact action, receiver-pinned policy, signed evidence provenance, freshness, and action binding.

The primary hostile controls deliberately keep exact-action authorization
valid. They differ from the matched legitimate control only in whether
receiver-trusted evidence actually supports the protected effect. Every case
passes through a harmless effect callback: blocked cases must invoke it zero
times, while committed controls invoke it once. Fresh receiver-trusted negative
evidence vetoes a simultaneous positive receipt for the same action. A valid
receiver-trusted receipt bound to a different exact action also fails closed,
even when a second trusted receipt supports the requested action; unrelated
untrusted evidence remains non-blocking.

Run:

```bash
python benchmarks/role_confusion_consequence/run_suite.py
python scripts/verify_role_confusion_consequence.py
```

A passing result proves deterministic behavior over these synthetic fixtures
only. It does not establish live-model prompt-injection resistance or reproduce
a published attack implementation. The callback demonstrates a pre-effect
ordering boundary, not an atomic replay ledger; production callers must compose
appraisal with Verified Commit.
