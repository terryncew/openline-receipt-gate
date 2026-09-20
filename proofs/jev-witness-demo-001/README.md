# Frozen evidence — JEV-WITNESS-DEMO-001

Terminal state: **PASS_JEV_WITNESS_DEMO_001**
Pre-contact freeze: commit `77a475a`
Preregistration SHA256:
`1514d52321e48b4be3660cad35ba606cd2ee81d05314ad6261349b778b869e82`

This directory is an index, not a copy. The frozen files live at their
original paths under `experiments/jev-witness-demo-001/` and are not
renamed or altered here. `MANIFEST.sha256` pins their exact bytes;
verify with:

```bash
sha256sum -c proofs/jev-witness-demo-001/MANIFEST.sha256
```

(run from the repository root)

## What the record contains

- `experiments/jev-witness-demo-001/TERMINAL.md` — the frozen terminal
  receipt: the live judgment, all five cases, the earned claim, the
  claims not earned, and the disclosed post-freeze metadata correction
  (a mistyped baseline-SHA tail in `preregistration.json`, corrected in
  commit `51b7df8`; no order element changed).
- `experiments/jev-witness-demo-001/preregistration.json` — the
  pre-contact freeze: model, request, the illustrative 0.80 risk-class
  policy, the exact protected action, authority setup, V1–V5
  expectations, rules, and claim ceiling.
- `experiments/jev-witness-demo-001/harness/frozen_request.json` — the
  exact request body sent to the gateway.
- `experiments/jev-witness-demo-001/harness/run_acceptance.py` — the
  frozen acceptance harness (V1–V5).
- `experiments/jev-witness-demo-001/run/20260920T205543Z/` — the live
  run: `gateway_response.json` (the real Jev response), `results.json`,
  `terminal_output.txt`, `consumed_evidence.jsonl`,
  `decision_receipts.jsonl`, and the protected marker
  `protected_workspace/jev-ok.txt`.

## The observation (verbatim from the terminal receipt)

- One live Jev call, 2026-09-20 20:55:43Z, `POST
  https://ai-gateway.vercel.sh/v1/evaluate`, model `typesafe-ai/jev`,
  generation `gen_01M309MZ9NJDGAP4MD2N9KV6TV`.
- Judgment: boolean, proceed, P(true) = 0.84.
- V1: COMMIT, exactly one effect. V2: after owner revocation, the same
  authentic evidence → DENY, no second effect. V3: action substitution
  → DENY. V4: evidence mutation → verification failure → DENY. V5:
  receipt replay → DENY.

The public entry point for the runnable demo is
`examples/jev_witness/`; its `demo.py` is a byte-identical copy of the
staged product demo from the frozen experiment.

## Prior labels (frozen, untouched by this demo)

- JEV-WITNESS-001 — INCONCLUSIVE_APPARATUS @ `b0640cd`
- JEV-WITNESS-002 — NOT STARTED
- JEV-WITNESS-VERCEL-001 — INCONCLUSIVE_PROVIDER_RUNTIME @ `ad8270b`
- JEV-WITNESS-VERCEL-002 — INCONCLUSIVE_PROVIDER_RUNTIME @ `6d14506`
- JEV-WITNESS-VERCEL-003 — BELOW_RECEIVER_THRESHOLD @ `9ec76ba`
