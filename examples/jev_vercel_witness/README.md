# Jev Witness (Vercel) — one-command demo

A real Jev judgment through Vercel AI Gateway, bound as signed OpenLine
evidence to an exact proposed action. The receiver decides from current
authority and its own policy. Jev is evidence, never permission.

## Run it

```bash
AI_GATEWAY_API_KEY=... python3 demo.py
```

Needs Python 3.10+ and the `cryptography` package (`pip install cryptography`).
Run from the repository root so `demo.py` finds `olp_gate`, or from this
directory (it adds the repo root to `sys.path` itself).

You will see:

1. the exact proposed harmless action (write one marker file);
2. the live Jev judgment and its probability;
3. current authority state;
4. the receiver's decision (COMMIT / QUARANTINE / DENY);
5. whether the protected effect executed;
6. owner revocation;
7. the same judgment reused after revocation -> refused;
8. action substitution -> refused;
9. evidence mutation and receipt replay -> refused.

The demo makes exactly one live Jev call. It never reruns the call to chase
a threshold: if Jev returns a below-threshold probability, the receiver's
frozen policy decides QUARANTINE or DENY and the demo shows that instead.

Transport: the documented public route `POST https://ai-gateway.vercel.sh/v1/evaluate`
with `{"model": "typesafe-ai/jev", "state", "questions", "providerOptions":
{"gateway": {"zeroDataRetention": true}}}` in the body.

## What this does not claim

Jev correctness, improved calibration, any official TypeSafe or Vercel
partnership, universal safety, demand, adoption, or production readiness.
The full scientific record (frozen preregistration, acceptance cases V1–V5,
terminal receipt) lives in `experiments/jev-witness-vercel-002/`.
