# Jev + OpenLine product demo — JEV-WITNESS-DEMO-001

A receiver can choose what confidence earns for a particular consequence.
Jev supplies the judgment. OpenLine binds it to the exact action and
current authority.

## Run it

```bash
AI_GATEWAY_API_KEY=... python3 demo.py
```

Needs Python 3.10+ and the `cryptography` package (`pip install cryptography`).
Run from the repository root so `demo.py` finds `olp_gate`, or from this
directory (it adds the repo root to `sys.path` itself).

One real Jev call, one real judgment, then the receiver decides from
current authority and its own policy. The protected action is trivial and
reversible: the literal text `jev-ok` written into a temporary marker file.

You will see something like:

```
Jev: proceed, 0.xx
Receiver policy: COMMIT
Effect: executed

Owner revoked the agent.

Same Jev judgment. Same action.
Receiver: DENY
Effect: not executed
```

followed by the refusal of action substitution, evidence mutation, and
receipt replay.

The >= 0.80 commit threshold is illustrative receiver policy for this
low-risk/reversible risk class — not a claim about Jev calibration or
safety. The demo never reruns the call to chase a threshold: if Jev
returns below 0.80, the receiver DENYs and the demo shows that instead.

Transport: the documented public route `POST https://ai-gateway.vercel.sh/v1/evaluate`
with `{"model": "typesafe-ai/jev", "state", "questions", "providerOptions":
{"gateway": {"disallowPromptTraining": true}}}` in the body.

Data hygiene: the example uses synthetic, non-sensitive data only and does
NOT request Vercel's Zero Data Retention control (`zeroDataRetention` is
Pro/Enterprise-only). It does not establish a ZDR execution path.

## What this does not claim

Jev correctness, improved calibration, any official TypeSafe or Vercel
partnership, Zero Data Retention, provider non-retention, production
privacy, production safety, demand, or adoption.

The full frozen record (preregistration, acceptance cases V1–V5, terminal
receipt) lives in `experiments/jev-witness-demo-001/`.
