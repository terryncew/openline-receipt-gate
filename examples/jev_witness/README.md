# A judgment is not a permission

Jev (TypeSafe) gave a small, harmless action an 84% green light.
The authorized action ran once.
Authority was then revoked.
The same authentic Jev judgment and the same action were presented again.
The second effect did not occur.

That is the whole demo. Jev supplies a judgment. Receipt Gate decides
whether that judgment currently earns this exact consequence.

## What happened

One live Jev call through Vercel AI Gateway (model `typesafe-ai/jev`,
2026-09-20) returned a real judgment: *proceed*, boolean, probability
0.84. The receiver's frozen policy for this low-risk, reversible action
class commits at 0.80 or above, so the receiver committed — exactly one
effect: the literal text `jev-ok` written to a temporary marker file.

Then the owner revoked the agent's standing. The identical signed Jev
evidence, for the identical action, was presented again. The receiver
refused: DENY. No second effect.

The same run also refused: the evidence presented for a different action
(substitution), the evidence with its bytes altered (mutation), and the
consumed receipt replayed on the protected-effect path (replay).

The Jev judgment stayed authentic through all of it. Its authority to
cause the protected effect did not.

## Why this is different from just checking the Jev score

Checking a score leaves the decision in the caller's hands, with nothing
binding the judgment to the action, the moment, or the authority. Here
the judgment is sealed into a signed receipt bound to the exact action;
the receiver independently verifies the seal, the binding, and the
agent's current standing before any effect happens. Revoke the standing
and the same judgment stops working — without touching the model.

## How to run it

```bash
AI_GATEWAY_API_KEY=... python3 demo.py
```

Needs Python 3.10+ and the `cryptography` package
(`pip install cryptography`). Run from this directory.

One real Jev call, one real judgment, then the receiver decides from
current authority and its own policy. You will see something like:

```
Jev: proceed, 0.84
Receiver policy: COMMIT
Effect: executed

Owner revoked the agent.

Same Jev judgment. Same action.
Receiver: DENY
Effect: not executed
```

followed by the substitution, mutation, and replay refusals.

The key is used for this demo call only; it is never printed or stored.
Without a key the demo exits with a clean message instead of faking a
call. The request uses only synthetic, non-sensitive data and does NOT
request Vercel's Zero Data Retention control (`zeroDataRetention` is
Pro/Enterprise-only), so this does not establish a ZDR execution path.
It sends `disallowPromptTraining=true` instead.

## Where is the frozen evidence

The complete frozen record — preregistration, acceptance cases V1–V5,
terminal receipt, the live gateway response, and decision receipts —
lives in this repository:

- `../../proofs/jev-witness-demo-001/` — index and hash manifest
- `../../experiments/jev-witness-demo-001/` — the frozen experiment
  (preregistration, harness, live run artifacts)

Verify the frozen files yourself:

```bash
sha256sum -c proofs/jev-witness-demo-001/MANIFEST.sha256
```

(run from the repository root)

## What this does NOT prove

This is one judgment, on one question, through one receiver policy, for
one trivial reversible action, on one day. It does not show that Jev is
correct, well calibrated, safe, or unsafe. It is not an official
TypeSafe or Vercel integration. It claims nothing about Zero Data
Retention, provider non-retention, production privacy, production
safety, demand, or adoption.

The 0.80 commit threshold is illustrative receiver policy for this
low-risk risk class — not a claim about Jev calibration. TypeSafe's own
public framing is that the surrounding code chooses the confidence
thresholds for autonomous action versus review; they prescribe no
universal cutoff. The demo never reruns the call to chase a threshold:
if Jev returns below 0.80, the receiver DENYs and the demo shows that
instead.

What it does show: a receiver can choose what confidence earns for a
particular consequence. Jev supplies the judgment. OpenLine binds it to
the exact action and current authority.
