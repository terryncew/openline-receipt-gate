# JEV-WITNESS-VERCEL-003 — TERMINAL

**Verdict: BELOW_RECEIVER_THRESHOLD**

## Why this terminal state

The frozen acceptance harness
(`experiments/jev-witness-vercel-003/harness/run_acceptance.py`) was executed
exactly once on 2026-09-20 (run `20260920T204847Z`). Its single live Jev
evaluation — `POST https://ai-gateway.vercel.sh/v1/evaluate` with the frozen
003 request body (`model`, `state`, boolean `proceed` question,
`providerOptions.gateway.disallowPromptTraining: true`, and deliberately NO
`zeroDataRetention`), authenticated through the approved Secure Vault path
(authd surrogate exchange) — returned a real judgment:

- answer: `proceed`, type `boolean`, `probability` **0.88**
- request id: `providerMetadata.gateway.generationId` =
  `gen_01M30988PH1X8605DY9HD40861` (bound in evidence; never invented)
- model echoed in response body: `typesafe-ai/jev` (recorded as
  `model_reported`, never as a resolved version id)
- usage: `inputTokens` 369, `outputTokens` 21
- `providerMetadata.typesafe.confidence` present but empty `{}`; the boolean
  signal used `probability` per the documented rule
- `providerMetadata.gateway` also carried `cost` / `gatewayCost` /
  `marketCost` / `routing` / `surchargeCost` — all bound in the evidence

The returned signal (0.88) is below the frozen commit threshold (0.95) and
falls in the frozen QUARANTINE band (0.80–0.95). Per the frozen no-rerun rule —
one live judgment is one observation; never rerun until it crosses a
threshold — no second call was attempted. The receiver froze the disposition
the policy actually produced: **QUARANTINE, no protected effect**
(protected workspace empty, effect count 0). This is the honest
below-threshold outcome the preregistration anticipated.

Real Jev judgments returned: **one** (boolean, P=0.88). Real Jev attempts: **one**.
Spend: one call, 369 input tokens at $0.042/M ≈ $0.000016; output free.

## Cases

- **V1** PASS — PRECONDITION MISS recorded honestly (signal 0.88 < 0.95);
  policy mapping for the actual band verified: expected QUARANTINE, got
  QUARANTINE; effects 0.
- **V2** PASS — same authentic evidence after owner revocation → DENY; the
  receipt still verifies (historical authenticity; the judgment remains real
  but no longer establishes current permission).
- **V3** PASS — evidence bound to action A presented for action B → DENY via
  `jev_vercel_evidence_action_binding_mismatch`, before any effect; the
  substituted marker is absent.
- **V4** PASS — mutated state bytes → signature verification failure →
  `payload_hash_mismatch` → DENY.
- **V5** NOT_APPLICABLE — V1 did not COMMIT, so no receipt was consumed on
  the protected-effect path; nothing exists to replay. One-use ledger
  semantics were covered by pre-contact unit tests.

## Provenance actually exposed and bound

Exact state; exact typed question; exact gateway response
(answers/usage/warnings/providerMetadata); request id from
`providerMetadata.gateway.generationId`; gateway surface identifiers (host,
`/v1/evaluate` path, `zero_data_retention_requested=false`,
`disallow_prompt_training_requested=true`); receiver-side `witness_clock`
timestamp; exact proposed action + canonical action hash; evidence nonce;
schema `openline.jev_vercel_evidence.v1`. Never fabricated: resolved-model
identity, provider timestamps, request ids. No new authority primitive was
required; authority, standing, replay, action binding, and final disposition
remained existing OpenLine semantics.

## What was built and qualified (apparatus only)

- `olp_gate/integrations/jev_vercel_v3.py` — the VERCEL-003 adaptation of the
  v2 module; the sole delta is the providerOptions change
  (`disallowPromptTraining: true`, `zeroDataRetention` never sent) and the
  honest evidence flags. Schema `openline.jev_vercel_evidence.v1` unchanged.
- `tests/test_jev_witness_vercel_003.py` — 24 unit tests, synthetic
  v1/evaluate-shaped fixtures only (labeled synthetic; never presented as Jev
  judgments). All pass. No network, no key.
- `experiments/jev-witness-vercel-003/harness/run_acceptance.py` — frozen
  V1–V5 cases. Harness logic qualified pre-contact on stubs: COMMIT branch
  5/5 PASS (terminal PASS_JEV_WITNESS_VERCEL_003); below-threshold branch
  V1–V4 PASS, V5 NOT_APPLICABLE (terminal BELOW_RECEIVER_THRESHOLD);
  credential gate exits 2 with zero network calls. Stub artifacts removed.
- `examples/jev_vercel_witness/demo.py` + `README.md` — one-command public
  demo updated in place for the 003 request shape
  (`AI_GATEWAY_API_KEY=... python3 demo.py`); both state that the example
  uses synthetic non-sensitive data and does not request Vercel's ZDR control.

## Frozen references

- Baseline: `6d14506dcf4b26b1643b5edf9fd5cbe518e51631`
  (JEV-WITNESS-VERCEL-002 terminal tip; VERCEL-002's branch stays frozen)
- Experiment branch: `study/jev-witness-vercel-003` (unmerged, unpushed,
  nothing published)
- Preregistration: `experiments/jev-witness-vercel-003/preregistration.json`
  sha256 `fa24c6c9e39d78966d9d6ef8d28bf32dcf5107be79cda1979a50ac3dae9c74ab`
- Pre-contact freeze commit: `c097565`
  ("JEV-WITNESS-VERCEL-003: pre-contact freeze of preregistration and apparatus")
- Live run artifacts: `experiments/jev-witness-vercel-003/run/20260920T204847Z/`
  (`results.json` records `terminal: BELOW_RECEIVER_THRESHOLD`;
  `frozen_request.json` preserves the exact sent body;
  `gateway_response.json` preserves the exact gateway response)

## Data hygiene

Because provider-level Zero Data Retention was not requested, this run used
only the synthetic, non-sensitive fixture ("Two plus two equals four."
marker-file write). No secrets, credentials, repository content, personal
data, research text, customer information, or proprietary code were sent.
**This run does NOT establish a ZDR execution path.**

## Claim record

Bounded claim earned: a real Jev judgment (boolean, probability 0.88)
obtained through Vercel AI Gateway was bound as OpenLine evidence to an exact
proposed action. Receipt Gate treated the judgment as evidence rather than
permission: current owner authority and receiver policy controlled the
disposition (QUARANTINE — no protected effect occurred), and revocation,
action substitution, and evidence mutation were refused under the frozen demo.

NOT earned: the full claim ceiling (no COMMIT positive control was
demonstrated; receipt replay was not executed live — V5 not applicable, the
one-use ledger semantic holding only in pre-contact qualification); Zero Data
Retention; provider non-retention; Jev correctness; improved calibration;
official TypeSafe or Vercel partnership; universal safety; production
privacy; production safety; demand; adoption.

## Resume instructions

This terminal record stays frozen, never rescued. Nothing further is earned
under this label: the below-threshold observation is the result, not a
failure to retry against. A differently designed question is a fresh label,
not a rescue. Billing/plan state unchanged (hobby; no Pro upgrade was made or
is required for this label's design).
