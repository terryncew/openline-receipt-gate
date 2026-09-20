# JEV-WITNESS-VERCEL-001 — TERMINAL

**Verdict: INCONCLUSIVE_PROVIDER_RUNTIME**

## Why this terminal state

The frozen acceptance harness (`experiments/jev-witness-vercel-001/harness/run_acceptance.py`)
was executed exactly once on 2026-09-20. Its single live Jev evaluation call —
`POST https://ai-gateway.vercel.sh/v4/ai/evaluation-model` with the frozen
request (`state` + boolean `proceed` question), authenticated through the
approved Secure Vault path — was refused by the provider before any judgment
was returned:

- HTTP 403, `customer_verification_required`
- "AI Gateway requires a valid credit card on file to service requests. [...]
  to unlock your free credits."

The key itself authenticated (not a 401); the Vercel account behind it has no
billing instrument on file, so the gateway serves no model traffic. This is an
account/billing state on Terrynce's Vercel account, not an apparatus failure:
the request was well-formed (the gateway validated the route, protocol, and
auth), the frozen apparatus was fully qualified pre-contact, and the credential
plumbing (surrogate exchange) worked.

Per the frozen preregistration's provider-error rule, a provider/transport
error before any Jev judgment is returned freezes INCONCLUSIVE_PROVIDER_RUNTIME.
No synthetic response was substituted. No evidence was fabricated. No rerun
was attempted. Real Jev judgments returned: **zero**. Spend: **$0.00** (the
refused call and all pre-contact probes cost nothing).

## What was verified live (no model call)

- `typesafe-ai/jev` exists on the gateway (`GET /v1/models`): type
  `evaluation`, zero-data-retention `all`, no-training `all`, input
  $0.042/M tokens, output free.
- The evaluation endpoint is live and validating: `POST
  /v4/ai/evaluation-model` with headers `ai-gateway-protocol-version: 0.0.1`,
  `ai-evaluation-model-specification-version: 4`, `ai-model-id: typesafe-ai/jev`
  returns structured 400s for malformed bodies — route, protocol, and auth
  all confirmed end-to-end at $0.

## What was built and qualified (apparatus only)

- `olp_gate/integrations/jev_vercel.py` — Jev judgments via the Vercel AI
  Gateway evaluation-model endpoint as signed OpenLine evidence (schema
  `openline.jev_vercel_evidence.v1`), composing existing Receipt Gate
  signing, canonicalization, exact-action binding, standing/revocation, and
  receiver-owned policy machinery. No new authority primitive.
- `tests/test_jev_witness_vercel_001.py` — 18 unit tests, synthetic
  wire-shaped v4 fixtures only (labeled synthetic; never presented as Jev
  judgments). All pass. No network, no key.
- `experiments/jev-witness-vercel-001/harness/run_acceptance.py` — the frozen
  V1–V5 cases. Harness logic qualified against stub clients for both the
  COMMIT branch (5/5 PASS) and the below-threshold branch
  (BELOW_RECEIVER_THRESHOLD with V1–V4 PASS, V5 NOT_APPLICABLE), plus the
  credential gate (exit 2, zero network calls). Stub artifacts were removed.
- `examples/jev_vercel_witness/demo.py` — one-command public demo
  (`AI_GATEWAY_API_KEY=... python3 demo.py`); stranger-facing, reads the key
  from the environment.
- `~/workspace/skills/vercel-ai-gateway/` — minimal skill with
  `bin/evaluate.py`, the sanctioned auth path (authd surrogate exchange;
  raw key never in the environment, never printed).

## Frozen references

- Baseline main: `eebd62995b33ad434d2c00defbc6b2a8a9a732fc` (PR #100 merge)
- Experiment branch: `study/jev-witness-vercel-001` (unmerged, nothing published)
- Preregistration: `experiments/jev-witness-vercel-001/preregistration.json`
  sha256 `7ad464a3b5437704b84f1e9e3117f1a29e98af0faaebbbe70e060b271fe22bfc`
- Pre-contact freeze commit: `6c6c7b0`
  ("JEV-WITNESS-VERCEL-001: freeze preregistration and apparatus (pre-contact)")
- Live run artifacts: `experiments/jev-witness-vercel-001/run/<stamp>/`
  (`results.json` records `terminal: INCONCLUSIVE_PROVIDER_RUNTIME`)

## Claim record

No claim is earned. In particular: no Jev judgment was observed, so nothing
is said about Jev's probability output, calibration, or correctness; no
official TypeSafe or Vercel partnership; no demand; no adoption; no
production readiness.

## Resume instructions

The blocker is a human billing step on Terrynce's Vercel account (add a credit
card to unlock gateway credits); he handles billing himself. If he completes
it and explicitly re-issues the frozen order, the V1–V5 harness may be run
unchanged under a fresh label — this terminal record stays frozen. Until then,
nothing else is earned here.
