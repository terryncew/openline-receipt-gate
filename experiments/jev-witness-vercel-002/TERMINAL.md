# JEV-WITNESS-VERCEL-002 — TERMINAL

**Verdict: INCONCLUSIVE_PROVIDER_RUNTIME**

## Why this terminal state

The frozen acceptance harness (`experiments/jev-witness-vercel-002/harness/run_acceptance.py`)
was executed exactly once on 2026-09-20. Its single live Jev evaluation call —
`POST https://ai-gateway.vercel.sh/v1/evaluate` with the frozen request body
(`model`, `state`, boolean `proceed` question, `providerOptions.gateway.zeroDataRetention: true`),
authenticated through the approved Secure Vault path (authd surrogate exchange) —
was refused by the provider before any judgment was returned:

- HTTP 403, `ZdrUnauthorizedError`
- "Zero Data Retention (ZDR) is only available for Pro and Enterprise plans.
  Current plan: hobby. Please upgrade your plan [...] to access this feature."

The key itself authenticated (not a 401); the request was well-formed and the
route live and validating (the gateway parsed the body and rejected the ZDR
opt-in as a plan feature, returning a `generationId` in providerMetadata even
on the refusal). But the frozen request — which discloses and sends the
per-request `zeroDataRetention: true` opt-in — cannot be served on Terrynce's
hobby-plan Vercel account. This is an account-plan state, not an apparatus
failure: the frozen apparatus was fully qualified pre-contact, and the
credential plumbing (surrogate exchange) worked.

Per the frozen preregistration's provider-error rule, a provider/transport
error before any Jev judgment is returned freezes INCONCLUSIVE_PROVIDER_RUNTIME.
No synthetic response was substituted. No evidence was fabricated. No rerun
was attempted (the no-rerun rule: one live judgment is one observation; a
provider refusal before any judgment is not an observation to retry against).
Real Jev judgments returned: **zero**. Spend: **$0.00** (the refused call and
all pre-contact probes cost nothing).

## What was verified live (no model call)

- `typesafe-ai/jev` exists on the gateway (`GET /v1/models`): type
  `evaluation`, zero-data-retention `all`, no-training `all`, input
  $0.042/M tokens, output free (listing fields; plan-level ZDR enforcement
  is separate from the listing).
- The public evaluation endpoint is live and validating: `POST /v1/evaluate`
  with an empty body returns HTTP 400 `invalid_request_error` ("model:
  Invalid input: expected string, received undefined") — route live, $0, no
  model call.
- The refusal is plan-scoped, not auth-scoped: `permission_denied` /
  `ZdrUnauthorizedError` after successful authentication; a generationId was
  issued for the refused request (`gen_01M304TTS5EYAHY5FCSP5NEEX6`).

## What was built and qualified (apparatus only)

- `olp_gate/integrations/jev_vercel_v2.py` — Jev judgments via the public
  `POST /v1/evaluate` route as signed OpenLine evidence (schema
  `openline.jev_vercel_evidence.v1` unchanged); `build_evaluate_request` for
  the frozen body; `extract_request_id_v2` for
  `providerMetadata.gateway.generationId`; explicit ZDR opt-in in the request;
  surface identifiers record host + `/v1/evaluate` path +
  `zero_data_retention_requested`; never fabricates resolved-model identity or
  provider timestamps; witness clock labeled receiver-side. Composes existing
  Receipt Gate machinery; no new authority primitive.
- `tests/test_jev_witness_vercel_002.py` — 23 unit tests, synthetic
  v1/evaluate-shaped fixtures only (labeled synthetic; never presented as Jev
  judgments). All pass. No network, no key.
- `experiments/jev-witness-vercel-002/harness/run_acceptance.py` — the frozen
  V1–V5 cases. Harness logic qualified against stub clients for the COMMIT
  branch (5/5 PASS) and the below-threshold branch (BELOW_RECEIVER_THRESHOLD
  with V1–V4 PASS, V5 NOT_APPLICABLE), plus the credential gate (exit 2, zero
  network calls). Stub artifacts were removed.
- `examples/jev_vercel_witness/demo.py` — one-command public demo updated in
  place for the v2 route (`AI_GATEWAY_API_KEY=... python3 demo.py`);
  stranger-facing, reads the key from the environment.

## Frozen references

- Baseline: `ad8270b2aeaaab39d3608b3553b2db512666ba61`
  (JEV-WITNESS-VERCEL-001 terminal tip; VERCEL-001's branch stays frozen)
- Experiment branch: `study/jev-witness-vercel-002` (unmerged, unpushed,
  nothing published)
- Preregistration: `experiments/jev-witness-vercel-002/preregistration.json`
  sha256 `c3ecea26617884a5b5382526663e82febca2287bb7f4fe7485ec98462641c837`
- Pre-contact freeze commit: `bd493c7`
  ("JEV-WITNESS-VERCEL-002: pre-contact freeze of preregistration and apparatus")
- Live run artifacts: `experiments/jev-witness-vercel-002/run/<stamp>/`
  (`results.json` records `terminal: INCONCLUSIVE_PROVIDER_RUNTIME`;
  `frozen_request.json` preserves the exact sent body)

## Claim record

No claim is earned. The claim ceiling (a real Jev judgment through Vercel AI
Gateway bound as OpenLine evidence, with revocation, substitution, mutation,
and replay refused under the frozen demo) was not earned: no Jev judgment was
observed. Nothing is said about Jev's probability output, calibration, or
correctness; no official TypeSafe or Vercel partnership; no demand; no
adoption; no production readiness.

## Resume instructions

The blocker is a plan/billing state on Terrynce's Vercel account: the frozen
request sends the per-request `zeroDataRetention: true` opt-in, which the
gateway serves only for Pro and Enterprise plans; the account is on hobby.
Billing is his lane. If he upgrades the plan (or explicitly re-issues a frozen
order whose request the account can serve), the experiment may run under a
FRESH label — this terminal record stays frozen, never rescued. Until then,
nothing else is earned here.
