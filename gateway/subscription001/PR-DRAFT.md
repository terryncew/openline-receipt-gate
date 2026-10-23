# GATEWAY-SUBSCRIPTION-001: subscription-cancellation demo

**Do not merge. For owner review only.**

## What this is

The enterprise gateway (`experiment/openline-gateway-001`, frozen at
38e33ce) stays the product. This branch adds its first understandable
consumer-facing use case: subscription cancellation through OpenLine
Wallet (mandates), Receipt Gate (Envoy + ext_authz + signed decision
tokens), and verifiable receipts. Not a separate product.

Base: 38e33ce (frozen baseline, history preserved untouched).

## The demo

```bash
cd gateway
./subscription001/run_demo.sh
```

One command. Fictional customer, fictional merchant (`merchant-acme`),
fictional funds. 25/25 checks passed on 2026-10-11:

- Owner authorizes the merchant to charge up to $20 (mandate).
- One $20 charge succeeds; the simulated ledger moves exactly $20.
- Duplicate billing (replayed charge, replayed token) is refused.
- A $200 increase is refused (`payment_limit_exceeded`).
- Forged tokens, unsigned API calls, and tampered request bodies fail.
- Owner revokes; the next charge is refused (`agent_revoked`), $0 moves.
- A signed refusal receipt is verified with the receiver public key
  alone (standalone verifier, no gateway code).
- The hard case, shown honestly: a token minted *before* revocation,
  presented *after* it, is refused by the execution-time standing check
  ($0 moved). Without the check it executes — the 60s TTL window,
  disclosed on a contrast instance, not hidden.

Evidence: `gateway/subscription001/EVIDENCE-demo.md` + `evidence/`
(transcript, refusal receipt, receiver pubkey, final balances).
Independent verification: `gateway/subscription001/VERIFY.md`.

## The 60-second window

Not closed to zero — narrowed. With the standing check (the demo's
configuration), the residual window is the check-to-commit interval
(measured ~75–116 ms). Without it, pre-revocation tokens execute to
their 60s TTL. Race tests: `gateway/tests/test_standing_races.py`;
results in `gateway/docs/STANDING-CHECK.md` and
`gateway/subscription001/EVIDENCE-races.md`. No instant-revocation
claim is made anywhere.

## Docker verification

`.github/workflows/gateway-subscription-001-docker.yml` runs the
compose stack for real on a GitHub Actions runner (the compose files
were previously written but never executed). Evidence:
`gateway/subscription001/EVIDENCE-docker.md`.

## Public materials (docs only, no claims beyond evidence)

- `gateway/subscription001/docs/ADOPTION-GUIDE.md` — for infra engineers
- `gateway/subscription001/docs/VIDEO-STORYBOARD.md` — 20–30s X video
- `gateway/subscription001/docs/PRESENTATION.md` — visual presentation frames
- `gateway/subscription001/docs/GUARANTEES.md` — established vs limitations

## Standing limitations (also in the docs)

- No per-period billing caps in the mandate model (per-charge caps +
  revocation only).
- Simulated payment API; no real money, merchants, or banks.
- Nothing here makes a real bank or merchant honor an OpenLine mandate —
  the receiver must integrate the check.
- Proof of a right is not the power to exercise it.
- Production non-bypassability depends on network isolation.

## Checklist for the owner

- [ ] Demo runs clean on your machine (`run_demo.sh`)
- [ ] Evidence reads honestly (EVIDENCE-demo.md)
- [ ] PR scope is right (branch only, no merge to main)
- [ ] Decide: keep the standing check opt-in or default-on for the gateway
