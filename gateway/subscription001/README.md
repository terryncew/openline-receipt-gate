# GATEWAY-SUBSCRIPTION-001: subscription cancellation demo

A working, reproducible public demonstration of subscription cancellation
using the OpenLine gateway: Wallet (mandates), Receipt Gate (Envoy +
ext_authz + signed decision tokens), and verifiable receipts.

The enterprise gateway is the product. This is its first understandable
consumer-facing use case — not a separate product.

## The story

"You gave permission. You canceled it. Your payment system refuses the
next charge."

A fictional customer authorizes a fictional merchant (`merchant-acme`)
to charge up to $20. One $20 charge succeeds. The merchant double-bills,
tries $200, forges tokens, tampers with the request body — all fail.
The customer revokes. The next charge is refused by the receiver, and a
signed refusal receipt proves it. A final section shows the hard case
honestly: a token minted *before* revocation, presented *after* it, is
refused by the execution-time standing check — and executes without it
(the measured 60-second TTL window, disclosed not hidden).

## Run it

```bash
cd gateway
./subscription001/run_demo.sh
```

Needs: Python 3.12, `pip install -r requirements.txt`, and the Envoy
1.39.3 binary at `$ENVOY_BIN` (default `$HOME/workspace/.envoy-binary`).
The Docker Compose path (`compose/docker-compose.yml`, profile
`openline`) runs the same code; see `subscription001/EVIDENCE-docker.md`
for its verification status.

The script starts a local stack on 127.0.0.1 (Envoy :8080, authz :50051
with standing endpoint :50053, payment API :9000 with the standing check
ON, plus a contrast API :9001 with it OFF), runs the sequence, prints
each step with PASS/FAIL, tears everything down, and leaves evidence in
`subscription001/run/evidence/<timestamp>/`.

## What the demo establishes

- Mandate-scoped permission: the merchant can charge at most $20 per
  charge; $200 is refused at consequence time (`payment_limit_exceeded`).
- Revocation works: after `revoke-agent`, fresh charges are refused
  (`agent_revoked`) with zero ledger movement.
- Replay protection: the same signed charge twice, and the same
  decision token twice, each execute at most once.
- The receiver executes authorized params, never the request body.
- Forged/unsigned tokens are refused at the payment API.
- The refusal is a signed receipt, verifiable with the receiver public
  key alone (`verify_receipt_standalone.py`).
- With the execution-time standing check, a pre-revocation token
  presented post-revocation is refused; the residual window is the
  check-to-commit interval (measured, see EVIDENCE-races.md).

## What it does NOT establish

- The mandate model has per-charge caps but no per-period ("per month")
  recurrence limit. "Monthly" is the billing narrative; the enforced
  parameters are the per-charge cap and revocation. Two genuinely
  distinct $20 charges would both be authorized.
- Without the standing check, a pre-revocation token stays executable
  until its 60-second TTL. The demo shows this on the contrast
  instance. No instant-revocation claim is made.
- The payment API is simulated. No real money, merchants, or customers.
- This demo does not make any real bank or merchant honor OpenLine
  mandates. It works where the payment receiver integrates the
  receiver-owned check — that integration is the requirement.
- Production non-bypassability depends on network isolation (the API
  reachable only through Envoy), not just this code.
- Receipts prove the receiver's decision, not downstream effects the
  gateway never observed.

## Files

- `demo.py` — the sequence, assertions, and evidence writer.
- `merchant_sim.py` — the fictional merchant actor (legit + adversarial).
- `run_demo.sh` — one-command runner (setup, stack, demo, teardown).
- `verify_receipt_standalone.py` — independent receipt verifier.
- `VERIFY.md` — how an outside engineer reproduces and checks this.
- `docs/` — adoption guide, video storyboard, presentation, guarantees
  (public-facing materials; each marked DRAFT until demo evidence lands).
- `EVIDENCE-docker.md`, `EVIDENCE-races.md` — raw verification evidence.
