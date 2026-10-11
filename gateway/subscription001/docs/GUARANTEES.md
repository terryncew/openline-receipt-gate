# OpenLine Gateway: Guarantees

Demo evidence landed 2026-10-11 (GATEWAY-SUBSCRIPTION-001, 25/25 checks,
`gateway/subscription001/EVIDENCE-demo.md`). Claims below are as narrow
as that evidence. The Limitations section is standing: it holds
regardless.

## Established (demo-measured)

1. Mandate-scoped authority. The owner grants an agent a mandate with
   action types, targets, and a payment ceiling. The worker cannot widen
   it, grant itself permission, or select the enforcement mode. Measured:
   a $200 charge against a $20 mandate was refused with
   `payment_limit_exceeded`; forged and unsigned tokens were refused at
   the payment API.

2. Replay protection. Each request carries a nonce. The gateway records
   nonces in sqlite. A replayed request is refused. (Baseline evidence:
   scenario "replay: 2nd identical denied" PASS in the gateway suite.)

3. Signed decision binding. On allow, the receiver mints a signed,
   single-use decision token carrying the authorized params. The API
   verifies the signature and executes exactly those params, never the
   request body.

4. Revocation with a measured bound. Revoking an agent stops new
   authorizations immediately (measured: the first fresh charge after
   revocation was refused with `agent_revoked`, $0 moved). In-flight
   decision tokens remain valid up to their 60 s TTL without the
   standing check (measured: a pre-revocation token presented
   post-revocation executed on the contrast API). With the
   execution-time standing check enabled (the demo's configuration),
   the same late token was refused with $0 moved; the residual window
   is the check-to-commit interval (single measured sample 116 ms on
   demo hardware; prior investigation measured ~75 ms steady state —
   see `gateway/docs/STANDING-CHECK.md`). No instant-revocation claim
   is made.

5. Independently verifiable receipts. Every decision is a signed receipt
   in the gateway database. `gateway_admin.py verify-receipts` confirms
   the chain without trusting the gateway's word for it.

6. Fail-closed evaluation. Every consequential request passes through
   the ext_authz filter before reaching the API. If the authz service is
   unreachable, requests are rejected.

Latency overhead of the bundle vs the OPA baseline: ~140 ms p50 on
the build hardware (Python + durable sqlite), dominated by per-check
durable writes. See `gateway/bench/HEAD-TO-HEAD.md`. Not separately
re-measured on the demo hardware; no demo latency claim is made beyond
the single 116 ms check-to-commit sample above.

## Limitations (standing)

1. Revocation is not instant. New authorizations stop at once. Tokens
   already minted live to their 60 s TTL. No instant-revocation claim is
   made.

2. Receipts prove decisions, not downstream effects. A receipt proves
   what happened and who authorized what. It does not prove what a
   downstream system did with the decision.

3. The gateway does not substitute for network isolation. Production
   non-bypassability depends on deployment: the gateway must be the only
   path to the API.

4. No merchant or bank is forced to honor a mandate. A receiver that
   never integrated OpenLine will not refuse a charge on the strength of
   a mandate. The refusal in the demo happens because the demo receiver
   enforces.

5. Proof of a right is not the power to exercise it. OpenLine settles
   what happened and who authorized what. It does not rewrite the
   commercial terms underneath.

6. The demo API is simulated. No real money, no real credentials, no
   real merchant or bank participated. Any presentation of the demo must
   say so.
