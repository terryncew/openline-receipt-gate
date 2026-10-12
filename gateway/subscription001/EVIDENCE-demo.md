# EVIDENCE: subscription-cancellation demo run

Date: 2026-10-11 ~00:16 PDT. Commit: `experiment/gateway-subscription-001`
at the demo commit (see git log). Command:

```bash
cd gateway
./subscription001/run_demo.sh
```

Stack (local processes, this VM): Envoy 1.39.3 (:8080) -> OpenLine
authz service (:50051, standing endpoint :50053) -> mock payment API
(:9000, `GATEWAY_STANDING_CHECK=1`) plus a contrast API (:9001, check
OFF). Fresh receiver key, enforce-mode policy, empty sqlite DB per run.
Fictional customer, merchant (`merchant-acme`), funds.

## Result: 25/25 checks passed, exit 0

| Step | What was shown | Result |
|---|---|---|
| 1 | Owner authorizes merchant-acme, $20/charge cap, subscription-billing mandate | PASS |
| 2 | $20 charge through Envoy -> 200; treasury -2000, vendor +2000; API executed authorized params | PASS (3 checks) |
| 3 | Same signed charge replayed -> 403; decision token presented twice -> first 200, second 409; ledger moved exactly once | PASS (5 checks) |
| 4 | $200 charge -> 403 `payment_limit_exceeded`; ledger unchanged | PASS (3 checks) |
| 5 | Forged decision token -> 403; unsigned direct API call -> 403; tampered body ($20 signed, $999.99 claimed) -> API executed the authorized $20 | PASS (3 checks) |
| 6 | Owner revokes the mandate (`revoked=1` in registry) | — |
| 7 | Fresh $20 charge post-revocation -> 403 `agent_revoked`; ledger unchanged | PASS (3 checks) |
| 8 | Refusal receipt `gw-9fe97fd49a02` verifies with the receiver public key alone (standalone verifier, no gateway code); all gateway receipts verify | PASS (2 checks) |
| 9 | Pre-revocation token presented post-revocation WITH standing check -> 403 "no longer standing", $0 moved; WITHOUT the check (contrast :9001) -> 200 executes (the 60s TTL window, disclosed) | PASS (5 checks) |

Final ledger: treasury 992,000 / vendor 8,000 — exactly the four
authorized $20 movements (demo charge, single-use token, tampered-body
charge at authorized params, contrast late-token execution). Every
refused attempt moved $0.

## Failures encountered during the build

1. **Python grpc client vs IPv4 localhost (environment quirk, not a
   gateway defect).** Direct gRPC `Check` calls from Python to
   127.0.0.1:50051 failed with "Failed parsing HTTP/2 (got frame type
   101)" while Envoy's C++ ext_authz client and raw sockets worked
   fine. Isolated to the Python grpc client's IPv4 localhost path on
   this VM; `[::1]:50051` works. `demo.py` uses `[::1]` with a comment.
2. **Port contention with a parallel worker.** Another agent's test
   stack briefly held :50051 mid-run. The demo now fails fast if ports
   are occupied at startup (clear message, exit 2).

## What this run does NOT establish

- Per-period ("monthly") billing caps: the mandate enforces per-charge
  caps and revocation only. Two genuinely distinct $20 charges would
  both be authorized.
- The 60s window is closed only with the standing check enabled (the
  demo's configuration). Without it, pre-revocation tokens execute to
  TTL — demonstrated on the contrast instance.
- Simulated ledger. No real money, merchants, or banks.

## Artifacts (this directory)

- `transcript.json` — every check with request/response evidence.
- `refusal_receipt.json` — the signed refusal receipt.
- `receiver.pubkey` — verify it via
  `python3 ../verify_receipt_standalone.py "$(cat receiver.pubkey)" refusal_receipt.json`.
- `final_balances.json` — closing ledger state.
