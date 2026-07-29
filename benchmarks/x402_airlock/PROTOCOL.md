# Frozen x402 Transaction Airlock hostile suite

Version: `x402-airlock-hostile-v1`
Source: Wang et al., *When HTTP 402 Meets the Blockchain*,
[arXiv:2607.19545v1](https://arxiv.org/abs/2607.19545)

## Question

Can the existing Receipt Gate `COMMIT` receipt and receiver-owned Verified
Commit ledger stop each frozen x402 mutation before the settlement callback,
and withhold the protected resource until a separately observed settlement
matches the submitted transaction?

## Fixed boundary

This suite introduces no receipt type, score, facilitator, wallet, chain
emulator, or authorization authority. It uses the existing signed
`proof_to_policy_decision_receipt` and one-use Verified Commit authorization.
The `x402_transaction_airlock/v1` settings profile is a normalized adapter
contract. Receiver-supplied snapshot, settlement, confirmation, and release
callbacks are explicit trust boundaries.

The suite paraphrases the paper's eight security rules in `RULES.json`.
`CASES.json` fixes the hostile inputs and expected observations. Fixture keys,
times, values, and case outcomes are synthetic.

## Order of operations

1. Receipt Gate validates the exact normalized payment and the signed receiver
   policy before issuing `COMMIT`.
2. The destination ledger verifies and atomically consumes that exact
   authorization and the payment nonce namespace, including across distinct
   signed COMMIT receipts.
3. The airlock obtains a fresh receiver-owned state snapshot and checks
   authorization authenticity, nonce, balance, settleability, and all
   verification bindings.
4. Only a passing fresh check reaches the settlement callback.
5. The protected resource remains withheld until a separate confirmation
   matches both the submitted transaction hash and the exact payment fields.
6. A resource callback receives that exact confirmation and must return a
   closed, positive acknowledgment binding the protected target and submitted
   transaction hash. Missing, negative, malformed, mismatched, or exceptional
   acknowledgments remain unconfirmed.

Permission is consumed before the fresh check. A stale or temporarily
unavailable snapshot therefore fails closed and requires a new receiver
authorization.

## Frozen falsifier

The settlement claim is rejected if any hostile case tagged `network`, `asset`,
`recipient`, `amount`, `expiry`, `replay`, or
`verification_settlement_divergence` reaches an additional settlement effect.
The release claim is rejected if an unconfirmed or mismatched settlement, or
an unconfirmed or mismatched resource-release acknowledgment, is reported as
having released the protected resource.

## Commands

```bash
python benchmarks/x402_airlock/run_hostile_suite.py
python scripts/verify_x402_airlock.py
python -m unittest tests.test_x402_airlock tests.test_x402_freeze -v
```

The first command exercises candidate code. The second is a standard-library
verifier that imports neither `olp_gate` nor benchmark modules.

## Claim boundary

A passing synthetic suite demonstrates the disclosed adapter's fail-closed
behavior under the frozen cases. It does not prove any x402 facilitator safe,
authenticate live chain data, guarantee global atomicity, prevent bypass of the
destination checker, or establish legal or production authorization. A
receiver must implement trustworthy snapshot and confirmation providers and
must route the irreversible effect through the airlock.
