# x402 Transaction Airlock

The Transaction Airlock applies Receipt Gate's existing receiver-owned
`COMMIT` and Verified Commit boundary to a normalized x402-style settlement.
It adds no receipt type, disposition, score, facilitator, wallet, or chain
implementation.

## Why it exists

Payment verification and settlement are different moments. A valid proof or
facilitator approval can become stale, refer to the wrong exact transaction, or
be replayed before the receiver's irreversible action. The airlock treats that
proof as evidence and asks a separate question:

> Does the receiver permit this exact settlement, under this policy, now?

## Signed issue-time bindings

The existing `proof_to_policy_decision_receipt` binds:

- tool, protected resource, run, capsule, evidence, receiver policy, expiry,
  and one-use code hash;
- scheme, network, asset, amount, recipient, payer, signature model,
  authorization hash, validity window, and nonce;
- execution template, program, ordered instructions, accounts, signers, fee,
  gas, and compute ceilings; and
- a hash of the declared requirements, payment, and verification time.

Unknown fields fail closed.

## Receiver execution boundary

Use `execute_x402_once()` with receiver-controlled providers:

```python
from olp_gate import VerifiedCommitLedger, execute_x402_once

result = execute_x402_once(
    VerifiedCommitLedger("state/x402-commit-ledger.json"),
    signed_decision,
    exact_action,
    one_use_code=receiver_held_code,
    trusted_gate_keys=[receiver_gate_public_key],
    snapshot_provider=read_fresh_receiver_state,
    settlement_executor=submit_exact_settlement,
    confirmation_provider=read_independent_confirmation,
    release_executor=release_protected_resource,
)
if not result["authorized"] or not result["settlement_confirmed"]:
    raise PermissionError(result["reason_codes"])
```

The snapshot provider must return the current authorization-authenticity,
nonce, payer balance, settleability, and the exact verification, requirements,
payment, and authorization hashes. The settlement callback must return its
transaction hash. The confirmation provider must observe that same transaction
as confirmed with the exact network, asset, amount, recipient, and nonce.
Before the snapshot, the shared ledger atomically reserves a hash of the
payment's scheme, network, asset, payer, signature model, and nonce. This
prevents two distinct valid COMMIT receipts from settling the same payment
sequentially or concurrently within that ledger's custody boundary.
The release callback receives the exact signed target and confirmation, and
must return a positive, target- and transaction-bound release acknowledgment;
callback return alone is not treated as successful release.
`resource_released` therefore means receiver-callback-confirmed release, not an
independent observation or rollback guarantee. A callback that performs an
effect and then returns an invalid acknowledgment may have acted even though
the result remains unconfirmed.

The permission is consumed before fresh appraisal. A failed or unavailable
snapshot cannot be retried with the same authorization.

## Frozen evidence

`benchmarks/x402_airlock` contains:

- the pinned paper metadata and paraphrased SR1–SR8 mapping;
- 56 frozen synthetic hostile and control cases;
- the deterministic runner and serialized report;
- hashes covering the adapter, ledger, fixtures, tests, report, and independent
  verifier; and
- a standard-library verifier that imports no candidate or benchmark module.

Run:

```bash
python benchmarks/x402_airlock/run_hostile_suite.py
python scripts/verify_x402_airlock.py
```

## Limits

The airlock cannot prove a receiver provider honest, turn an off-chain read and
on-chain transaction into one global atomic operation, recover a partially
executed external effect, or constrain bypass routes. A production receiver
must use trustworthy chain reads, sufficient finality, closed settlement
templates, durable shared consumption state, and one tool entry point.
