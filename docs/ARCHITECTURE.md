# Architecture

## Two preserved layers

The repository contains two explicitly different mechanisms.

### Legacy action wrapper

The v0.1.1 `gate(...)` context manager emits a local hash-chained receipt. It remains useful for small examples and backwards compatibility. Its records are unsigned.

### Proof-to-policy gateway

The v0.2 gateway receives an already emitted source receipt and produces a separately signed decision receipt. It never edits or upgrades the source receipt.

```text
source bundle
  ├── OLP Wire Canon
  ├── Agent Receipts
  └── legacy Receipt Gate
        ↓
format adapter
        ↓
integrity / profile / provenance / coverage
        ↓
challenge, session, source, sequence, parent, freshness
        ↓
artifact hash + source commitment + policy assertion
        ↓
orthogonal outcome receipt
        ↓
policy evaluator
        ↓
signed decision receipt
```

## External authority

The policy file, trust store, signing key, and session ledger are CLI arguments. They are not accepted from the untrusted request body.

The request may carry source receipts, disclosures, evidence locations, an outcome receipt, and a previously issued binding. It cannot add a trusted key or change the policy.

## Assessments

Each assessment has its own status and reason codes:

```text
pass
fail
partial
unavailable
```

`unavailable` differs from `fail`. Missing evidence produces `UNDECIDABLE`; altered evidence produces `REJECTED`.

## Session state

`SessionLedger` issues a random one-time challenge bound to:

```text
run_id
session_id
sequence
parent_decision_hash
expected_source_hash
expiry
```

Successful validation consumes the nonce, remembers the source hash, advances the sequence, and records the decision hash as the next parent. Replayed or cross-run requests can receive signed rejection receipts without advancing the accepted decision chain.

## Semantic recomputation

The decision receipt carries the policy snapshot and every assessment. The Python and Node verifiers independently recompute:

```text
verdict
decision
reason codes
chain acceptance
policy hash
```

This catches a verdict, reason-code, or chain-acceptance rewrite that contradicts the included policy snapshot and assessment set, even if that inconsistent object is resealed with the gate key. The portable decision receipt does not include raw source or evidence, so these verifiers do not independently recompute the assessments themselves.
