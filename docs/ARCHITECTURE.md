# Architecture

## Pipeline

```text
risky action
  ↓
ReceiptGate context manager
  ↓
policy checks
  ↓
COMMIT / QUARANTINE / NO_BADGE
  ↓
hash-chained JSONL receipt
  ↓
CLI verify / badge / review
```

## v0.1.1 policy checks

The gate can require:

- evidence hash
- user intent confirmation
- grader receipt hash
- tool result hash

The policy is intentionally small.

## Fail-closed behavior

If a gate exits without `commit()`, `quarantine()`, or `no_badge()`, it emits a `NO_BADGE` receipt.

If a required proof field is missing during `commit()`, it emits a `QUARANTINE` receipt.

If an exception happens inside the context manager, it emits a `QUARANTINE` receipt and re-raises.

Missing or empty receipt files return `NO_BADGE`.

Malformed JSON returns `INVALID_CHAIN`.

## Privacy

Raw evidence is not stored by default.

Receipts store `evidence_hash` and `evidence_keys`.

Use `store_raw_evidence=True` only when you explicitly want raw evidence inside the receipt metadata.

## CLI

```bash
python -m olp_gate.cli verify receipts.jsonl
python -m olp_gate.cli badge receipts.jsonl
python -m olp_gate.cli review receipts.jsonl
```

## Design boundary

Receipt Gate is a primitive.

Eval Airlock, Agent Health Monitor, Memory Integrity, and future policies should plug into it instead of becoming separate worlds.
