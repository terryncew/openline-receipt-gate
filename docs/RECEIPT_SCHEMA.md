# Receipt Schema

## JSONL receipt

```json
{
  "schema": "openline.receipt_gate.v0.1.1",
  "receipt_id": "uuid",
  "parent_hash": "previous receipt hash or null",
  "timestamp": 0.0,
  "action_type": "tool_call",
  "claim": "Search customer records",
  "evidence_hash": "sha256...",
  "result_hash": "sha256...",
  "status": "committed",
  "decision": "COMMIT",
  "policy_flags": [],
  "next_use_note": "Use receipt_hash for audit, handoff, or replay checks.",
  "metadata": {
    "evidence_keys": ["query_hash"],
    "raw_evidence_stored": false
  },
  "receipt_hash": "sha256..."
}
```

## Decisions

```text
COMMIT
QUARANTINE
NO_BADGE
```

## Policy flags

Common flags:

```text
missing_evidence_hash
missing_result_hash
missing_user_intent
missing_grader_receipt
missing_tool_result
gate_exited_without_commit_or_quarantine
exception_inside_gate
```

## Badges

```text
PASS          chain valid, all actions committed
REVIEW        chain valid, one or more actions quarantined
NO_BADGE      missing/empty chain or explicit no-badge action
INVALID_CHAIN malformed JSON or hash-chain failure
```

## Hash chain

`receipt_hash` is computed over the canonical receipt body excluding `receipt_hash`.

`parent_hash` links each receipt to the previous receipt in the same file.
