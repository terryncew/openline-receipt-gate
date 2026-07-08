# OpenLine Receipt Gate

One line around a risky agent action.

Get a receipt.

Missing proof? Quarantine.

No chain, no badge.

Core rule:

> The agent cannot just say it did the thing. It has to pass the gate.

## Why this exists

Agents are starting to touch tools, files, memory, eval scores, handoffs, and external systems.

Most stacks record traces after the fact.

OpenLine Receipt Gate wraps the boundary crossing itself.

```python
from olp_gate import gate

with gate(
    action_type="tool_call",
    claim="Search customer records",
    evidence_required=True,
) as g:
    result = search_customer_records(query)
    g.commit(result, evidence={"query_hash": "sha256:..."})
```

If required proof is missing, the gate fails closed.

## Decisions

```text
COMMIT      required proof exists
QUARANTINE missing or risky proof; review required
NO_BADGE    action lacks enough chain to certify
```

## Fail-closed badge behavior

```bash
python -m olp_gate.cli badge does_not_exist.jsonl
```

returns:

```text
NO_BADGE
reason: empty_or_missing_receipt_chain
exit code: 1
```

Malformed JSON returns `INVALID_CHAIN`, not a Python traceback.

## Privacy default

Raw evidence is not stored in receipts by default.

The receipt stores:

```text
evidence_hash
evidence_keys
raw_evidence_stored: false
```

To store raw evidence, opt in explicitly:

```python
gate(..., store_raw_evidence=True)
```

Default rule:

> Proof moves. Data doesn't.

## Receipt fields

Each receipt is JSONL:

```text
receipt_id
parent_hash
timestamp
action_type
claim
evidence_hash
result_hash
status
decision
policy_flags
next_use_note
receipt_hash
```

This is a local hash chain, not public-key signing.

Say **hash-chained receipts**, not signed receipts.

## Install / run locally

```bash
python -m pytest -q
python examples/demo_all.py
python -m olp_gate.cli verify receipts/tool_call_receipts.jsonl
python -m olp_gate.cli badge receipts/tool_call_receipts.jsonl
python -m olp_gate.cli review receipts/tool_call_receipts.jsonl
```

If installed as a package, the CLI name is:

```bash
olp-gate verify receipts.jsonl
olp-gate badge receipts.jsonl
olp-gate review receipts.jsonl
```

## Examples

```text
examples/wrap_tool_call.py
examples/wrap_memory_write.py
examples/wrap_eval_score.py
```

Expected demo behavior:

```text
clean tool call                  → COMMIT
missing evidence hash            → QUARANTINE
memory write without user intent → QUARANTINE
eval score without grader receipt→ QUARANTINE
eval score with no chain         → NO_BADGE
```

## What this is not

No server.

No dashboard.

No external API.

No LangChain dependency.

No observability platform.

This does not magically undo side effects after an action already happened. In production, place the gate before irreversible execution or use it with a staging/quarantine layer.

This is the small gate every agent should pass through before it changes the world.

## Keeper line

A benchmark score without receipts is just a press release.

An agent action without a receipt is just a claim.
