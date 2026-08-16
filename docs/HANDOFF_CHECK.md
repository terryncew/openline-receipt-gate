# OpenLine Handoff Check

OpenLine Handoff Check is a local continuation check for changing agents without
silently changing the state the next agent inherits.

The invariant is simple:

> A continuation capsule may propose inherited state. It may never certify its
> own fidelity.

`handoff-check` first canonicalizes the supplied history and builds a bounded
capsule. It then runs a separate forward reference replay, with its own
validator and traversal, over the full canonical history and compares the
capsule with that replay. The capsule extractor does not call the reference
replay.

## Quick start

```bash
olp-gate handoff-check path/to/history.jsonl \
  --next "implement the authentication refactor" \
  --repo . \
  --output ./handoff
```

Supported adapters in v0.6.0rc6:

- `claude-code` — local Claude Code JSONL transcripts with message content
  blocks, tool calls, and tool results;
- `codex` — local Codex rollout JSONL records including response items,
  event messages, compaction events, and function calls;
- `generic` — JSON/JSONL objects with common event fields and optional explicit
  semantic state.

Use `--source` to pin the adapter. Automatic detection fails closed when a
generic history does not contain enough structure to identify its semantics.

## Semantic boundary

Ordinary prose is telemetry, not trusted rationale. Handoff Check only promotes
state into the decision/evidence layer when it is explicit.

Generic structured example:

```json
{
  "event_id": "e2",
  "semantic": {
    "kind": "decision",
    "item_id": "D1",
    "key": "auth.validation.location",
    "statement": "Keep authentication validation server-side.",
    "status": "active",
    "evidence_ids": ["E1"],
    "relevant_actions": ["authentication refactor"]
  }
}
```

Visible message histories may also carry explicit markers:

```text
OLP_EVIDENCE[E1]: Authentication tests passed || action=authentication
OLP_DECISION[auth.validation]: Keep validation server-side || evidence=E1;action=authentication
```

The marker is intentionally explicit. Handoff Check does not use a language
model or a phrase heuristic to decide that normal prose "sounds like" a
commitment.

Action scopes are also fail-closed. After generic operation words such as
`implement`, `refactor`, and `update` are removed, every remaining scope term
must occur in the receiver's next action. An authentication decision therefore
cannot borrow support declared only for a payments refactor merely because
both strings contain the word `refactor`.

## Results

`SAFE_TO_CONTINUE` means the generated capsule matches the explicit state
reconstructed from the supplied byte-bound history and its required evidence is
present.

`DECISION_CHANGED` means an existing capsule contains an inherited decision,
constraint, or assumption that no longer matches the current full history.

`EVIDENCE_MISSING` means the proposed inherited state lacks required support or
the history contains no explicit decision/evidence structure sufficient to
justify a semantic continuation claim.

`UNDECIDABLE` is fail-closed. It covers malformed or uninterpretable source
records, unsafe semantic fields, low-confidence generic auto-detection, changed
repository bindings, and other cases where the receiver cannot establish the
comparison safely.

## Outputs

A run writes:

```text
capsule.json
capsule.md
reference_replay.json
archive_index.json
handoff_report.json
continuation_receipt.json
proof-card.html
```

`capsule.md` is the bounded fresh-agent context. It repeats only explicit state
and bounded operational metadata; it does not invent a new natural-language
summary. The operational slice is also recomputed from the source during
inspection; a capsule with forged operational context fails closed.

The receipt is hash-bound locally by default. Pass `--key` with an existing
mode-0600 OpenLine Ed25519 private key to sign it.

## Inspecting a later handoff

```bash
olp-gate handoff-inspect current-history.jsonl ./handoff/capsule.json \
  --next "implement the authentication refactor" \
  --source codex \
  --repo .
```

The next action is receiver-owned and required. It is never inferred from the
capsule being inspected. This is the path that can expose a stale capsule after
the underlying history has evolved.

## Restoring indexed state

```bash
olp-gate handoff-restore ./handoff \
  --history original-history.jsonl \
  --item D1 \
  --output restored-D1.json
```

Restore requires the source history to match the original SHA-256 exactly and
independently rebuilds the archive index before returning an event. The index
covers every valid explicit semantic item in the supplied history, including
items outside the bounded capsule. The command restores canonical events, not
provider-private latent state.

## Claim boundary

Handoff Check verifies fidelity against the supplied history. It does not prove
that the history captured every fact that influenced an agent, that an explicit
claim is true merely because it appeared in the history, or that a fresh agent
will complete the next task correctly. It is a continuity instrument, not a
truth oracle or task-success predictor.
