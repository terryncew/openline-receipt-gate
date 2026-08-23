# OpenLine guarded-tool adapter

OpenLine's reference adapter sits at the function boundary. It does not rewrite the agent loop and it does not trust the model's rationale.

```text
agent / LangGraph
      |
      | ordinary tool args
      v
@authorize
      |
      | frozen exact args + receiver state
      v
Authority Compiler
      |
      | mandate + receiver-owned evidence
      v
COMMIT_ELIGIBLE / QUARANTINE / DENY
      |
      | only COMMIT_ELIGIBLE continues
      v
Proof-to-Policy + Verified Commit
      |
      | fresh preflight + exact hash + one use
      v
original Python function
```

## Boundary rules

- The wrapped function body never runs on `QUARANTINE` or `DENY`.
- Arguments are JSON-frozen before compilation, and execution reconstructs the call from those frozen values rather than caller-owned mutable objects.
- `state_source` and `evidence_sources` are receiver-owned callbacks. Do not wire LLM output directly into them as trusted evidence.
- Evidence providers are keyed by the requirement IDs declared in the receiver policy. `None`/`False` means unavailable; `True` or a mapping means a fresh verified receiver-side assertion; `EvidenceAssertion` exposes expiry/revocation controls.
- The default `LocalAuthorityRuntime` persists local signing keys and replay state under `.openline/runtime`. It is a reference/local-service runtime, not a replacement for production KMS/HSM key custody.
- The adapter uses the existing Authority Compiler, Proof-to-Policy gate, and `VerifiedCommitLedger`. It does not create a new access-control primitive.

## LangGraph

Use LangGraph's normal tool decorator outside OpenLine:

```python
@tool
@authorize(...)
def consequential_tool(...):
    ...
```

No LangGraph-specific dependency is required inside `openline-receipt-gate`.
