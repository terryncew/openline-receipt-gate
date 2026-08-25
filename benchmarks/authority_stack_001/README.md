# AUTHORITY-STACK-001

## Question

Do the existing OpenLine authority layers remain coherent when composed end to end, without adding a new primitive or bypass path?

## Frozen claim

> OpenLine can compose mandate ownership, exact-action approval, temporal standing, selective standing loss, and exact-action gating so that historically valid artifacts remain verifiable while current execution authority changes selectively.

## Layers under composition

```text
developer-authored mandate proposal
        |
        v
receiver-pinned mandate owner admission
        |
        v
exact-action approval receipt
        |
        v
receiver-recognized standing head
        |
        v
Authority Compiler / Receipt Gate / Verified Commit
        |
        v
exact protected effect
```

No new `olp_gate` authority primitive is introduced by this experiment. The harness uses the real `LocalAuthorityRuntime`; there is no custom runtime shim.

## Canonical sequence

1. A developer-authored $500 mandate proposal exists. Before owner admission, the protected action is blocked.
2. The receiver-pinned owner admits a narrower $100 mandate.
3. Alice signs exact action approvals for two refund calls and both receive `ACTIVE` standing.
4. Action 1 ($75) executes under the admitted $100 mandate, not the developer's $500 proposal.
5. Action 1 standing advances to `REVOKE`. The exact same approval receipt remains byte-for-byte unchanged and cryptographically valid. Action 1 blocks; unrelated Action 2 proceeds.
6. The owner narrows the mandate to $80. The old $100 owner authorization remains cryptographically valid but non-current. A separately approved and ACTIVE $90 probe blocks because only the current $80 mandate governs.
7. The mandate successor alone does **not** restore Action 1 because its standing is still revoked.
8. A separate receiver-admitted `ACTIVE` standing successor restores Action 1; the same $75 call executes under the current $80 mandate.

The sequence is intentionally eight stages rather than pretending mandate succession can restore a separately revoked standing relation. Silent cross-layer restoration would violate the architecture and fail the experiment.

## Four separations

| Boundary | Invariant |
|---|---|
| Authorship != Authority | A valid developer mandate proposal has zero governing authority until the pinned owner admits a mandate. |
| Valid Receipt != Current Standing | An unchanged, correctly signed approval can remain authentic while its current standing blocks execution. |
| Selective Standing Loss | Revoking one exact `(support receipt, action)` pair does not block an unrelated authorized action. |
| Receiver-Admitted Governance | Superseded owner authorizations remain authentic history, but only the current admitted mandate governs new effects. |

A fifth composition check protects layer orthogonality: changing mandate authority must not silently rewrite action standing.

## Falsifier

Fail the composition milestone if it requires any of the following:

- a custom runtime shim instead of `LocalAuthorityRuntime`;
- bypass flags or special-case execution logic;
- mutation of historical receipt objects to simulate revocation;
- mandate semantics implemented inside the standing layer;
- a mandate successor silently restoring revoked action standing;
- a new core authority primitive created only to make the sequence pass.

Target verdict: `AUTHORITY_STACK_COMPOSITION_PASS`

Failure verdict: `AUTHORITY_STACK_COMPOSITION_GAP`

`policy_authority: NONE`

## Boundary

This is a deterministic composition proof, not an external deployment result. Receiver-pinned keys remain the software trust roots. Legal authority, fiduciary duty, distributed persistence, multi-process concurrency, crash recovery, and external protocol interoperability remain outside the earned claim.
