# OpenLine Authority Compiler

OpenLine does not need a new access-control primitive. DPL-002 established
capability parity against a strong caveated-capability control. The production
abstraction is therefore an **authority compiler**: a receiver-owned engine that
turns an untrusted optimizer proposal into a tightly scoped request for existing
Verified Commit authorization.

```text
optimizer / planner (untrusted)
        |
        | exact proposal
        v
AuthorityCompiler
  1. receiver-owned effect semantics
  2. standing Mandate assessment
  3. current-state resolution
  4. DPL proof obligation
  5. receiver evidence resolution
  6. permission assessment
  7. evidence/mandate lifetime clamp
        |
        | COMMIT_ELIGIBLE + authority_compiler/v1 settings
        v
Proof-to-Policy / Verified Commit
        |
        | signed exact-action authorization
        v
VerifiedCommitLedger.execute_once(..., preflight=compiler.preflight)
        |
        | authorization consumed before fresh revalidation
        v
side effect or fail-closed block
```

## Security boundary

The optimizer supplies only the proposal. It does **not** supply its own
mandate, state resolver, effect semantics, or evidence resolver. Those adapters
are installed by the receiver when constructing `AuthorityCompiler`.

`COMMIT_ELIGIBLE` is not execution permission. The compiler result explicitly
carries `execution_authority = NONE_UNTIL_VERIFIED_COMMIT`.

The production spend path is `AuthorityCompiler.execute_once(...)`, which always
passes `compiler.preflight(...)` into the existing `VerifiedCommitLedger`. This
closes the temporal seam between compilation and spend: state, mandate standing,
evidence freshness/revocation, and the frozen obligation are rechecked
immediately before the effect. Verified Commit consumes the one-use
authorization before running that receiver-owned preflight, so a stale grant
cannot be retried after a failed check.

## Lifetime rule

The compiler clamps the authorization window to the earliest of:

- the DPL route's maximum authorization TTL;
- mandate expiration;
- each selected evidence artifact's expiration; and
- each selected evidence artifact's `issued_at + max_age_seconds` deadline.

A caller may choose a shorter Verified Commit TTL. It must never treat the
compiler's TTL as permission to extend beyond these evidence/mandate bounds.

## What is portable

The compiler result is orchestration state, not a new signed receipt family.
The portable proof remains the existing signed Proof-to-Policy / Verified Commit
decision receipt, plus the execution ledger/postcondition evidence already used
by OpenLine.

## What DPL-002 killed

Do not claim that DPL is a novel authorization primitive. A strong
receiver-issued caveated bearer capability reproduced the permission and
execution semantics in DPL-002. The surviving value is the receipt-native,
receiver-owned compilation pipeline that safely mints narrowly scoped
authorization from untrusted AI proposals.

## Execution adapter rule

`AuthorityCompiler.execute_once(...)` does not hand the application an arbitrary
closure with ambient state. It calls the receiver's execution adapter with the
compiled `(tool, target, effect_settings)` tuple, taken from the validated
proposal that was bound into the compiler result. The adapter is still a trusted
receiver component, but the API makes the exact compiled payload the input to
that component rather than asking it to reconstruct the action from model state.
