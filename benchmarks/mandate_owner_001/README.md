# MANDATE-OWNER-001

## Question

Can a policy author produce a perfectly valid mandate without thereby acquiring the authority to make that mandate govern a protected action?

## Frozen claim

> A mandate may be syntactically valid and correctly compiled without having authority to govern. Executable mandate authority exists only after admission by the receiver-pinned mandate owner, and only the current admitted mandate may govern new actions.

## New mechanism under test

The developer-authored `policy["mandate"]` is treated as a **proposal**, not as executable authority.

A receiver configures a mandate slot out of band:

```text
slot: refund-agent/default
owner_id: alice
owner_public_key: <receiver-pinned Ed25519 key>
```

The mandate object cannot select this key. An owner authorization binds the slot, owner, exact mandate hash, lifecycle state, monotonic sequence, predecessor, and freshness window. `MandateOwnerView.admit(...)` moves one receiver-owned current head only after verifying that record against the pinned owner configuration.

`authorize_owned(...)` then obtains the current receiver-admitted mandate and passes **that** mandate into the existing Receipt Gate / Authority Compiler path. The draft mandate in the policy bundle is never used as governing authority.

## Corrected six-arm matrix

| Arm | Class | Expected result |
|---|---|---|
| Valid developer-authored $500 mandate, no owner admission | NEW | blocked |
| Developer signs the $500 mandate with developer key | NEW | receiver rejects; blocked |
| Agent signs its own $500 mandate | NEW | receiver rejects; blocked |
| Pinned owner admits $100 mandate; $75 action | NEW | executes |
| Owner narrows to $50; old signed $100 record replayed; $75 action | COMPOSITION with #32 | old signature remains valid, old record is non-current, action blocked |
| Owner admits later $100 successor; same $75 action | COMPOSITION with #32 | executes |

The first four arms establish the new authorship/authority separation. The final two deliberately reuse current-head lifecycle semantics already demonstrated by STANDING-SEAM-001.

## Preflight hostile check

The selected mandate head is bound into the receiver state used by the ordinary Authority Compiler. If the receiver admits a different mandate after compilation begins but before execution preflight, the action fails closed. This prevents a call from spending authority from a mandate that stopped being current during the authorization window.

## Falsifier

If this experiment can be implemented by routing mandate objects through `ReceiverStandingView.admit()` unmodified, with no owner-validation path between policy authorship and `AuthorityCompiler`, the result must be downgraded to:

`STANDING_SEAM_EXTENSION_ONLY`

The benchmark reports this falsifier explicitly.

## Trust-root boundary

This does **not** solve authority regress in general. It grounds this experiment at an existing receiver-side trust boundary: the slot owner identifier and public key are configured out of band. It does not prove legal identity, legal authority, fiduciary duty, or the correctness of that receiver configuration.

## Verdict vocabulary

Success: `MANDATE_AUTHORSHIP_AUTHORITY_SEPARATION`

Failure: `MANDATE_AUTHORSHIP_AUTHORITY_SEPARATION_NOT_ESTABLISHED`

Falsifier collapse: `STANDING_SEAM_EXTENSION_ONLY`

`policy_authority: NONE`
