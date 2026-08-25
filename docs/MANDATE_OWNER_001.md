# Mandate ownership: policy authorship is not authority

OpenLine already separates an untrusted action proposal from receiver-owned evidence appraisal and execution. MANDATE-OWNER-001 adds the missing authority boundary above the mandate itself.

The rule is:

> A developer or model may write a rule. Writing the rule does not grant the rule authority to govern.

## Architecture

```text
Developer / policy compiler
        |
        | proposes a syntactically valid mandate
        v
DRAFT MANDATE                         authority: NONE
        |
        | owner signs exact mandate hash
        | receiver verifies pinned slot owner
        v
RECEIVER-ADMITTED CURRENT MANDATE     authority source
        |
        v
Authority Compiler
        |
        v
Receipt Gate / Verified Commit
        |
        v
Exact protected effect
```

A receiver configures each mandate slot outside the mandate object:

```python
view = MandateOwnerView({
    "refund-agent/default": {
        "owner_id": "alice",
        "public_key": ALICE_PUBLIC_KEY_HEX,
    }
})
```

The mandate cannot alter that trust root. A signed mandate authorization must match the configured slot owner and key, bind the exact `MandateSpec.mandate_hash`, and extend the slot's single monotonic predecessor chain.

## Lifecycle

`DRAFT` is an unauthoritative policy proposal. It is never an admitted state.

An admitted head is either:

- `ACTIVE`: the exact bound mandate is current and may be supplied to `AuthorityCompiler`;
- `REVOKED`: the slot has no current executable mandate authority.

When an `ACTIVE` successor replaces another `ACTIVE` head, the older head is historically authentic but implicitly superseded. It does not become false or cryptographically invalid.

## Guarded use

```python
@authorize_owned(
    policy=developer_authored_bundle,
    mandate_view=view,
    mandate_slot_id="refund-agent/default",
    tool="process_refund",
    target="refund://process",
    semantics=payment_semantics("amount_cents"),
    state_source=current_refund_state,
    evidence_sources={"refund_authority": refund_authority},
)
def process_refund(amount_cents: int, customer_id: str):
    ...
```

`developer_authored_bundle["mandate"]` is parsed only as proposal material. On every call, `authorize_owned` resolves the current receiver-admitted mandate and constructs the ordinary `authorize(...)` path with that mandate instead.

The selected mandate head is also included in receiver state. A head change between selection and execution preflight causes the existing Authority Compiler preflight to fail closed.

## What is new versus STANDING-SEAM-001

The new claim is **authorship does not confer authority**. A developer-signed or agent-signed mandate remains non-governing when its key is not the receiver-pinned mandate owner key.

The older standing mechanism is reused for a different property: after the owner admits a successor, an older correctly signed mandate authorization is authentic history but no longer the current authority. MANDATE-OWNER-001 labels those arms as composition evidence rather than presenting them as a new result.

## Root-of-trust boundary

This design intentionally stops the regress at receiver-side configuration. It does not prove that `alice` is the legally correct owner or that the configured key corresponds to a real-world legal principal. Those are deployment and institutional trust questions outside this software claim.

It also does not yet establish distributed persistence, multi-process compare-and-swap, crash recovery, HSM/KMS integration, or cross-receiver mandate federation.

## Experimental status

This module is intentionally not promoted into the stable top-level `olp_gate` API by MANDATE-OWNER-001. The benchmark first asks whether the separation is mechanically real.

Target verdict: `MANDATE_AUTHORSHIP_AUTHORITY_SEPARATION`

`policy_authority: NONE`
