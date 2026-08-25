# Standing projection seam

Receipt Gate can consume externally supplied standing without granting the
upstream system execution authority.

The interface is:

```python
view = ReceiverStandingView({
    "claim-graph-projector": TRUSTED_PUBLIC_KEY_HEX,
})

view.admit(external_projection)

standing_source = standing_requirement_source(
    view,
    support_source=current_approval_receipt,
    projection_source=current_external_projection,
)

@authorize(
    policy=policy_with_message_standing_requirement,
    ...,
    evidence_sources={
        "message_authority": message_authority,
        "message_standing": standing_source,
    },
)
def send_message(recipient: str, message: str):
    ...
```

A standing projection is signed, names the hash of the support artifact, names
the hash of the exact protected call, carries a sequence and predecessor, and
has its own freshness window.

`ReceiverStandingView.admit()` verifies the external signature against a
receiver-pinned issuer key and requires a continuous successor chain before it
moves the receiver's current head. Merely receiving a `REVOKE`, `CORRECT`, or
other upstream event does nothing by itself.

At authorization time the standing evidence source verifies the supplied
projection again and requires it to equal the receiver-admitted head. A stale
pre-revocation projection may still be perfectly signed, but it no longer
matches current standing and therefore cannot satisfy the policy requirement.

An INACTIVE current projection is translated into revoked permission evidence;
a malformed, forged, stale, or non-current projection is translated into
unverified evidence. Existing Receipt Gate logic then blocks the action.

This keeps the separation explicit:

external system reports consequence -> receiver admits current standing ->
Receipt Gate appraises current evidence -> protected action executes or does not.
