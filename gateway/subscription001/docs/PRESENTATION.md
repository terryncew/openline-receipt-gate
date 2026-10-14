# Subscription Demo: Presentation Copy and Frame Specs

DRAFT. Pending measured demo evidence from GATEWAY-SUBSCRIPTION-001.
This will become an HTML page later. For now: the copy and what each
frame shows.

Register: terse. Short declarative sentences. No em-dashes.

## Narrative

The enterprise gateway's first understandable consumer-facing use case.
Authorize a merchant $20/month. Revoke permission. Watch the receiving
payment system refuse the next charge and issue a verifiable receipt.

## Frames

### Frame 1 — The setup

Copy: "An owner grants a merchant permission. $20 a month. Bounded by
a mandate, not by trust."

Shows: the mandate as issued. Agent name, action types, target,
max_payment_cents. A simple card. Nothing else moves.

### Frame 2 — The charge, allowed

Copy: "The charge comes in. The gateway checks the mandate. It matches.
The charge goes through."

Shows: terminal. The signed request passes through Envoy. The mock API
verifies the signed decision token and executes exactly the authorized
params. Ledger: before balance, after balance minus $20. The authorized
receipt appears with its signature.

### Frame 3 — The revocation

Copy: "The owner cancels. The mandate ends here."

Shows: the admin command `gateway_admin.py revoke-agent`. The wallet
card flips to canceled. A timestamp. The revocation is the visible
event, not the setup.

### Frame 4 — The refusal

Copy: "The next charge comes in. There is no mandate. The gateway
refuses it. The balance does not move."

Shows: terminal. The same charge request. Envoy returns 403. The
gateway log: "denied — mandate revoked". Ledger: unchanged balance.
Side by side with Frame 2, so the contrast is the frame.

### Frame 5 — The receipt

Copy: "The refusal is a signed receipt. It proves what happened and
who authorized what. It proves nothing downstream."

Shows: the refusal receipt record. Signature line. `verify-receipts`
output: receipt valid. A caption under it: "Decision proof, not
execution proof."

### Frame 6 — The boundary

Copy: "This works because the receiver enforces it. A bank that never
integrated OpenLine would not refuse. Proof of a right is not the power
to exercise it."

Shows: one line of text on an empty background. The honest boundary,
given equal weight to the demo.

## Layout notes for the HTML build

- One frame per viewport. Advance on scroll or tap.
- Frames 2 and 4 share the ledger panel so the balance contrast is
  visible without scrolling.
- Terminal text must be readable at phone scale. Large type, no more
  than six lines per terminal panel.
- Frame 6 is not a footnote. Same type size as the others.
