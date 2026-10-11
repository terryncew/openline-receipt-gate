# Subscription Demo: Video Storyboard (X, 20–30 s)

Demo evidence landed 2026-10-11 (25/25 checks,
`gateway/subscription001/EVIDENCE-demo.md`). The permitted line below
is supported by measured behavior: permission granted (step 1), charge
succeeded (step 2), permission revoked (step 6), next charge refused
with 403 `agent_revoked` and $0 moved (step 7). All on-screen claims
stay exactly as narrow as that evidence.

Target viewer: non-technical. Simple language. One idea per shot.

## Shot list

### 0:00–0:05 — Permission given

Screen: phone-style wallet card. One line fills in: "Merchant: Acme
Streaming — $20/month". A tap on "Allow".

On-screen text: "You gave permission."

Narration: "You gave permission. Twenty dollars a month."

### 0:05–0:10 — Charge succeeds

Screen: terminal. A charge request goes through the gateway. Ledger
balance drops by $20. Receipt appears: "authorized — decision signed".

On-screen text: "The charge goes through."

Narration: "The charge goes through. There is a signed receipt."

### 0:10–0:16 — Permission revoked

Screen: same wallet card. "Allow" flips to "Canceled". Admin revokes
the mandate. Timestamp visible.

On-screen text: "You canceled it."

Narration: "Then you canceled it. The permission is gone."

### 0:16–0:24 — Next charge refused

Screen: terminal. The same charge request fires again. Envoy returns
403. The gateway log shows "denied — mandate revoked". Ledger balance
unchanged.

On-screen text: "Your payment system refuses the next charge."

Narration: "The next charge comes in. Your payment system refuses it."

### 0:24–0:30 — Receipt as proof

Screen: the refusal receipt, zoomed. Signature line visible.
`verify-receipts` output: "receipt valid".

On-screen text: "Proof of what happened. Who authorized what."

Narration: "A receipt proves what happened, and who authorized what."

## Production notes

- Keep terminal text large and readable at phone scale.
- No em-dashes in on-screen text.
- The demo runs against the simulated ledger, not a real bank. The
  video must not imply real money moved or that any real merchant or
  bank participated.
- Permitted line, pending verification: "You gave permission. You
  canceled it. Your payment system refuses the next charge." Use it
  verbatim or not at all.
