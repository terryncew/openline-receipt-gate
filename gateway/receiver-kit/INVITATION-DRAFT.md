# External Engineer Invitation — DRAFT (UNSENT)

**Do not send without explicit order.** This is a draft for review.

---

Subject: A receiver that enforces someone else's authority — want to try breaking it?

Hi [name],

I'm working on OpenLine, a protocol for portable AI authority. The core
idea: an AI's permission to act shouldn't be trapped inside the system
that issued it. An owner grants a mandate (signed, bounded, revocable);
a separately operated receiver verifies and enforces it.

I've built a starter kit for external receivers — the party that *didn't*
issue the authority but has to decide "is this exact action allowed now?"

What's in it:
- A minimal receiver in ~60 lines (pin a key, admit a bundle, decide)
- Worked examples: worker key rotation, revocation with explicit bounds
- The trust model written down (no hand-waving about freshness)
- A fair comparison vs. building it on OPA (including why you might not choose it)

The interesting part for a security engineer: the revocation bound is
explicit. New bundles stop new presentations immediately; in-flight
presentations live to their challenge TTL (60s default). No "instant
revocation" claims.

I'd value your take, especially on:
1. Is the trust model honest? (TRUST-MODEL.md)
2. Would you run this in front of a real API? What's missing?
3. Can you break the worker-replacement demo? (Try using the wrong key.)

Kit: [link to receiver-kit on the branch]
Demo: `python3 gateway/demo_wallet_integration.py` (10/10 checks)

No pitch, no ask beyond your honest engineering judgment. If it's not
interesting, that's useful signal too.

— Terrynce

---

**Target profile:** Security engineers who operate consequential APIs
(payments, infra, deployments). People who've felt the "we can stop the
agent" gap. Not crypto enthusiasts, not AI hype followers.

**Send criteria (all must hold):**
- P1 Docker verification is green
- Terrynce has approved the kit content
- Terrynce names the recipient
