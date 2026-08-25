# STANDING-SEAM-001

## Question

Can an unchanged protected action be blocked after the evidence that earned its
approval loses receiver-recognized standing, even though the original approval
artifact remains correctly signed and byte-for-byte unchanged?

## Frozen claim

> An action previously authorized by a valid receipt can be selectively blocked
> after its supporting evidence loses receiver-recognized standing, without
> revoking unrelated actions or invalidating the original receipt
> cryptographically.

## Mechanism under test

The seam is intentionally small.

1. `send_message()` already uses the ordinary Receipt Gate guarded-tool path.
2. Alice signs approval for one exact recipient + one exact message body.
3. A separately signed standing projection names that approval receipt and that
   exact protected action.
4. The receiver explicitly admits one projection as the current standing head.
5. The policy has a second ordinary requirement, `message_standing`.
6. `standing_requirement_source(...)` verifies the supplied external projection
   against the receiver's pinned issuer key and admitted current head, then
   converts that result into ordinary permission evidence.
7. Receipt Gate makes its normal receiver-owned decision.

The upstream standing system never mutates the protected function, mandate,
policy, or prior approval. It only supplies a projection. Calling
`ReceiverStandingView.admit(...)` is the receiver's decision to recognize a new
head.

## Hostile matrix

The test suite covers:

- relevant `REVOKE` -> unchanged action blocked;
- relevant `EXPIRE` -> blocked;
- relevant `SUPERSEDE` -> blocked;
- relevant `CORRECT` -> blocked;
- unrelated revocation -> unaffected action still executes;
- replay of the old pre-revocation ACTIVE projection -> blocked by current-head mismatch;
- agent-signed fake restoration -> blocked by pinned issuer verification;
- explicitly receiver-admitted signed successor -> action executes again.

The main case also checks that Alice's original approval bytes are unchanged
after revocation and its Ed25519 signature still verifies.

## Boundary

This does **not** promote Claim Graph to a trusted internal dependency. The
benchmark never imports Claim Graph code. Any upstream system can emit the
projection shape. Receipt Gate trusts only the receiver's issuer pins, the
receiver-admitted current head, and its own policy/evidence appraisal.

This is a local deterministic seam test, not a claim that every external
standing system is correct.
