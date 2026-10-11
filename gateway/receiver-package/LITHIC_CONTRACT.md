# Lithic ASA Sandbox Contract (Offline Fixture)

**Status:** Documented, not connected. No Lithic adoption. No real funds.

This documents the EXACT request/response contract for a hypothetical
Lithic ASA sandbox integration. The offline fixture test (`test_lithic_adapter.py`)
verifies the adapter logic without a network connection.

## Distinction: Authorization vs Settlement

**Card authorization** (what we test):
- The moment a card is swiped/tapped/entered, Lithic sends an
  authorization request to the ASA endpoint.
- The ASA decides: APPROVE or DECLINE.
- This is a *decision*, not money movement. No funds transfer yet.

**Financial settlement** (what we DO NOT test):
- Later (hours/days), the merchant settles. Money moves.
- OpenLine does not participate in settlement. The authorization
  decision is the consequence boundary.

**Our test:** Only the authorization decision. $1 synthetic auths.
No settlement. No real money.

## Sandbox Request (Lithic → Our ASA Endpoint)

Lithic sends a JSON POST to our enrolled ASA webhook URL.

```json
{
  "token": "lithic-auth-token-abc123",
  "card_token": "card_xxx",
  "amount": 100,
  "currency": "USD",
  "merchant": {
    "name": "TEST MERCHANT",
    "mcc": "5999"
  },
  "openline_presentation": {
    "schema": "openline.presentation.v1",
    "principal_id": "terrynce-test-owner",
    "mandate_id": "mandate_abc123",
    "subject_id": "test-agent-1",
    "subject_public_key": "hex...",
    "action": "lithic:authorize",
    "receiver_challenge": "challenge-xyz",
    "bundle_head_hash": "hash...",
    "issued_at": "2026-10-11T20:00:00Z",
    "signature": "hex..."
  }
}
```

**Fields:**
- `token`, `card_token`, `amount`, `currency`, `merchant`: Standard Lithic ASA.
- `openline_presentation`: Injected by the agent (or its platform) into
  the authorization request metadata. Our ASA extracts and verifies it.

## Sandbox Response (Our ASA → Lithic)

```json
{
  "approved": true,
  "openline_receipt": {
    "schema": "openline.receipt.v1",
    "decision": "APPROVED",
    "principal_id": "terrynce-test-owner",
    "mandate_id": "mandate_abc123",
    "amount_cents": 100,
    "at": "2026-10-11T20:00:01Z",
    "receiver_signature": "hex...",
    "receiver_public_key": "hex..."
  }
}
```

If declined:
```json
{
  "approved": false,
  "decline_reason": "MANDATE_REVOKED",
  "openline_receipt": {
    "schema": "openline.receipt.v1",
    "decision": "DECLINED",
    "reason": "MANDATE_REVOKED",
    ...
  }
}
```

## The 6 Test Scenarios (Offline Fixtures)

1. **Valid mandate → APPROVE**
   - Presentation signed by worker key, mandate active, amount within limit.
   - Expect: `approved: true`, receipt signed.

2. **Revoked mandate → DECLINE**
   - Owner revoked the mandate (new bundle admitted without it).
   - Same presentation re-fired.
   - Expect: `approved: false`, reason `MANDATE_REVOKED`.

3. **Worker replacement → APPROVE (new worker)**
   - Owner issues new mandate to successor worker (different key).
   - Successor presents with new key.
   - Expect: `approved: true`. Old worker's presentations still declined.

4. **Amount exceeds mandate → DECLINE**
   - Presentation for $5.00, mandate limit is $1.00.
   - Expect: `approved: false`, reason `AMOUNT_EXCEEDS_MANDATE`.

5. **Duplicate delivery → DECLINE (second)**
   - Same presentation (same challenge) sent twice.
   - First: APPROVE. Second: DECLINE (challenge replay).
   - Expect: Second has reason `CHALLENGE_REPLAY`.

6. **Invalid signature → DECLINE**
   - Presentation with tampered signature.
   - Expect: `approved: false`, reason `PRESENTATION_SIGNATURE_INVALID`.
   - Fail closed: no receipt without valid signature.

## What Requires Terrynce's Approval

Before ANY real sandbox connection:
1. [ ] Terrynce approves the Lithic invitation draft verbatim.
2. [ ] Terrynce confirms the test owner keypair (or generates a fresh one).
3. [ ] Terrynce approves the ASA webhook URL (where our receiver runs).
4. [ ] Terrynce confirms: sandbox only, $1 synthetic, no real cardholders.
5. [ ] Lithic integrator confirms sandbox enrollment (their side).

**Do not proceed without all five.**
