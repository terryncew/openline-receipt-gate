# Lithic ASA sources and the bounded authorization contract

This investigation read official Lithic repositories on October 11, 2026. It made no Lithic API calls, enrollments, card creations, or transactions. The fixtures contain synthetic identifiers and no PAN. The documentation site was unavailable through this environment's network proxy; the claims below come from the pinned official SDK, OpenAPI specification, and ASA demo rather than an inferred webhook format.

## Pinned official sources

| Source | Pin | What it establishes |
| --- | --- | --- |
| [Lithic OpenAPI](https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml) | `0afad9e69e57f2e0bbace17c1f03f79c97c07c76` (September 16, 2026) | `authorization`, `asa-response`, `webhooks.card_authorization.approval_request`, and the three signature headers. |
| [Current Python CardAuthorization type](https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/card_authorization.py) | `826a8c940571e88bd4682a38e22b1c9f999cef93` (October 8, 2026) | Current structured amounts, nested card identity, merchant fields, operation types, and optional beta event token. |
| [Current Python ASA secret resource](https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/resources/auth_stream_enrollment.py) | Same current SDK commit | ASA has a program secret retrieved using `/v1/auth_stream/secret`; rotation deactivates the old secret after 24 hours. No endpoint was called here. |
| [Official ASA Python handler](https://github.com/lithic-com/asa-demo-python/blob/078de63030904faf61e63b3f8e7eeb7abfcc0b5f/webhook/app.py) and [decision logic](https://github.com/lithic-com/asa-demo-python/blob/078de63030904faf61e63b3f8e7eeb7abfcc0b5f/webhook/authorization.py) | `078de63030904faf61e63b3f8e7eeb7abfcc0b5f` (April 8, 2026) | An ASA responder uses the SDK's `client.webhooks.parse` verifier, expects `CardAuthorizationApprovalRequestWebhookEvent`, and returns documented `result` values. Its optional unauthenticated demonstration mode is unsuitable for the configured pilot. |
| [Official Python verifier](https://github.com/lithic-com/lithic-python/blob/a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f/src/lithic/resources/webhooks.py) and [published verifier fixture](https://github.com/lithic-com/lithic-python/blob/a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f/tests/api_resources/test_webhooks.py) | Release `v0.132.0`, commit `a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f` | Verifier behavior and a published general-webhook signature fixture. This fixture is not an ASA-specific published example. |

The full OpenAPI file fetched at that pin has SHA-256 `13f01516dfbc129804b5086b1a45beb8e413b24148458af234e01e46a1a4f09c`. The current `card_authorization.py` file has SHA-256 `d29b55e60b1c4dcc3b8ca6991f4babfd170e940b9be13edadb8050aaacee79d9`.

## Real ASA request fields

The request event is `card_authorization.approval_request`. Its card identity is **`card.token`**, not an invented top-level `card_token`. `token` is the provisional transaction-group UUID assigned to the authorization. The sandbox authorization simulator's response returns this transaction token; its request parameters do not provide a way to select it in advance. `event_token` is optional and currently documented as available only to programs enrolled in a beta. A receiver cannot depend on that field for this pilot.

| Field | Official meaning and pilot boundary |
| --- | --- |
| `amounts.cardholder.amount`, `.currency`, `.conversion_rate` | Amount in the currency's smallest unit, ISO 4217 billing currency, and conversion rate. A $1 USD intent uses integer `100`, `USD`, and a fixed conversion value. |
| `amounts.merchant.amount`, `.currency` | Network merchant amount and currency. Matching only the billing amount would miss currency conversion or a different merchant-side amount. |
| `amounts.hold`, `amounts.settlement` | Nullable structured amount objects. A hold adjustment can exceed the initial request; settlement amounts distinguish single-message operations. The OpenAPI requires these properties but permits `null`; the current Python model also tolerates omission. The full fixture includes both. |
| `merchant.acceptor_id`, `acquiring_institution_id`, `descriptor`, `mcc`, `city`, `country`, `state` | Required merchant identity and descriptor/location fields. `country` uses ISO 3166-1 alpha-3 plus documented exceptions. A city can contain a merchant URL or phone number, so it is not an independently attested physical location. |
| `merchant.phone_number`, `postal_code`, `street_address` | Optional details. They cannot be assumed present or used as stronger identity guarantees than the delivered network data supports. |
| `status` | Operation type: `AUTHORIZATION`, `CREDIT_AUTHORIZATION`, `FINANCIAL_AUTHORIZATION`, `FINANCIAL_CREDIT_AUTHORIZATION`, or `BALANCE_INQUIRY`. The narrow purchase pilot accepts only `AUTHORIZATION`. There is no invented `operation` field. |
| `transaction_initiator` | `CARDHOLDER`, `MERCHANT`, or `UNKNOWN`. Bind the intended operation rather than treating a merchant-initiated retry or recurring charge as the same purchase automatically. |
| `acquirer_fee`, `cash_amount` | Explicit fee and cash portions. The latter is always present and zero when no cash is requested. A $1 purchase intent does not authorize an ATM debit, cash back, or an additional fee. |
| `network`, `pos` | Additional network/POS details where present. Network-specific purpose data is optional and restricted to certain programs. Do not assert these fields provide a unique order identifier. |

The specification still requires deprecated fields such as `amount`, `authorization_amount`, `merchant_amount`, and their currencies. The full test fixture supplies consistent values but uses `amounts` as the payment boundary. `created`, `avs`, `card`, `merchant`, `status`, `token`, `transaction_initiator`, `name_validation`, and `service_location` are also required in the pinned OpenAPI; the latter two are nullable. Older minimal fixtures in this repository did not represent the full current ASA schema.

## Honest preauthorization semantics

A card binding identifies which owner authority may be presented; it supplies no permission by itself. Before receiving an ASA transaction token, the strongest available permission is **one matching purchase intent during a short expiry window**: the selected card, amount and currencies, merchant identity/descriptor, purchase operation, initiator, and supported fee/cash/POS details. The worker must cryptographically bind that intent to its verified Wallet presentation, and the receiver must consume it atomically once.

This is not an authorization for a preselected transaction UUID, unique merchant order, or receipt of purchased goods. Two purchases with identical delivered intent fields remain indistinguishable before Lithic assigns the token; the first authenticated matching authorization can consume the single pending intent. The pilot must accept and document that limitation. A different merchant, currency, operation, or otherwise bound intent must decline even when the card and dollar amount match.

After deciding an authenticated request, store the complete request-content fingerprint with its transaction token and decision. An identical retry can return the durable original response. A reused token with different contents must fail closed, including after a restart. The token is a transaction-group identity; later changed events must not inherit this pilot's first approval. This restricted behavior deliberately does not implement incremental authorizations, recurring charges, clearing, settlement, or credit operations.

## Documented responses and timing

`asa-response` requires only `result`. A full approval can return `{"result":"APPROVED"}`; echoing the original `token` is documented and optional. The defined decline values include `CARD_PAUSED`, `UNAUTHORIZED_MERCHANT`, `SUSPECTED_FRAUD`, `INSUFFICIENT_FUNDS`, `AVS_INVALID`, `VELOCITY_EXCEEDED`, `DRIVER_NUMBER_INVALID`, and `VEHICLE_NUMBER_INVALID`. `CHALLENGE` is supported only for cardholder-initiated transactions. A custom value produces a decline with detailed result `CUSTOM_ASA_RESULT`, so private OpenLine reasons belong in the separate persisted receipt, not in invented ASA response fields.

The official webhook specification documents HTTP 200 for a handled ASA response and HTTP 5XX for processing failure, which causes one immediate retry. It does not establish a delivery guarantee. Local tests enforce the requested six-second response budget; they cannot prove the deployed network's total round-trip time or Lithic's behavior under an external outage. No deployment was performed.

The response must not contain an OpenLine receipt, presentation, custom signature, or other undocumented OpenLine extension. Retrieve the independently verifiable signed receipt through the integrator's authenticated, read-only interface instead. Its public-key pin must be provisioned independently of the retrieved receipt.

## Signature scope

ASA uses the program's **ASA signing secret**. An arbitrary regular webhook-subscription secret or API key is not interchangeable. The official ASA demo's use of the ordinary SDK verifier establishes a shared signing algorithm, not a shared secret. Verify the original request bytes before interpreting their JSON; do not verify one body and authorize a separately supplied mapping.

The official header schema documents `webhook-id`, Unix `webhook-timestamp`, and a space-separated list of versioned Base64 `webhook-signature` values, including multiple signatures during rotation. Secret decoding, freshness checks, and signature comparison must reproduce the official verifier. The conformance tests distinguish the published general-webhook fixture from independently constructed ASA-shaped fixtures; neither is a real delivered Lithic authorization.

The official-verifier check is reproducible without a Lithic API key or network request to Lithic:

```bash
python3 -m venv /tmp/openline-lithic-verifier
/tmp/openline-lithic-verifier/bin/python -m pip install \
  'lithic[webhooks] @ git+https://github.com/lithic-com/lithic-python.git@a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f' \
  'standardwebhooks==1.1.0'
cd gateway/receiver-package
OPENLINE_REQUIRE_OFFICIAL_LITHIC=1 /tmp/openline-lithic-verifier/bin/python \
  -m unittest -v test_lithic_hmac
```

`OPENLINE_REQUIRE_OFFICIAL_LITHIC=1` makes an absent SDK fail the verification instead of skipping the independent check. The SDK client uses a placeholder offline API key and only invokes its local signature verifier.
