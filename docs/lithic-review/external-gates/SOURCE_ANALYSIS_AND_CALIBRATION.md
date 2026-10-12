# OPENLINE-LITHIC-EXTERNAL-GATES-001

**Gate 1 — CALLBACK MATCHING: PARTIALLY RESOLVED.** Exposed simulator controls and token timing are documented; a reproducible complete OpenLine intent is not established.

**Gate 2 — PROVIDER FAILURE BEHAVIOR: PARTIALLY RESOLVED.** One immediate retry for HTTP 5XX and decline for an unknown string result are documented. The fixed deadline and final decisions after timeout, exhausted 503 retries, malformed JSON or an invalid response shape remain unestablished.

**Recommendation: NO-GO for armed approval/revocation/successor testing.** A bounded, owner-approved **unarmed** calibration is the justified next experiment. It must explicitly allow observing a possible unexpected synthetic provider approval; OpenLine granting no authority cannot guarantee the provider's unknown fallback.

Research snapshot: October 11, 2026, client timezone. Read the existing acceptance audit and owner packet. Reused their accepted 104-check evidence; **no tests rerun**. Repository and PR #108 untouched; no branch created. No Lithic API calls, enrollment, contacts, deployment, transactions, paid APIs or merges occurred. Research files and source hashes are outside the checkout.

## Official evidence and discrepancies

Current official GitHub heads are unchanged from the audit: OpenAPI `0afad9e69e57f2e0bbace17c1f03f79c97c07c76` (September 16) [S1]; Python SDK `826a8c940571e88bd4682a38e22b1c9f999cef93` (October 8) [S2]. Fresh OpenAPI SHA-256 is `13f01516dfbc129804b5086b1a45beb8e413b24148458af234e01e46a1a4f09c`, matching preserved evidence. Official documentation-page requests returned proxy HTTP 403; their contents were **not** read. Findings below come from current official repositories, not an inferred current website policy. Source retrieval records preserve successful reads, errors and hashes.

### Gate 1: what can actually be supplied

The SDK exposes exactly these 15 inputs; the published OpenAPI exposes 13, omitting the two newer currency inputs. These are request controls, **not a guarantee that all callback strings/objects are echoed unchanged**. [S1], [S2], [S3]

| Caller-supplied input | Documented meaning / restriction |
| --- | --- |
| `pan` | Selects the existing card; OpenAPI requires 16 characters. Card token/state/type are resolved from card state, not chosen transaction metadata. |
| `amount` | Required billing authorization amount; OpenAPI integer 0–2,000,000,000. Credits become negative; balance inquiry requires zero. Pilot uses 100. |
| `descriptor`, `mcc` | Descriptor required, 1–25 characters. MCC is a four-digit ISO 18245 code; supported-code list is linked in official sources. |
| `merchant_acceptor_id` | OpenAPI string length **1–15**, no format or registered-merchant allowlist supplied. `OL-PILOT-001` meets this syntax; actual acceptance remains unobserved. The lab's `OPENLINE-SYNTHETIC-001` has 22 characters and cannot be copied to this input. A supplied ID is not independently attested merchant identity. |
| `merchant_acceptor_city/state/country` | City <=13; state <=3; country exactly 3 characters, documented ISO alpha-3. Proposed NEW YORK/NY/USA meets those constraints. |
| `merchant_amount`, `merchant_currency` | Merchant amount includes fees. **SDK:** USD/GBP/EUR/CAD, other codes return 422; currency is used with merchant amount and then defaults GBP. **OpenAPI:** USD/GBP/EUR and another ISO code defaults GBP. Use explicit 100/USD; actual API discrepancy is untested. |
| `billing_currency`, `settlement_currency` | **Current SDK only:** USD/GBP/EUR/CAD; invalid codes return 422. Billing defaults USD; settlement defaults billing and is ignored for dual-message AUTHORIZATION. Accepted PR's verifier SDK 0.132.0 lacks these arguments. |
| `status` | AUTHORIZATION, BALANCE_INQUIRY, CREDIT_AUTHORIZATION, FINANCIAL_AUTHORIZATION, FINANCIAL_CREDIT_AUTHORIZATION. OpenAPI default AUTHORIZATION. Explicitly use AUTHORIZATION; financial types can debit/credit immediately and are excluded. |
| `partial_approval_capable`, `pin` | Terminal partial-approval capability and PIN simulation; omission means no PIN check. These influence processing/context, not every POS/authentication field. Use false and omit PIN. |

**Not exposed as simulator inputs:** acquiring institution ID; transaction initiator; conversion-rate representation; acquirer fee/cash/hold objects; merchant optional address/phone details; complete network/POS/AVS/name/authentication/service-location/risk/token/fleet/challenge context. Some are derived from card/program/network state and supplied inputs; the official sources do not guarantee their fixed values or omission. Do not label them all random, and do not invent defaults. [S1], [S4]

The real ASA structure is `event_type: card_authorization.approval_request`, nested `card.token`, structured `amounts`, `merchant`, operation `status`, initiator and context; `token` is the provisional transaction-group UUID. The optional beta `event_token` is not a preauthorization token service. OpenAPI additionally requires deprecated amount fields, nullable context and hold/settlement properties; SDK models tolerate omission of several nullable fields, including merchant contact details. Parsing successfully with the SDK is therefore not identical to satisfying the published schema. [S1], [S4]

**Token timing:** there is no documented token input/reservation before the simulation is submitted. The ASA callback contains a token **before the receiver returns its decision**; the simulator subsequently returns it. Thus it is unavailable for PR #108's advance intent, not unavailable until after the final decision. An online callback-time approval design could bind it then, but that is a different design and is not required for this calibration. A simulator HTTP 201/token alone proves no approval. [S3], [S4]

**Matching uncertainty:** PR #108 signs complete normalized amounts/merchant plus selected supplied context, and requires equality. Even equal-valued conversion rates with different strings, changed context or nullable-property presence can affect that equality. No official simulator-to-full-callback template is guaranteed. A repeated real callback profile could establish bounded observed compatibility; it cannot prove every future callback will be identical or distinguish two purchases with identical terms. Drift must decline and stop. Smallest next step: one unarmed valid-decline request, then compare a second identical-input request already needed for a failure trial. No signed intent or permission is needed.

### Gate 2: what the sources actually guarantee

| Receiver behavior | Independently documented | Still unknown |
| --- | --- | --- |
| HTTP 503 | ASA webhook contract: HTTP 5XX processing failure causes **one immediate retry**. [S1] | Decision after both attempts fail; retry payload/header identity; full retry deadline. |
| Timeout / no response / response after deadline | `ttl` is explicitly **deprecated, approximate** authorization expiry, not a fixed guaranteed response budget. `CUSTOMER_ASA_TIMEOUT` exists as a detailed-result code. [S1], [S4], [S5] | Fixed deadline, time origin, timeout retry behavior, final decision/default policy, acceptance of a late response. |
| HTTP 200 with malformed JSON | `MALFORMED_ASA_RESPONSE` exists as a detailed-result code. [S5] | Retry and final authorization decision. The enum alone is not a fallback guarantee. |
| HTTP 200, string result outside enum | Response property explicitly says transaction **declines with CUSTOM_ASA_RESULT**. This covers an unknown string value. [S1] | This sentence does not define missing `result`, wrong type, non-object JSON or mismatched response token behavior. |
| HTTP 200, invalid decision shape | Schema requires an object and string `result`. [S1] | Validation-error retry and final authorization result; e.g. `{"result":17}`. |

Do not stretch “any other response will decline” in the **result-property description** into a transport-timeout guarantee. CHALLENGE is a special documented result with cardholder constraints, not an ordinary decline. Enrollment exposes `type`/`url`, no `fail_open`, default-policy or timeout field; that proves neither fail-open nor fail-closed. [S1], [S6]

No fixed six-second provider deadline was found in accessible official contracts/examples. Six seconds remains the accepted local target. SDK API-client timeout and the official demo's three-second Lambda execution setting are different timers. The demos' minimal legacy curl payload and optional unsigned/default-approve behavior are unsuitable for unarmed calibration. [S7]

Smallest next action: obtain applicable existing program documentation/configuration if already available to the owner, or conduct the finite fault cases below under explicit sandbox permission. No contacts or additional research program are required by this report. Observations settle the chosen sandbox's behavior; they do not become universal contractual guarantees.

## Conventional controls

Native card pause and spending/merchant rules can solve a $1 cap, merchant restriction and stopping spend. TRANSACTION limits permit repeated spends; FOREVER limits aggregate authorizations; **zero removes a limit, it does not deny all**. SINGLE_USE closes after success and MERCHANT_LOCKED learns the first merchant, changing the VIRTUAL-card scenario. These controls are simpler if spending control alone is the objective. [S8]

A conventional stateful policy gate, or owner-signed capability/JWT plus holder proof, durable revocation/version/nonce/decision state and signed receipts, can provide equivalent enforcement. Basic stateless JWT alone is not the fair comparison. OpenLine's independent experiment is portable Wallet grant/revocation/succession enforced by a separately pinned receiver without trusting the worker's assertion—not unique cryptography or exact owner-signed purchase terms. Keep issuer controls unchanged and allowance sufficient; a paused card/exhausted cap could mask a receiver failure or prevent ASA delivery.

## Smallest unarmed calibration — design only

**Authorization budget:** at most **five sequential new $1 USD AUTHORIZATION simulator POSTs**, zero OpenLine grants, card bindings, challenges or pending intents; no workers/signing authority, clearing, settlement or real funds. Stop at the first unexpected approval. Do not claim zero synthetic provider approvals are guaranteed: fallback is unknown. One case covers no response/timeout/late response together; unknown string decline is already documented and needs no extra probe. If program documentation settles a case first, omit that case. No automatic or manual simulator retry.

| Case | HTTPS responder behavior after verifying real raw-body ASA HMAC | Evidence sought |
| --- | --- | --- |
| U1 — baseline | Fresh unarmed verified OpenLine receiver: valid HTTP 200 decline, normally CARD_PAUSED. Out-of-contract payload may give UNAUTHORIZED_MERCHANT; record it and stop the matching investigation for review. | Actual complete payload, signature compatibility, independently pinned signed local decision, provider decline and response timing. |
| U2 — exhausted 503 | Dedicated calibration transport mode returns empty HTTP 503 for **every** delivery, never invokes an approval path. | Actual retry count/timing and final provider result. Compare normalized terms with U1 for the same simulation inputs; repeat delivery is not a second new transaction sample. |
| U3 — malformed | HTTP 200, application/json, raw body `{`. | Provider validation/error/retry/final result. |
| U4 — invalid shape | HTTP 200, application/json, `{"result":17}`. | Provider invalid-decision handling, distinct from documented custom-string decline. |
| U5 — no timely response | Keep response silent for **at most 30 seconds**, then send valid decline only if still connected. Never emit APPROVED. | Connection/request timing, retries, transaction final result and late-response handling. If Lithic is still waiting at the cap, deadline remains inconclusive: stop, do not extend the probe automatically. |

The fault facade is a future, separately reviewed transport harness outside PR #108; no verified application assertions are changed. It authenticates requests but creates no purchase permission. Fault cases need no fabricated signed authorization receipt. With no owner/card binding, U1's ownerless receipt is collected through the trusted local operator and checked against a receiver key pinned beforehand; do not promise it is available through the owner-scoped integrator route.

**Resources and exact future calls, all requiring permission:** named sandbox program with ASA access; sandbox API key; one existing OPEN VIRTUAL card and securely supplied sandbox PAN; real program ASA secret; approved public trusted-certificate HTTPS ingress preserving raw bytes/headers; supervised protected single-host receiver state and independently enrolled receiver public key. No owner/worker grant is needed for calibration. Inspect `GET /v1/responder_endpoints?type=AUTH_STREAM_ACCESS` and `GET /v1/cards/{card_token}`; enroll only the approved endpoint via `POST /v1/responder_endpoints`; retrieve `GET /v1/auth_stream/secret` (may create secret/activate headers). Do not replace unknown enrollment or rotate keys. Submit up to five `POST /v1/simulate/authorize`; inspect `GET /v1/transactions/{token}` and, only for an ambiguous/missing token, authorized card/time-scoped `GET /v1/transactions`. Existing program records may eliminate setup calls. [S1], [S3], [S6]

Use current reviewed SDK at the recorded SHA with environment sandbox, `max_retries=0`, finite connect/read timeouts (e.g. 5/60 seconds, **not** a provider deadline). Fixed inputs: amount/merchant_amount 100, billing/merchant currency USD, status AUTHORIZATION, descriptor OPENLINE PILOT, ID OL-PILOT-001, MCC 5999, city/state/country NEW YORK/NY/USA, partial approval false, PIN omitted. Settlement currency is unnecessary for this dual-message operation. SDK-default retries are unsuitable: preserved mock evidence shows three simulator POSTs after a 500; no default idempotency header. No call above has been made.

**Observe before advancing:** exact token and event result/detailed results, callback count and authenticated fingerprints, normalized-context differences, elapsed times, unchanged issuer controls and remaining allowance. Record bodies privately without publishing PAN/keys/bearers; preserve only permitted redacted evidence. A simulator error can leave outcome ambiguous—query existing records; do not resubmit. If no ASA arrives, decline from an issuer rule is not evidence about receiver fallback. A late local decline is not proof the issuer declined.

**Immediate stop:** any provider approval; missing/invalid HMAC; wrong card/currency/type/amount; unexpected call/token, unsupported schema, untrusted pin or changed state; ambiguous outcome; unresolved result after the finite observation window; issuer controls masking ASA; credentials/production-resource exposure or cost above the approved ceiling. No further simulation. Preserve evidence. Emergency pause/disarm/enrollment cleanup requires a separately preapproved operator plan; deleting the endpoint may itself change fallback.

**Potential costs/dependencies:** sandbox/ASA eligibility and commercial terms are not verified; API/card restrictions, hosting/domain/certificate charges and existing responder conflicts must be checked. No paid resource or new service is approved. A PAUSED/deny-all card can prevent useful observation, so it cannot be used to guarantee safety while claiming the provider fallback was tested. The experiment relies on a true isolated sandbox and explicit consent to a possible synthetic fallback approval.

If U1 fits and U2 supplies another matching normalized profile, callback matching becomes **observed for this scenario**, still first-match semantics. If all required failure cases decline and timing is understood sufficiently for the bounded run, prepare the existing three-attempt approval/revoke/successor plan with that template and measured budget. If fields drift, propose only the necessary reviewed intent-constraint correction; if fallback approves, do not arm until applicable provider controls genuinely prevent it. Stop once those two gates are settled; do not expand into production infrastructure.

## Official source links

[S1]: https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml
[S2]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/transaction_simulate_authorization_params.py
[S3]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/resources/transactions/transactions.py
[S4]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/card_authorization.py
[S5]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/transaction.py
[S6]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/responder_endpoint_create_params.py
[S7]: https://github.com/lithic-com/asa-demo-node/blob/0c686de3414c2623fc1ea305cf5a235a4e027e28/template.yaml
[S8]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/card_create_params.py

- **S1:** simulator at line 7491; ASA schema at 25790; deprecated ttl at 25860; response at 26259; 5XX retry at 28708; detailed results at 14375; enrollment at 7299; ASA secret at 1665.
- **S2/S3:** current 15 simulator inputs, currency semantics and actual request forwarding; simulation result is a token/debugging ID.
- **S4/S5:** real callback structure, optional fields, token timing and transaction-event evidence.
- **S6/S7/S8:** enrollment fields, demo timer (not provider deadline), native card/spend controls. Demo [README](https://github.com/lithic-com/asa-demo-node/blob/0c686de3414c2623fc1ea305cf5a235a4e027e28/README.md) and [handler](https://github.com/lithic-com/asa-demo-node/blob/0c686de3414c2623fc1ea305cf5a235a4e027e28/webhook/app.js) were read, not executed.
- Documentation site attempted: [ASA](https://docs.lithic.com/docs/auth-stream-access-asa); [simulator reference](https://docs.lithic.com/reference/simulate-authorization). Both were blocked by the environment proxy; no bypass or claims about unseen page contents.

**Stop for owner review.**
