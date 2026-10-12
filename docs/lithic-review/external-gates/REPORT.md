# OPENLINE-LITHIC-EXTERNAL-GATES-001

**NO-GO for armed external testing. Both gates are PARTIALLY RESOLVED.** Current official sources identify simulator inputs, token timing, 5XX retry and custom-string decline, but do not establish a complete predictable callback template or final provider failure/default behavior and deadline. The next justified step is a separately approved **unarmed** calibration; none was executed.

Read the existing audit/owner packet and reused accepted offline evidence. **No test reruns, repository/PR changes, branch, provider API calls, deployment, enrollment, outside contact, transactions or paid APIs.** Full source extracts, retrieval errors/hashes and calibration details are preserved in [SOURCE_ANALYSIS_AND_CALIBRATION.md](SOURCE_ANALYSIS_AND_CALIBRATION.md).

## 1. Callback matching — PARTIALLY RESOLVED

Fresh official heads match the previous audit: [OpenAPI at 0afad9e][spec] and [Python SDK at 826a8c9][params]. The SDK exposes these **15** input fields:

| Inputs | Documented controls and limitations |
| --- | --- |
| `pan`, `amount`, `descriptor` | Required card selection, authorization amount and descriptor. PAN length 16; amount integer 0–2 billion; descriptor length 1–25 in OpenAPI. |
| `mcc`, `merchant_acceptor_id`, `merchant_acceptor_city`, `merchant_acceptor_state`, `merchant_acceptor_country` | MCC is four-digit ISO18245; ID length 1–15, city<=13, state<=3, country length 3 / ISO alpha-3. No registered-ID allowlist is documented. `OL-PILOT-001` fits syntax; actual API acceptance is unobserved. Lab ID length 22 fails simulator syntax. |
| `merchant_amount`, `merchant_currency`, `billing_currency`, `settlement_currency` | Explicitly use amount 100 and USD merchant/billing currency. SDK defaults merchant currency to GBP when merchant amount supplied; billing defaults USD. Settlement defaults billing and is ignored for dual-message AUTHORIZATION. |
| `status`, `partial_approval_capable`, `pin` | Five operation types; use explicit AUTHORIZATION, false partial approval and omit PIN. Financial operations can debit/credit immediately and are excluded. |

**Source discrepancies:** published OpenAPI omits billing/settlement currency inputs. It documents USD/GBP/EUR with fallback GBP for another merchant ISO code; current SDK adds CAD and says invalid codes return 422. Accepted verifier SDK 0.132.0 lacks the new inputs. OpenAPI requires certain nullable properties that SDK models allow omitted. These are documentation differences, not observed API behavior. [spec], [params], [callback]

**Not controllable through those inputs:** acquiring institution, full network/POS/AVS/authentication/risk/service-location/token/fleet/challenge context, transaction initiator, conversion-rate representation, cash/fees/hold details and optional merchant contact fields. Values may be derived from supplied inputs/card/program/network state; no fixed defaults or complete callback template are guaranteed. PR #108 signs complete selected objects/context and requires equality, so guessed values cannot establish reliable matching.

Real ASA is `card_authorization.approval_request`, with `card.token`, structured `amounts`, merchant, operation and context. **No token input or advance reservation is documented.** The callback contains its provisional transaction token before the receiver decides; the simulator returns it afterward. It is unavailable for PR #108's advance intent, not unavailable until after final approval. Exact order/token binding remains outside that preauthorization contract. [callback], [resource]

**Smallest action:** obtain an applicable guaranteed template, or capture a valid unarmed callback and compare a second same-input transaction already needed for the 503 trial. This establishes observed compatibility for one scenario, not universal predictability. Drift must decline and stop; no silent constraint removal.

## 2. Timeout/failure behavior — PARTIALLY RESOLVED

| Case | Official evidence | Unresolved |
| --- | --- | --- |
| HTTP 503 | Any 5XX causes **one immediate retry**. | Final decision after exhausted failures, complete retry deadline/payload identity. |
| Timeout/no response/late response | `ttl` is **deprecated, approximate** expiry; CUSTOMER_ASA_TIMEOUT exists as a detailed-result code. | Fixed deadline/time origin, timeout retries, default/final authorization decision, late-response treatment. |
| Malformed JSON | MALFORMED_ASA_RESPONSE exists as a detailed-result code. | Retry/final decision; an enum is not a fallback guarantee. |
| Unknown string decision | Result-property description explicitly guarantees decline with CUSTOM_ASA_RESULT. | Does not define wrong type, missing result, non-object JSON or bad response token. |
| Invalid response shape | Schema requires object plus string result. | Final validation-error behavior. |

Evidence is the official [ASA response/webhook contract][spec] and [transaction model][transaction]. Do not interpret “any other response” in a result-property description as a timeout guarantee. Enrollment exposes type/url, no `fail_open` control. No fixed six-second provider deadline was established; the requested local budget, SDK request timeout and demo Lambda's three-second setting are distinct timers. Public documentation pages returned proxy 403 and were not read. [spec], [demo]

**Smallest action:** applicable existing program evidence, or finite sandbox fault observations below. No outside contact occurred or is required by this report. Observations characterize that sandbox, not a universal contractual guarantee.

## 3. Conventional-controls comparison

[Native card controls][cards] can cap spending, pause a card and restrict merchant use. TRANSACTION permits repeated spending; FOREVER limits aggregate authorizations; zero removes a limit. These are simpler if the goal is merely $1 and stopping spend. Issuer pause/cap exhaustion can also mask whether ASA enforcement worked.

An ordinary stateful policy gate or signed capability/JWT with holder proof, durable revocation/nonces/decisions and signed receipts can match OpenLine's guarantees. The distinct experiment is a separately pinned receiver enforcing portable Wallet grant/revocation/succession independently of a worker's assertion. No competitive or unique cryptographic advantage is presumed; owner scope remains reusable delegation, not exact purchase consent.

## 4. Exact next experiment — design only

At most **five sequential $1 USD AUTHORIZATION POSTs**, omitting any case already settled by applicable documentation. **Zero OpenLine grants, card bindings, challenges or pending intents; no worker authority, clearing, settlement or real funds.** An unknown provider fallback could nevertheless record a synthetic approval; first such result stops execution.

1. **U1:** actual unarmed receiver returns valid HTTP 200 decline. Capture authenticated full callback, independently pinned signed local decision, provider result and timing. Unsupported/out-of-contract payload stops matching review.
2. **U2:** dedicated authenticated transport probe always returns empty 503. Observe retry and final result; compare normalized fields with U1's same simulation inputs.
3. **U3:** HTTP 200 application/json with body `{`. Observe malformed-response handling.
4. **U4:** HTTP 200 application/json with `{"result":17}`. Observe invalid shape; no extra custom-string trial is needed.
5. **U5:** no response for at most 30 seconds, then valid decline only if connected. Observe timeout/retries/late response and final result. If still waiting at the cap, stop with deadline inconclusive; do not extend automatically.

Fault modes require a separately reviewed future transport harness outside PR #108. No approval path exists; no verified tests/assertions change. Use current reviewed SDK, sandbox environment, **max_retries=0**, finite timeouts. Fixed inputs: secure selected PAN, amount/merchant_amount 100, USD billing/merchant currency, AUTHORIZATION, descriptor OPENLINE PILOT, ID OL-PILOT-001, MCC 5999, NEW YORK/NY/USA, partial approval false, PIN omitted. Full timings, modes and comparison rules are in the linked detailed plan.

**External prerequisites/calls requiring explicit permission:** existing eligible sandbox program/API key, one OPEN VIRTUAL sandbox card/PAN, program ASA secret, approved public trusted-certificate HTTPS ingress preserving raw bytes/headers, protected persistent receiver state/key and independent public-key pin. Inspect GET `/v1/responder_endpoints?type=AUTH_STREAM_ACCESS` and GET `/v1/cards/{card_token}`; enroll approved endpoint via POST `/v1/responder_endpoints`; GET `/v1/auth_stream/secret` may create key/activate headers. Up to five POST `/v1/simulate/authorize`; GET `/v1/transactions/{token}`, or authorized card/time-scoped transaction listing after ambiguity. No endpoint replacement/rotation/card issuance/new service without separate scope. [spec], [resource]

A simulation 201/token is not approval evidence: compare actual AUTHORIZATION event/result/detailed results, authenticated fingerprints, callback counts and timings. No callback or issuer-rule decline does not test fallback. With no owner binding, U1's ownerless signed decision is inspected locally; do not promise owner-scoped receipt retrieval. Fault cases need no fabricated signed decision.

**Stop:** provider approval, invalid/missing HMAC, wrong card/terms, drift/unsupported schema, untrusted pin/corrupt state, unexpected call/token, ambiguous/unresolved outcome, issuer rules masking ASA, production/credential exposure or excess cost. No simulator resubmission after ambiguity. Preserve evidence and use only authorized record reads; emergency pause/disarm/enrollment cleanup must be preapproved separately.

**Costs/restrictions:** sandbox/ASA access terms, API/card limits, hosting/domain/TLS costs and existing endpoint conflicts are unverified. No resource is assumed free or approved. A paused/deny-all card might suppress ASA and cannot both guarantee zero approval and prove unknown fallback behavior. Use true isolated sandbox and explicitly accepted synthetic-only risk.

## 5. Recommendation

**NO-GO armed; unarmed calibration justified for owner review.** After actual fields match and required failure cases decline with an understood usable timing budget, use that template for the existing three-attempt approval/revoke/successor plan. Field drift needs only the minimal reviewed intent correction; provider fallback approval needs actual fail-closed provider controls before arming. Stop once these gates are settled.

[spec]: https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml
[params]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/transaction_simulate_authorization_params.py
[callback]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/card_authorization.py
[resource]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/resources/transactions/transactions.py
[transaction]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/transaction.py
[demo]: https://github.com/lithic-com/asa-demo-node/blob/0c686de3414c2623fc1ea305cf5a235a4e027e28/template.yaml
[cards]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/card_create_params.py
