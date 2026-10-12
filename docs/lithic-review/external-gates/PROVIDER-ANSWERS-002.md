# LITHIC-EXTERNAL-GATES-002 — provider written-evidence answers

**Overall: UNRESOLVED; external execution remains NO-GO.** The pinned sources verify several contracts but do not establish the three material provider guarantees. No applicable program-specific written answer, selected program or card is supplied. Nothing below claims actual provider fail-open or a live failure.

Starting branch: `codex/openline-lithic-preflight-001`, commit `c0d4adaf13300eafbb9506e4533c80032a4928fc`. Read HANDOFF, EVIDENCE_CLOSURE, CONTAINMENT_REVIEW and the owner packet first. Historical 104/104 offline acceptance stands; no tests or experiments rerun. This work used only existing evidence and unauthenticated public-document/GitHub-source reads. No provider operational API, credentials, support submission, deployment or transaction.

## Evidence scope, version and freshness

Reviewed October 11, 2026 (owner/client timezone). A fresh public GitHub head check returned the **same** pins; no newer source was available from those heads to answer a blocker:

| Source | Applicable version/date | Scope and limitation |
| --- | --- | --- |
| [Official OpenAPI][spec] | Commit `0afad9e69e57f2e0bbace17c1f03f79c97c07c76`, September 16, 2026; spec info version 1.0.0; SHA256 `13f01516dfbc129804b5086b1a45beb8e413b24148458af234e01e46a1a4f09c` | Generic published API/schema and descriptions. Not a selected program's configuration, commercial agreement or observed callback. Preserved locally as `openapi-current.yml` and `extracted-contracts.json`. |
| [Official current simulator parameters][params], [callback model][callback], [resource][resource] | SDK head `826a8c940571e88bd4682a38e22b1c9f999cef93`, October 8, 2026 | Generated SDK contract; general program conditions/beta fields are indicated where documented. Does not prove backend defaults or complete callback predictability. It is newer than accepted verifier SDK 0.132.0. |
| [Accepted SDK 0.132.0 client][client] | Commit `a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f` | Historical local verifier/caller-default evidence, not a deployed sandbox controller. |

Only potentially decisive pages were retried. Each normal HTTPS request failed at the environment proxy with `Tunnel connection failed: 403 Forbidden`: [ASA](https://docs.lithic.com/docs/auth-stream-access-asa), [sandbox candidate path](https://docs.lithic.com/docs/sandbox), [public support portal](https://support.lithic.com/), [terms](https://lithic.com/legal/terms). No content, access-controlled support answer or newer policy was read; the candidate sandbox article's existence is not established. No bypass or authentication was attempted. Official source heads were checked through public GitHub, not Lithic's operational API. No need to repeat settled simulator/HMAC research.

## 1. Sandbox isolation

| Property | Status | Direct evidence / remaining question |
| --- | --- | --- |
| Documented sandbox destination and simulation semantics | **VERIFIED** | [OpenAPI lines 15–16][sandbox] designate `https://sandbox.lithic.com`; [simulator description][simulate] says it simulates a card-network authorization as if from an acquirer. This is a label/operation description, not proof that our proposed resources are correctly isolated. |
| Actual card-network activity or real-fund movement excluded | **UNRESOLVED** | No applicable no-real-network/no-real-funds guarantee or its exact conditions exists in the reviewed evidence. No resources are selected. Need provider conditions for sandbox-only credential/program/card/destination separation, including fallback and partial approvals. |
| Unexpected synthetic approvals excluded | **UNRESOLVED** | The [ASA response contract][result] explicitly accepts APPROVED, so simulation is approval-capable by design. An unarmed OpenLine responder does not exclude an independently approving default/fallback. No unexpected provider approval was observed. |
| Fees, quotas, entitlements or contractual charges | **UNRESOLVED** | Sources do not establish free use; current terms were unreadable. Need sandbox/ASA charges or account-contract conditions and limits. Hosting/domain costs are owner-side, not Lithic authorization semantics. |
| Effects on other programs/cards and responder enrollment scope | **UNRESOLVED** | [Responder enrollment/status schema][enroll] exposes type/url/enrolled; no card selector or routing/isolation guarantee. It does not establish cross-program effects or safe replacement of an existing responder. Need applicable scope; do not infer a shared endpoint is dedicated to our card. |

**Support response required:** yes, unless the owner supplies equivalent applicable official written evidence. Ask only for conditions and nonsecret ways to verify them; do not provide a PAN, API key, secret or invented program/card. A program-dependent answer stays conditional until the owner later identifies and verifies resources. No public guarantee of zero fees or real-fund isolation is claimed.

## 2. Authorization callback compatibility

### What the request controls

The current SDK exposes 15 fields: `amount`, `descriptor`, `pan`, `billing_currency`, `mcc`, `merchant_acceptor_city/country/id/state`, `merchant_amount/currency`, `partial_approval_capable`, `pin`, `settlement_currency`, `status`. The published OpenAPI exposes 13, omitting billing/settlement currency. [params], [simulate]

For this proposed profile, desired terms are 100 USD cents, merchant amount 100/USD, dual-message AUTHORIZATION, no PIN/partial approval. The current SDK documents billing defaultUSD and merchant defaultGBP when merchant amount supplied: specify USD explicitly. Settlement currency is ignored for dual-message authorizations. The SDK adds CAD/422 validation versus OpenAPI's older USD/GBP/EUR/GBP-fallback description; this discrepancy is documented, not an observed API failure, and unrelated-currency research is unnecessary.

Merchant ID input is length 1–15 with no schema regex/registered-ID allowlist. Descriptor length 1–25, city<=13, state<=3, country exactly3/ISO alpha-3; MCC is four-digit ISO18245. [OpenAPI constraints][merchant-input] A tentative `OLPILOT001` is 10 alphanumeric characters, consistent with the callback's alphanumeric merchant-ID description; it is a synthetic label, not an actual merchant or proven accepted value. The old22-character lab ID cannot be simulator input. Earlier hyphenated suggestions remain historical; no existing fixture or contract is changed. [Merchant schema][merchant]

Supplying an input does not guarantee byte-identical callback echo or normalization. The worker can sign **desired input-derived terms** and a known card identity after future selection. It cannot yet reliably sign PR108's entire exact normalized callback object before delivery: no complete template or fixed generated defaults is established.

### Full documented callback coverage, not an invented concrete callback

The [webhook schema][webhook] combines `event_type: card_authorization.approval_request` with [authorization][authorization]. These are all 18 required authorization top-level fields and all 13 optional fields. A fully concrete 100/USD body cannot be produced from available evidence without guessing generated data.

| Fields / nested structure | Control, possible variation and advance-signing limit |
| --- | --- |
| `event_type`; `status` | Constant event type; chosen operation should be AUTHORIZATION. Other operation types are out of pilot scope. |
| `card` | Required token/last_four/memo/spend_limit/duration/state/type reflect selected card state, not arbitrary simulator parameters. PAN selects the card. Identity can be known after authorized selection; card state may change. Pilot requires OPEN VIRTUAL. No card is selected now. |
| `amounts` | Required cardholder(amount/currency/conversion_rate), merchant(amount/currency), and nullable hold/settlement properties. Desired cardholder/merchant100/USD. Conversion-rate string representation and hold/null presence are derived/unsupported controls; hold adjustments depend on program/MCC. Equal numeric rates with different strings can fail exact object equality. |
| `amount`, `authorization_amount`, `cardholder_currency`, `merchant_amount`, `merchant_currency`, `settled_amount` | Required deprecated fields must agree with structured amounts for the pilot. Actual consistency/format/defaults are provider-derived; no complete emitted profile is guaranteed. |
| `merchant` | Required acceptor_id/acquiring_institution_id/city/country/descriptor/mcc/state; published allOf also requires nullable phone_number/postal_code/street_address. SDK permits those contact fields omitted. ID/MCC/descriptor/location have request controls; **acquiring institution and contact fields do not**. Sample institution IDs are examples, not defaults. |
| `avs` | Required address/zipcode/address_on_file_match. Match outcome depends on supplied/network/KYC data; simulator has no AVS controls. Do not guess NOT_PRESENT or empty strings. |
| `name_validation`, `service_location` | Required nullable context in OpenAPI; SDK permits omission. Source/program/network-derived, no simulator setter. Null/absence and object values are not proven predictable. |
| `cash_amount`, `acquirer_fee`, `transaction_initiator` | Required. Conditional source descriptions specify zero when no cash/fee, but simulator has no direct setter for these or initiator. Receiver requires zero/zero/CARDHOLDER; not established as a fixed complete simulator profile. |
| `created`, `token` | Required timestamp and provisional transaction-group UUID. Not selectable simulator inputs; vary with transactions. Token arrives **in ASA before decision**, then simulator response returns it. It cannot be preselected for advance intent. |
| Optional `account_type`, `cardholder_authentication`, `pos`, `network`, `network_risk_score`, `network_specific_data`, `token_info`, `fleet_info`, `latest_challenge` | Program/card/network/context-derived, not fully controlled by inputs. Partial-approval/PIN inputs may affect parts of POS/authentication but do not choose complete objects. Which fields vary per request is unknown. |
| Optional `cashback`, `conversion_rate`, `ttl`, `event_token` | Deprecated cash/rate/approximate-expiry context and beta-only event identifier. None provides a selectable advance transaction token or fixed response deadline. |

**VERIFIED:** schema structure, exposed controls, documented token timing and conditional field descriptions. **UNRESOLVED:** complete deterministic values/presence/normalization for the proposed scenario, acquiring institution and every selected dynamic context field. The SDK's tolerant model does not guarantee schema-conforming full bodies. [callback]

PR108's [payment_details](https://github.com/terryncew/openline-receipt-gate/blob/c0d4adaf13300eafbb9506e4533c80032a4928fc/gateway/receiver-package/openline_receiver/lithic_adapter.py#L58) binds whole amounts/merchant plus selected context, and exact equality is required. Known desired inputs alone cannot establish a matching signed intent. No security assertion should be weakened. **Support response required:** yes for a guaranteed profile/identification of fields that cannot be predetermined; if guarantees are unavailable, say so and leave empirical compatibility for a later separately approved unarmed observation. Identical purchases remain first-match semantics even with a stable template.

## 3. Failure behavior, retries, deadline and abort

| Responder case | Status | Established and missing evidence |
| --- | --- | --- |
| HTTP503 / repeated 503 | Retry **VERIFIED**; final decision **UNRESOLVED** | [Webhook contract][webhook] documents one immediate retry for 5XX. It does not specify final outcome after both fail, total deadline or retry body identity. |
| Timeout/silence/late full response | **UNRESOLVED** | No fixed numeric provider deadline, time origin, per-attempt/total retry budget or late-response treatment in reviewed sources. [ttl][ttl] is explicitly deprecated/approximate. CUSTOMER_ASA_TIMEOUT is an enum, not a guaranteed authorization action. |
| HTTP200 malformed JSON | **UNRESOLVED** | MALFORMED_ASA_RESPONSE enum exists; retry/final decision/default policy not established. |
| HTTP200 invalid response shape | **UNRESOLVED** | Contract requires an object and string result. Missing/wrong-type/non-object result handling is not specified beyond that schema. |
| Unknown string result | **VERIFIED** | [Result description][result] explicitly says decline with CUSTOM_ASA_RESULT. This already answered case needs no support question or extra probe. CHALLENGE is a separately qualified result. |
| Unavailable receiver: connection refusal/DNS/TLS failure | **UNRESOLVED** | No applicable final decision, retry schedule or issuer-default setting shown. A local fail-closed endpoint cannot attest to issuer action. |
| Safe abort / responder removal or card pause | **UNRESOLVED provider consequences** | Endpoint DELETE exists but does not establish authorization/default-policy effects. Teardown is not reversal. Native card pause can prevent useful ASA observations; ordering and scope need applicable confirmation. |

The result property's “any other response” text does not establish transport-failure behavior. SDK's API-client timeout, demo Lambda's timer and the requested local six-second target are not provider deadlines. [Enrollment][enroll] has no `fail_open`, default-policy or deadline field; absence establishes neither approval nor decline. **Support response required:** yes, with program-dependent policy/defaults explicitly identified, including safe-abort consequences. No provider failure is marked FAILED without observation or applicable contradictory evidence.

## Disposition

All three material provider blockers remain **UNRESOLVED**; their settled subfacts are **VERIFIED**. No actual provider fail-open, network/fund escape or unsafe deployment is demonstrated **FAILED**. Existing failed sufficiency claims (SDK defaults; empty pending/initialize flag) concern owner configuration, detailed in [READINESS-002](READINESS-002.md).

The [support draft](LITHIC-SUPPORT-DRAFT.md) is ready for owner review, not transmission. Written answers may remove probes; no five-case sweep, fixed 30-second timeout experiment, code change or calibration begins here. Operational preparation/execution remains NO-GO. No selected resources or provider portability claim is invented.

[spec]: https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml
[sandbox]: https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L15
[simulate]: https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L7477
[merchant-input]: https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L7528
[merchant]: https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L19910
[authorization]: https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L25790
[webhook]: https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L28678
[result]: https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L26259
[ttl]: https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L25860
[enroll]: https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L7299
[params]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/transaction_simulate_authorization_params.py
[callback]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/card_authorization.py
[resource]: https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/resources/transactions/transactions.py
[client]: https://github.com/lithic-com/lithic-python/blob/a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f/src/lithic/_client.py
