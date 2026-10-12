# Owner approval packet — bounded Lithic sandbox experiment

**Offline preflight: ACCEPT. External sequence: defer until the two provider gates below are resolved.** This is a review packet, not permission or an executed pilot. Detailed operational steps are in [OWNER_RUNBOOK.md](OWNER_RUNBOOK.md); findings and reproducible evidence are in [AUDIT.md](AUDIT.md).

The purpose is to test whether a receiver operated independently of the worker enforces portable owner-signed Wallet delegation, admitted revocation and successor authority on the same card. Ordinary card controls or an equivalent stateful policy gate can also authorize and stop spending; no unique cryptographic advantage is claimed.

## Scope to approve

One named sandbox program, one OPEN VIRTUAL sandbox card, one owner, workers A/B, one receiver and one receipt integrator. The full sequence needs **three $1 authorization attempts: two intended approvals ($2 total synthetic authorized), one decline, no clearing or settlement**. Optional unarmed template calibration needs **one separately approved $1 attempt expected to decline**. Any fault trial or additional attempt is separately scoped. If permission covers literally one total authorization attempt, it cannot cover the complete sequence.

The owner grants reusable `lithic:authorize` scope; receiver policy fixes each purchase at 100 USD cents; the worker signs payment terms. This is not owner-signed exact purchase consent or an aggregate $1 cap. An intent lasts at most 60 seconds and permits the first matching authenticated callback. Exclusive card control and no earlier in-flight matching request are required; identical purchases cannot be distinguished in advance by an unknown Lithic token.

## Gates and enrollment

| Required item | Evidence/action before arming |
| --- | --- |
| **Actual request template** | Simulator parameters cannot set all currently signed callback fields. Confirm a program-specific predictable template or separately approve an unarmed calibration with an explicitly declining receiver. Unknown or unstable fields stop the run; do not silently relax signed constraints. Use a merchant ID <=15 characters; the lab fixture's 22-character ID is unsuitable for simulation. |
| **Provider failure/default policy** | Record actual-program behavior on connection failure, timeout, malformed response and exhausted retries, and its deadline. Local HTTP 503 does not prove provider decline. Applicable authoritative evidence may suffice; a bounded fault trial requires separate approval if needed. Enrollment has no documented `fail_open` parameter. |
| Sandbox access/resources | Name the authorized program/operator and card; verify ASA eligibility, sandbox credentials/base URL, USD billing and available allowance. Selecting/using a card needs approval; issuance, contacts/invitations or new services require separate explicit scope. No production credentials/card or real funds. |
| Keys and credential isolation | Authenticate owner/card-account relationship and independently pin owner root. Owner retains root private key; A/B each hold only their own worker key. Receiver generates/protects its receipt key once; integrator independently authenticates/pins its public key before ASA. Control-plane API key/PAN, program ASA secret, receiver key and owner-scoped strong receipt bearer remain separate; workers get no administration or those credentials. |
| Hosting/state | Approved trusted-certificate HTTPS ingress to supervised loopback receiver running delivery `8a537d4ff598541bb21cc564b3220ec97ef09fb3` (runtime matches tested `abf6bc72f4375bd43d2c274812e5dadd68f03e41`). Preserve original body bytes/signature headers; reject ambiguous framing, forward finite Content-Length; keep administration local and receipt access authenticated. Protect persistent SQLite/WAL/SHM/keys, stable clock and receiver pin; never restore older state. No credential/raw-body logging. |
| Actual ASA enrollment/secret | Review existing endpoint before approved `POST /v1/responder_endpoints` with type AUTH_STREAM_ACCESS and intended HTTPS URL. Do not replace an unrelated endpoint. GET `/v1/auth_stream/secret` can create the key and activate headers, so it needs permission despite GET. Inject the actual ASA key securely; it is not the API key or ordinary webhook secret. Verify real signature activation before arming. Rotation is outside this run. |

## Caller and observable sequence

Use a sandbox-only SDK client with **`max_retries=0`**, finite timeout and secure PAN binding. Never resubmit after ambiguous failure. Proposed nonsecret terms: amount 100, merchant amount 100, merchant currency USD, status AUTHORIZATION, no partial approval/PIN, merchant ID `OL-PILOT-001`, fixed reviewed descriptor/MCC/location. Current SDK can explicitly set billing currency USD; pinned 0.132.0 cannot, so confirm program billing instead. Merchant currency otherwise defaults to GBP with merchant amount supplied. These parameters do not determine all signed ASA context.

| Stage | Required action and result |
| --- | --- |
| **A approval** | Admit genuine signed A grant; bind card; A supplies fresh receiver challenge, verified Wallet presentation and signed confirmed intent. One $1 attempt within expiry must yield valid provider HMAC, HTTP 200 APPROVED, one consumed intent, durable A receipt and matching provider approval. Restart; receipt remains verifiable. |
| **Revocation → decline** | First create a valid, unconsumed A intent and record expiry. Owner signs revoke; receiver admits newer bundle and commits pending invalidation. Restart, then one new matching $1 attempt while the removed intent would otherwise remain valid. Require CARD_PAUSED and provider decline. Keep card state/rules/allowance unchanged: cap exhaustion or expiry would make revocation attribution inconclusive. Preserve admission ordering; decline receipt normally says NO_PENDING_AUTHORIZATION and does not itself prove revocation causality. |
| **B successor approval** | Admit genuine new B grant, bind the same card, obtain fresh B presentation/intent and, within expiry after reopening retained state, submit one new $1 attempt. Require APPROVED, signed B/new-mandate receipt and provider approval. Verify receipts after restart; A cannot use B authority. |

Record distinct **provider-returned** tokens; callers cannot preselect them. An identical retry of a committed A token may correctly acknowledge its historical approval after revocation. A simulator HTTP 201/token is not approval evidence: retrieve its provider AUTHORIZATION event/result and compare with the receiver. Record authenticated request fingerprints/terms, timings, authority heads/admission ordering and unchanged issuer controls with adequate allowance; a lifetime $1 cap would mask this experiment.

Retrieve `/receipts/{token}` with the owner's enrolled read-only bearer. Independently check canonical hash and Ed25519 signature with the pre-pinned receiver key, plus token/result/terms/worker/mandate. Separately verify root-signed bundles/epoch certificates, certified-epoch-signed grants, root-signed revocation and ancestry. Never adopt a receipt's embedded key as trust. Capture sensitive provider evidence privately, with no credential publication.

## Stop and permission boundary

Stop before arming on unresolved gates, costs, enrollment or trust. Immediately stop on invalid/missing HMAC, template drift, wrong terms/card/pin, unavailable/corrupt/restored state, unexpected retry/extra token, receipt failure, ambiguous timeout, provider/receiver disagreement, unarmed/revoked approval, or response exceeding the confirmed deadline or requested six seconds. Issue no further simulation calls; preserve evidence and inspect only authorized records. Future approval must name an emergency operator and separately authorize safe disarming/card pause/endpoint cleanup; changing an endpoint can change fallback.

**Prepared offline:** exact code/evidence, 104 passing checks, signature verifiers, request/run/stop plan. **Requires explicit permission:** account/resource use, credentials/enrollment/secret activation, key enrollment, public hosting, card selection or issuance, every external attempt/result query and emergency external controls. No such action occurred or is approved here.

Owner must verify sandbox eligibility/fees, API limits and hosting/domain/TLS costs and state an allowed ceiling; none is assumed free or approved. Dependencies are the authorized sandbox program, real signed callbacks, protected approved host/ingress, pinned Python SDK/crypto dependencies and stable state/clock. No paid API, new external service, production deployment, real funds, clearing, merge or outside contact is authorized. **Stop for owner review.**
