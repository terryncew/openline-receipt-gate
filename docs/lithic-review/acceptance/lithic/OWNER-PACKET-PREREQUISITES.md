# External owner packet prerequisites and exact bounded run

This is a concrete review packet draft, not authorization or an executed pilot. Every external action below is deferred. Current task permits none of: provider API calls, contacts/invitations, enrollment, card issuance, transactions, paid APIs, production credentials/services, deployment, or merge. Any future approval must explicitly name the actions, existing sandbox resources, execution owner, allowed request count, allowed cost, and stop conditions.

## Preconditions to approve an external run

| Required item | Concrete review evidence / action | Current status |
|---|---|---|
| Account/program operator | Named authorized owner of the existing Lithic sandbox program and chosen existing virtual card; dedicated sandbox scope and program identity recorded independently of API responses | Not supplied/verified by this audit |
| API credential | Existing nonproduction key securely supplied for approved enrollment, simulation, and read-only result verification; configure SDK `environment="sandbox"`, `max_retries=0`, explicit timeout; verify the SDK's resolved base URL before any call | No matching exported credential name observed; actual binding unverified |
| Existing test card | Existing OPEN VIRTUAL card token, secure sandbox PAN access only to simulator caller, USD billing, known available authorization capacity, transaction-scoped limit permitting two 100-cent authorizations if needed; no new card issuance in approved scope | None selected or verified |
| ASA key | Program ASA secret securely injected as actual local HMAC key material; never API key or regular webhook secret; signature-header activation on delivered request verified | Not provisioned |
| Enrollment | Review exact intended `POST /v1/responder_endpoints` body `{"type":"AUTH_STREAM_ACCESS","url":"https://<approved-host>/asa"}` and existing enrollment status; no `fail_open` parameter invented; do not replace an unknown existing endpoint | Not called; approved host absent |
| Provider fallback | Program-specific authoritative record of decline on timeout, malformed response, connection failure and exhausted ASA processing retries; record provider deadline and how default authorization policy interacts with ASA | Unknown; official pinned enrollment does not expose these settings |
| TLS/ingress owner | Approved host/deployment, valid trusted certificate, public reachability, process supervision, protected state and credentials, receiver bound to loopback behind safe proxy | No public server/deployment exists |
| Proxy/raw bytes | For `/asa`, preserve exact body bytes and signature values, do not parse/reserialize JSON or change signed body; forward one auth header each, reject ambiguous duplicates/framing, forward finite content length (receiver rejects Transfer-Encoding), no caching; response complete within both actual provider deadline and requested six seconds | Only local HTTP tested |
| Trusted keys | Independently verified owner principal/root key; owner retains root private key. Receiver key generated once at explicit fresh initialization, obtained via trusted local enrollment and pinned independently by integrator before receipts; stable gate ID; reopen with expected receiver key | Only synthetic offline trusted enrollment demonstrated |
| Signed authority | Owner-signed initial Wallet grant of `lithic:authorize` to selected worker; receiver admits the signed bundle and binds exact existing card/mandate/subject; new one-use receiver challenge + actual worker presentation + signed payment intent for confirmed terms | Only offline examples exercised |
| Storage | Protected single-host SQLite state plus WAL/SHM and stable receiver identity; no old-state restoration; only trusted local operator accesses administration; no public admin route | Deployment protection unverified |
| Receipt ACL | Separately provisioned secure integrator bearer credential >=32 characters, enrolled locally to the selected owner principal; trusted receiver key provisioned separately; `/receipts/<token>` HTTPS or approved private route; no bearer/key/database export | Only offline synthetic credential demonstrated |
| Reproducible terms | Valid <=15-character simulator acceptor ID and confirmed provider-generated exact `payment_details` template; no arbitrary `acquiring_institution_id`, POS/AVS, or risk-context guessed from fixture | Unresolved interoperability prerequisite |
| Costs/dependencies | Operator verifies sandbox fees, API limits, card authorization limits and hosting/TLS costs; approved ceiling stated; Python receiver dependencies, pinned SDK/webhook verifier, network to sandbox host, stable clock and trusted storage present | No paid resources allocated or used |

The ASA key retrieval GET may create a key and activate headers if none exists. Include it explicitly in future approval if needed; do not run it as an innocuous read. Rotation is outside the minimal three-stage run: if separately approved, rotation POST creates the new key, GET retrieves it, receiver accepts explicit current/previous keys during overlap, and removes the retired key no later than the documented 24-hour deactivation.

## Simulator request template

Use the selected sandbox PAN through a secure runtime binding, never a saved value. Proposed nonsecret inputs:

```
amount = 100
descriptor = "OPENLINE PILOT"
merchant_acceptor_id = "OL-PILOT-001"
merchant_acceptor_city = "NEW YORK"
merchant_acceptor_state = "NY"
merchant_acceptor_country = "USA"
mcc = "5999"
merchant_amount = 100
merchant_currency = "USD"
status = "AUTHORIZATION"
partial_approval_capable = false
```

With the current official SDK at `826a8c940571e88bd4682a38e22b1c9f999cef93`, additionally specify `billing_currency = "USD"`; the older pinned v0.132.0 method does not accept that keyword. Omit PIN. Do not switch to FINANCIAL_AUTHORIZATION, authorization advice, clearing, settlement, credit, reversal, new card creation, or production environment. USD merchant currency must be explicit when merchant amount is supplied; the current official simulator documentation says its default in that case is GBP.

These inputs do not define the complete ASA payload. Resolve provider-generated fields before signing the intent. The fixture's `OPENLINE-SYNTHETIC-001` acceptor ID cannot be copied: it exceeds the simulator's 15-character maximum.

## Proposed approved run, after prerequisites are resolved

Run one selected existing sandbox card, one owner, one receiver, one integrator. Permit at most three new 100-cent simulator requests for the approval/revocation/successor sequence, producing at most two synthetic approvals (200 cents total authorized, zero clearing requested). If template calibration is necessary, explicitly approve one additional 100-cent request with no pending authority; it must decline and consumes a separate transaction token. Do not let SDK/manual retries exceed the authorized count. New simulator calls create new transaction groups; they cannot be used to replay a previously acknowledged ASA token.

1. **Approve.** Independently pin owner root and receiver public key. Admit owner's initial grant bundle; bind existing card to worker A. Issue a fresh receiver challenge; worker A makes the actual presentation and signs confirmed payment details; `pre_authorize` must return authorized with an expiry <=60 seconds and no live competing pending intent. Within that window, make exactly one simulator request. Observe one provider-signed ASA request, receiver HTTP 200 `{"result":"APPROVED"}`, one consumed pending intent and durable signed receipt bound to provider transaction token, matched owner/mandate/subject, exact terms and authenticated content fingerprint. Verify receipt hash/Ed25519 signature independently using the pre-pinned receiver key. Retrieve provider transaction by returned simulator token: verify its authorization event and result independently. HTTP 201 from simulate alone is not approval evidence. Restart receiver using expected key and verify the same receipt remains retrievable.

2. **Revoke and decline.** While worker A is still authorized, create one fresh pending intent through a new challenge/presentation. Owner invokes real Wallet revoke of A's mandate, exports the updated root-signed bundle, and trusted operator admits it. Verify admission completed and pending intent was invalidated. Restart receiver with same key. Make one new, otherwise matching simulator request with a distinct provider-generated transaction token. Expect receiver HTTP 200 `{"result":"CARD_PAUSED"}`, durable signed decline receipt, no consumption of revoked authority and no new approval. After admission has removed the pending row, the normal receipt reason is `NO_PENDING_AUTHORIZATION`; the admitted owner-signed revocation bundle supplies revocation evidence. Verify corresponding provider authorization event declined. An identical retry of the first already committed token can legitimately acknowledge its old approval; it is not a new revocation trial.

3. **Successor.** Owner gives worker B a new signed `lithic:authorize` mandate and exports updated bundle. Admit it; bind the same existing card to B's mandate/subject. B issues a fresh verified presentation from a new receiver challenge and signs confirmed matching terms. Preauthorize exactly one new intent, then make one new simulator request within expiry. Expect receiver HTTP 200 APPROVED, one durable signed receipt naming B/new mandate, old authority unable to reuse the new pending permission, and provider's new authorization event approved for exactly 100 USD cents. Verify all receipts with the original receiver pin. No settlement/clearing request is made.

Safe receipt observables before external run: missing/wrong bearer gives 401; unknown/inaccessible owner receipt gives the same 401; valid owner-mapped bearer retrieves only that principal's signed persisted receipt; GET does not alter authority. Confirm these through local synthetic checks; do not add external requests just to test ACL.

## Stop conditions

Stop before simulator/enrollment actions when a prerequisite is unknown. During the approved run, stop on missing/invalid provider signature, unexpected field/template drift, wrong owner/card/currency/amount/status/initiator, untrusted key/certificate, unavailable/corrupt/restored receiver state, receipt mismatch, unexplained provider/receiver result disagreement, response exceeding either confirmed provider deadline or six-second requested budget, revocation decline failure, or any ambiguous simulator timeout/non-2xx response. Do not retry a simulation automatically or manually after ambiguity; first inspect authorized provider records for the attempt. Stop before additional requests, key rotation, endpoint replacement/cleanup, deployments or services beyond the named approval. Costs above the explicit approved ceiling also stop the run.

A signed receiver receipt proves its ASA decision. Provider transaction evidence proves provider handling of that authorization. Neither proves purchased goods, card-network settlement, power-loss durability, protected hosting or delivery of a revocation not admitted by the receiver. Before initial ASA token assignment, this contract authorizes the first identical matching purchase inside the short window; it does not identify a unique merchant order. Owner must explicitly accept that first-match limit.
