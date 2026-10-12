# Bounded Lithic ASA sandbox preflight contract

This contract covers one receiver, one pinned owner, one virtual-card identifier, and a synthetic **100 USD cent purchase authorization**. It specifies the offline adapter and loopback interface implemented in `openline_receiver.lithic_adapter` and `openline_receiver.lithic_server`. No Lithic enrollment, issued card, public endpoint, external transaction, or settlement has occurred. The final readiness verdict and evidence belong in the preflight report; this document does not grant approval to connect the pilot.

The implementation starts from PR #107's verified commit, `8a2ddf2af62374b70908421da6066afb69d5803e`. This contract supersedes its hypothetical request/response examples. The original file is preserved byte for byte in [historical evidence](evidence/preflight-001/historical/LITHIC_CONTRACT-8a2ddf2.md), SHA-256 `64b8ce077a416000fe5401782180ceb71c140224d35cffccf0de1ad4c34dbf97`.

## Actual request and response

The complete synthetic request is [fixtures/official-asa-request.json](fixtures/official-asa-request.json). It is validated against the pinned official Lithic OpenAPI schema, not delivered by Lithic. [LITHIC_SOURCES.md](LITHIC_SOURCES.md) records the official source commits, signature verifier, field definitions, and limitations.

The ASA event is `card_authorization.approval_request`. Card identity is `card.token`; `token` is the provisional transaction-group UUID. The adapter reads `amounts.cardholder` and `amounts.merchant`, `merchant`, `status`, and `transaction_initiator`. The pilot permits `status: "AUTHORIZATION"`, `transaction_initiator: "CARDHOLDER"`, an open virtual card, exactly 100 USD cents in both structured amounts, a conversion rate of one, zero cash, and zero acquirer fees. Adjusted hold or settlement amounts, inconsistent deprecated amount/currency fields, other currencies, credits, balance inquiries, and single-message financial authorizations are outside this contract.

Merchant intent includes `acceptor_id`, `acquiring_institution_id`, `descriptor`, `mcc`, `city`, `country`, and `state`, plus supplied optional merchant details. Supplied network, POS, authentication, service-location, and other supported operation context is also bound to the intent, including absence. An altered merchant, currency, operation, or bound context cannot use an existing intent merely because its card and dollar amount match.

The adapter returns only documented ASA fields. A committed approval is:

```json
{"result":"APPROVED"}
```

A missing, consumed, expired, or revoked pending authorization returns a committed decline such as:

```json
{"result":"CARD_PAUSED"}
```

A request outside the bounded purchase intent returns `UNAUTHORIZED_MERCHANT`. A reused transaction token with different authenticated JSON contents returns `SUSPECTED_FRAUD` and leaves the original signed receipt unchanged. The implementation does not add a presentation, receipt, boolean `approved`, or private OpenLine reason to the ASA response. Those historical fields were hypothetical, not supported Lithic extensions.

## Mandatory ASA authentication

`SecureLithicAdapter` defaults to `sandbox=True`. Construction requires valid configured `signing_secrets`; `PilotHTTPServer` refuses an unauthenticated adapter. These are the program's **ASA signing secrets**, not an API key or an unrelated regular webhook subscription's secret.

`POST /asa` requires one each of `webhook-id`, `webhook-timestamp`, and `webhook-signature`. The verifier checks the original raw request bytes, decodes the secret as the official verifier does, validates timestamp freshness within at most 300 seconds, and compares versioned HMAC-SHA256 signatures. It accepts a valid signature from the space-separated signature list and supports explicitly configured old/new secrets during rotation. Invalid signatures, changed bodies, expired or future timestamps, missing headers, and duplicate authentication headers fail authentication. JSON parsing and authorization use that same authenticated body; supplying a different mapping cannot bypass this boundary.

The official-verifier tests reproduce a published general-webhook signing fixture and run the official Lithic SDK against independently signed ASA-shaped fixtures. The published vector is not an ASA-specific provider example. No real signing credential is included in the repository.

## Authority and preauthorization

Owner pinning, bundle admission, card binding, integrator enrollment, and preauthorization are trusted **local Python operations**, not unauthenticated HTTP administration routes:

1. Explicitly initialize a fresh `SecureLithicAdapter` database with `initialize=True`, a stable `gate_id`, and the ASA signing secret. Obtain and independently pin its receiver public key over the trusted enrollment channel. Reopening existing state does not initialize it again and can require `expected_receiver_public_key`.
2. Call `enroll_owner(principal_id, root_key_hex)` using the owner's independently authenticated root key. Admit the real owner-signed Wallet bundle with `admit_bundle(principal_id, bundle)`.
3. Bind the single card identifier to an active mandate and worker with `bind_card(card_token, principal_id, mandate_id, subject_id)`. This creates no spending permission.
4. Obtain a durable receiver challenge using `issue_challenge(card_token)`. The worker creates its actual Wallet presentation for `lithic:authorize` using `worker_present(...)`.
5. Normalize the intended real ASA operation using `payment_details(intended_request)`. Use `create_payment_intent(gate_id=..., details=..., presentation=..., subject_key=...)` to sign the payment terms and the exact Wallet presentation with the worker's mandate key.
6. Submit `pre_authorize(card_token, details, presentation, signed_intent)`. The receiver verifies the owner bundle, active mandate, owner/mandate/subject/card binding, worker presentation, fresh one-use receiver challenge, and separate signed intent. A successful result creates one pending authorization lasting **at most 60 seconds**, also bounded by bundle and mandate expiry.

Only one live pending intent is permitted for the card. Another presentation cannot silently overwrite it. The actual ASA decision rechecks current admitted authority, validates the stored signed proof, matches the authenticated operation to the intent, and consumes it once.

### The transaction token is unknown in advance

This preauthorization is permission for **the next matching ASA purchase during the expiry window**. It is not permission for a preselected Lithic transaction token. The token becomes bound to the decision and signed receipt only when ASA arrives. An optional beta `event_token` is not required or assumed available.

Two purchases with identical bound fields remain indistinguishable before a transaction token is assigned: either may consume the single pending intent first. The regression suite demonstrates this limitation. A subsequent distinct transaction token declines after consumption. This bounded first-match behavior is the authorization semantics the pilot owner must review; it is not exact merchant-order identification or evidence that goods or settlement occurred.

## Owner-signed revocation and successor workers

The owner uses the real Wallet's `revoke(mandate_id, ...)` and exports its updated signed bundle. `admit_bundle(principal_id, updated_bundle)` cryptographically verifies that history and atomically persists it while removing pending authorizations whose mandates are no longer active. No explicit adapter `revoke_mandate()` call is required or provided.

After admission completes, a new ASA request cannot consume revoked authority, including after a restart or from another adapter process. Admission rejects older bundle heads or older refreshes that would restore prior authority. Conflicting signed history quarantines the principal durably and invalidates its pending authority. These guarantees begin when the receiver admits the updated bundle; the adapter does not discover undelivered owner revocations.

A successor worker must receive a new valid owner-signed mandate, have the updated bundle admitted, be bound to the same card, and supply a fresh verified presentation and signed intent. Rebinding clears prior pending authority and challenges. Revoking an old worker does not automatically authorize its successor.

## Durable decisions, retries, crashes, and failures

SQLite uses WAL and `synchronous=FULL`. A receiver lock owns complete connection transactions; `BEGIN IMMEDIATE` serializes competing workers and bundle admission. Pending consumption, receipt creation, and decision persistence share one commit boundary. The receiver signing key is created only in explicit database initialization. Signing a receipt neither creates a key nor commits an unfinished authorization transaction.

An authenticated retry with the same transaction token and JSON contents returns its original committed result and persisted receipt, including after a restart. This also preserves an already committed approval when an owner subsequently revokes authority; it acknowledges the earlier decision rather than granting a new authorization. Changing contents under that token fails closed. Whitespace or JSON member ordering alone does not change the canonical content fingerprint.

A crash before commit leaves no acknowledged approval and does not consume the pending authorization. A crash after commit but before response preserves the decision for an identical retry. A processing failure that cannot commit a decision yields HTTP **503 with an empty body**, rather than inventing an unpersisted decline or approval. The official ASA webhook specification permits one immediate retry on HTTP 5XX.

Missing, corrupt, replaced, truncated, or unreadable receiver state cannot be implicitly reinitialized or used to approve a request. The adapter validates live durable state rather than trusting only cached SQLite pages or an in-memory signing key. It also validates persisted authority and signed receipts. This is a bounded pilot implementation on a trusted host; it does not add remote administration, backup restoration, settlement, or production recovery infrastructure.

## Authenticated, read-only receipt retrieval

Enroll the integrator locally using `enroll_integrator(identity, bearer_token, principal_id)`. Supply a separately provisioned bearer credential of at least 32 characters; only its hash is persisted. The receipt route is:

```http
GET /receipts/{transaction-token}
Authorization: Bearer <separately provisioned integrator credential>
```

The adapter returns the persisted signed receipt only when that credential is enrolled for the receipt's principal. Unauthenticated or unrelated callers receive HTTP 401 without disclosing whether an inaccessible transaction exists. Mutation methods return HTTP 405. Responses use `Cache-Control: no-store`; the handler does not log headers, raw bodies, or receipts.

The receipt contains the transaction token, authenticated request fingerprint, documented ASA result, private decision reason, authority identities, matched payment details, signed authority proof where applicable, and the limited authorization semantics. Verify its canonical payload hash and Ed25519 signature using the **receiver public key pinned before the request**, not a key learned from the receipt. `test_lithic_preflight.independently_verify` performs this verification independently of the adapter's verifier and rejects substituted keys or tampered contents.

`PilotHTTPServer` binds only to `127.0.0.1` or `localhost`. Its HTTP transport is for local preflight; no public endpoint or TLS deployment is included.

## Reproducible offline validation

From the repository root:

```bash
python3 -m venv /tmp/openline-lithic-preflight
/tmp/openline-lithic-preflight/bin/python -m pip install \
  -r gateway/receiver-package/requirements-preflight.txt
cd gateway/receiver-package
OPENLINE_REQUIRE_OFFICIAL_LITHIC=1 /tmp/openline-lithic-preflight/bin/python \
  -m unittest -v test_lithic_hmac test_lithic_schema \
  test_lithic_preflight test_lithic_wallet_revocation test_lithic_atomicity \
  test_lithic_live_state
```

The suites cover the real owner-approved $1 → ASA approved → admitted owner-signed revocation → new ASA declined → successor authority → ASA approved sequence; restart cases; real signatures; raw-body HMAC; intent mismatches; repeated and conflicting transaction tokens; competing processes; crash boundaries; unavailable or corrupt state; receipt ACLs; and independent signature verification. The HTTP tests measure complete localhost response bodies and enforce the requested six-second budget, including concurrent retries and an unavailable writer. These local measurements do not establish an external network budget or live Lithic acceptance.

The existing Gateway integration and crash suites remain separate required checks. Their exact commands, final tested commit, CI links, failures, and readiness verdict are recorded in the final preflight report. Stop at owner review before any external pilot action.
