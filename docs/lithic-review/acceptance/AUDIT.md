# OPENLINE-LITHIC-ACCEPTANCE-001 — owner acceptance audit

**A. OFFLINE ACCEPTANCE: PASS / ACCEPT**, for PR #108's documented synthetic, controlled, trusted-host preflight contract. **B. EXTERNAL SANDBOX READINESS: NOT READY to execute the advertised approval → revocation → decline → successor sequence.** Two specific provider-integration gates remain below. A separately approved unarmed calibration is a justified next experiment once its safety conditions are established; more simulation polishing is not the next step.

Reviewed on October 11, 2026. [PR #108](https://github.com/terryncew/openline-receipt-gate/pull/108) remains open and draft. Nothing was changed in the repository or PR. No provider API call, enrollment, card, transaction, contact, deployment, external service, merge, or paid API was used. Public official source retrieval and GitHub evidence reads were the only external reads.

## Provenance and reproduced evidence

| Check | Independent result |
| --- | --- |
| PR #107 starting commit | `8a2ddf2af62374b70908421da6066afb69d5803e` is the verified ancestor. Seven protected Gateway source/config/test files are byte-identical; Gateway identity binding and receipt protections were preserved. |
| Tested implementation | `abf6bc72f4375bd43d2c274812e5dadd68f03e41`; [Linux CI 38182746885](https://github.com/terryncew/openline-receipt-gate/actions/runs/38182746885) independently reports success at this SHA. Retrieved logs show 72 tests, 7 tests, and 25/25 Gateway checks. |
| Delivered implementation | `8a537d4ff598541bb21cc564b3220ec97ef09fb3`; 24 runtime, fixture, requirements, and test files match the tested implementation byte for byte. Delivery adds documentation/evidence/the standalone receipt verifier and retires the temporary push trigger. |
| Installed runtime | Fresh Python 3.12 environment, package installed from an archive of the exact delivery commit, tests copied outside the checkout. Imported adapter came from `site-packages`, matched delivery, SHA-256 `8b2f91b3e6c05169c6cee5eb37dee1681ff10c7edba421838f1ddf8bccfce92d`. |
| Preserved evidence | All **39** manifest hashes match. Four measurement/public-evidence JSON files retrieved independently from the actual CI log match the preserved files **byte for byte**. Historical failure evidence remains present. |
| Fresh official-SDK/Wallet/ASA/state tests | **72/72 passed**, 17.772 seconds, **zero skips**. |
| Unchanged Gateway atomicity/crash tests | **7/7 passed**, 0.270 seconds. |
| Actual Envoy + Gateway + Wallet integration | **25/25 passed** using Envoy 1.39.3. |
| Total reproduced contract checks | **104/104 PASS**, with no dependency failures or hidden skips. This is the preflight's test set; it is not a fresh complete Docker Compose verification run. |
| Independent public cryptography | A verifier importing cryptography, not OpenLine verification code, checked **19 Ed25519 signatures**, bundle heads 1 → 2 → 3, grant → root-signed revoke → successor, and APPROVED → CARD_PAUSED → APPROVED receipts. |

Provenance, versions, CI metadata/logs, evidence comparison, and fresh logs are preserved beside this report: `provenance.json`, `installed-runtime.json`, `ci-38182746885.json`, `ci-38182746885.log`, `ci-evidence-comparison.json`, `clean-preflight-tests.log`, `gateway-crash-tests.log`, and `gateway-integration-tests.log`. Auxiliary state/authority probes overlap the 104 checks and are not inflated into a new headline count.

Fresh complete localhost response measurements were 4.83–7.21 ms for the three-step sequence; 80 duplicate deliveries at concurrency eight completed within 33.87 ms; eight unavailable-writer requests returned 503 within 1.009 seconds. All met the requested local six-second budget. These small functional measurements prove neither a provider deadline nor deployed network latency or capacity.

## What the receiver actually enforces

The receiver independently pins the owner root, verifies signed bundle ancestry and active authority, verifies the worker's mandate key and challenge-bound Wallet presentation, then verifies a separate worker-signed normalized payment intent. A card binding alone does not approve. Foreign-worker and old-worker/successor substitution probes were refused. A worker's claim that it is authorized is insufficient.

Bundle admission and ASA consumption serialize through `BEGIN IMMEDIATE`. Successful admission of a newer owner-root-signed revocation invalidates affected pending authority in the same durable transaction. New transaction tokens then decline, including after restart and in another process. Older heads, freshly re-signed old history, and stale refreshes cannot restore admitted authority; signed forks persist quarantine. Both revocation/ASA race orderings pass: a previously committed approval remains a historical retry acknowledgment; an admission that commits first prevents a new approval. A revocation signed but **not delivered and admitted** is ineffective at this receiver, as independently reproduced.

The owner's mandate grants reusable `lithic:authorize` scope to a worker. It does **not** sign a particular card, merchant, purchase, total budget, or purchase count. The receiver supplies the fixed 100-USD-cent policy; the worker signs the payment terms. A fresh probe approved two $1 purchases at different merchants under one unchanged owner grant. This meets the stated delegation contract but would fail a claim of owner-signed exact purchase consent or one total $1 allowance. The approval packet uses the actual semantics.

The 60-second intent authorizes the first matching authenticated callback, not an exact order or preselected Lithic token. Identical purchases, a resubmission creating another transaction group, another matching card use, or an earlier delayed unseen callback can consume it. A probe created and HMAC-signed a matching request 120 seconds **before** preauthorization; it was still within the 300-second HMAC freshness window and approved when delivered afterward. Detailed merchant/context binding and a short TTL do not distinguish identical purchases. For this pilot, require exclusive controlled card use and no prior in-flight matching request. If the owner requires only newly initiated purchases, a defined creation-time lower bound is a minimal additional constraint; exact order binding still needs a trusted correlation value available beforehand.

## Security challenges and limits

| Property | Finding |
| --- | --- |
| Raw-body Lithic HMAC | Correct program ASA secret, original bytes, versioned signatures, integer timestamp, 300-second freshness and explicit current/previous secrets. Official SDK 0.132.0 verifies the published general-webhook vector and independently signed ASA-shaped fixtures; valid/invalid/tampered/expired/missing cases pass. This establishes SDK compatibility, not an actual provider-origin ASA fixture or external interoperability. Sandbox HTTP authentication is mandatory. |
| Actual schema/response | Full fixture validates against pinned official OpenAPI, and extracted schemas match the official objects. Only documented minimal results are returned: APPROVED, CARD_PAUSED, UNAUTHORIZED_MERCHANT, SUSPECTED_FRAUD. No OpenLine receipt fields are inserted into ASA responses. |
| Duplicates/replay | Same token and canonical JSON return the committed signed result across restart, including an old approval after revocation. Changed contents under that token return SUSPECTED_FRAUD without replacing its original receipt. A new token requires fresh usable pending authority. |
| Atomicity/concurrency/crash | Key creation is explicit initialization only. Pending consumption, signing and decision persistence share a transaction. Independent-process and signing/commit crash tests pass. Before-commit failure rolls back; after-commit crash preserves a retryable signed decision. Signing or writer failure acknowledges no decision and returns empty HTTP 503. |
| Corruption/unavailability | Live missing/replaced/truncated/header/B-tree-corrupt state and corrupt signed metadata/proofs fail closed, including cached approval retries and receipt reads. FULL/WAL and protected 0600 database/WAL/SHM files were verified. This does not prove physical power-loss or hostile-host durability. |
| Receipts and ACL | Independent pre-pinned receiver key verifies receipts; substituted pins and modified payloads/signatures fail. Owner-scoped read-only bearer succeeds; missing/wrong/unrelated credentials, the ASA secret, public key and worker key fail. Only bearer hashes are stored. The standalone delivery verifier checks receipt signatures/hash/results, not the full owner chain; the audit separately checked that chain. |
| Rollback | Restoring a complete older valid database under the same receiver key **revived pending revoked authority** in a probe. This is an explicitly excluded trusted-host/backup boundary, not a newly discovered in-contract blocker. A receiver pin proves identity, not storage freshness. Pilot storage must remain protected and must not be restored to an older snapshot. |
| Revocation attribution | Normal post-admission decline has `NO_PENDING_AUTHORIZATION` and no authority proof because admission deleted the pending row. A signed decline alone does not prove revocation caused it. Record an otherwise-valid unconsumed intent, its expiry, committed admission ordering, unchanged provider controls and remaining allowance. |

The laboratory's separately supplied pins do not prove real owner/card-account enrollment or independently operated host isolation. Private signing keys remain ordinary host-protected material; no HSM, hostile-administrator resistance, multi-host recovery, settlement or production availability guarantee is established. These limits are acceptable only within the documented narrow trusted-host experiment.

## External blockers and smallest corrections

| ID / severity | Exact unresolved property and evidence | Smallest correction |
| --- | --- | --- |
| E1 — **HIGH, functional experiment blocker** | A worker must sign details matching the real callback before it arrives. Adapter `payment_details` (`lithic_adapter.py:101`) binds complete amounts/merchant plus supplied network, POS, authentication, AVS, risk and other context; `:512` demands exact equality. Official simulation parameters cannot set all these provider-generated values. The offline suite knows a manufactured complete body in advance. Its merchant acceptor ID is also 22 characters whereas `/v1/simulate/authorize` allows 15. No real-provider template or stability evidence exists. This proves the proposed run is not yet reproducible, not that every real request must fail. | Use a supported ID such as `OL-PILOT-001`. Obtain an authoritative program-specific template, or separately authorize **one unarmed calibration with an explicitly declining receiver** after the safety gate. Establish which bound fields are predictable for the chosen scenario. If fields vary per transaction, stop and propose a minimal reviewed intent-constraint change separating knowable payment terms from provider telemetry; never silently drop signed constraints. A single captured sample is not proof of future stability. |
| E2 — **HIGH, enforcement safety gate** | Local 503/timeout does not establish issuer decline. Official enrollment has `type` and `url`, no `fail_open` or fallback control. Official ASA contract says 5XX causes one immediate retry but does not establish the final authorization decision after failure, malformed response or timeout. The actual program policy and deadline were not supplied or observed. No fail-open behavior was demonstrated either. | Record authoritative actual-program failure/default policy and deadline before arming. Confirm receiver failure cannot yield a provider approval, through applicable program configuration/documentation or a separately approved bounded fault trial if needed. Measure complete deployed responses against that deadline and the requested six-second budget. Do not invent a `fail_open:false` enrollment field. |

Two packet corrections accompany E1/E2 and need no PR modification: the SDK's default two retries can produce **three simulator POSTs** after a mocked 500, with no automatic idempotency header; use `max_retries=0` and never resubmit after ambiguous timeout. Explicitly set 100-cent merchant amount, USD merchant currency and AUTHORIZATION status; merchant currency defaults to GBP when merchant amount is supplied. Current SDK exposes billing currency too; the pinned 0.132.0 call does not accept that newer parameter.

Actual ASA secret retrieval is write-affecting: GET creates the program secret if missing and activates signature headers. Rotation has a documented 24-hour old-secret overlap. Actual secret provisioning, TLS hosting and enrollment remain future owner-authorized actions, not silent audit prerequisites already completed.

Public `docs.lithic.com` retrieval returned proxy HTTP 403; this audit used pinned official OpenAPI/SDK and current public SDK source and did not bypass the restriction. Official SDK/schema compatibility is established; current program availability, provider fallback and live timing are not.

## Simpler alternatives and what the experiment could demonstrate

Ordinary issuer controls can cap or restrict a card and pause it. They are the simpler choice if the goal is merely a $1 authorization followed by stopping spend. A stateful conventional policy gate, or owner-signed JWT/JWS capability with holder proof, durable revocation/version/nonce/decision state and signed audit receipts, can reproduce these guarantees. Basic stateless JWT or basic OPA alone is not a fair equivalent. This audit found no unique cryptographic advantage.

The useful hypothesis is narrower: an **independently operated receiver** can consume portable Wallet authority, enforce an admitted owner-signed revocation without trusting the worker, accept a newly delegated successor on the same card, and issue independently verifiable decisions. Keep issuer card state, limits and rules unchanged so they do not substitute for that demonstration. A lifetime $1 limit exhausted by the first approval would falsely resemble a revocation decline and block the successor.

## Exact local reproduction

The clean audit setup archived delivery into `source/`, created `venv/`, installed `requirements-preflight.txt`, `grpcio==1.84.0`, `protobuf==7.36.2` and that archived package. Six unchanged test files and fixtures were copied to `tests/`. Python 3.12.14, cryptography 50.0.1, standardwebhooks 1.1.0, jsonschema 4.26.0 and Lithic 0.132.0 at official SDK commit `a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f` were used. No provider API key is needed.

```bash
cd /workspace/openline-lithic-acceptance-001/tests
OPENLINE_REQUIRE_OFFICIAL_LITHIC=1 \
OPENLINE_TEST_MEASUREMENT_DIR=/workspace/openline-lithic-acceptance-001/reproduced-measurements \
  /workspace/openline-lithic-acceptance-001/venv/bin/python -m unittest -v \
  test_lithic_hmac test_lithic_wallet_revocation test_lithic_atomicity \
  test_lithic_preflight test_lithic_schema test_lithic_live_state

cd /workspace/openline-receipt-gate
/workspace/openline-lithic-acceptance-001/venv/bin/python \
  -m unittest gateway/poppy/test_atomic_receipt.py -v
ENVOY_BIN=/tmp/openline-envoy NO_PROXY=localhost,127.0.0.1 \
  /workspace/openline-lithic-acceptance-001/venv/bin/python gateway/poppy/test_gateway_path.py
/workspace/openline-lithic-acceptance-001/venv/bin/python \
  /workspace/openline-lithic-acceptance-001/authority/verify_public_chain.py
```

The Envoy binary already available here was used; CI extracts official `envoyproxy/envoy:v1.39.3` with Docker. The upstream repeatable clean-install and extraction commands remain in delivery `gateway/receiver-package/LITHIC_PREFLIGHT.md:98`. A pre-existing SDK virtualenv contained an older installed adapter, so it was not used as the clean acceptance environment; current import provenance was explicitly checked. Scratch authority/state probes and their outputs remain under `authority/` and `state/`.

The actionable next step is the separate `OWNER_APPROVAL_PACKET.md`. No code change is proposed unless E1 reveals genuinely unpredictable bound context. **Stop for owner review.**
