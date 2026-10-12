# OPENLINE-LITHIC-PREFLIGHT-001

**Verdict: READY for the bounded pilot's offline preflight and owner review.**
This verdict covers one receiver, one pinned owner, one synthetic virtual-card
identifier and 100 USD cent purchase authorizations. No actual card, enrollment,
public deployment, external ASA delivery, real funds or settlement is claimed.
Stop at owner review before any external pilot action.

The implementation starts at PR #107's verified
`8a2ddf2af62374b70908421da6066afb69d5803e`. It ports the durable pins, bundles,
pending verified authority and signed decision design from
`fix/lithic-adapter-secure-001` at
`7a9d51400900a506a0c2db02382d0afcf500ead0`, rather than replacing the verified
Gateway with that older branch. Gateway source, identity binding, receipt
signing, integration tests and crash assertions remain byte-identical to the
verified base.

**Tested implementation commit:**
`abf6bc72f4375bd43d2c274812e5dadd68f03e41`.
[Complete passing Linux run 38182746885](https://github.com/terryncew/openline-receipt-gate/actions/runs/38182746885).
The delivery commit adds review documentation, public evidence and an
independently run receipt verifier; it retires the temporary branch push
trigger. Implementation, fixtures, requirements and regression tests remain
identical to the tested commit. No merge was performed.

## Closed blockers

| Boundary | Repair and evidence |
| --- | --- |
| Owner-signed revocation | Actual Wallet root signatures are verified. Admitting a newer bundle commits its monotonic head and invalidates revoked or superseded pending authority together. New ASA requests decline after admission, across processes and restart. Older signed bundles and refreshed older heads cannot restore authority. Signed forks persist quarantine. |
| Lithic authentication | The actual ASA program secret is Base64 decoded; original request bytes, timestamp and versioned signatures are checked before JSON. Configured sandbox HTTP cannot operate without authentication. Official SDK `v0.132.0` verifies independent ASA fixtures and its published general-webhook vector is reproduced. Rotation signatures, wrong secrets, tampering, missing/duplicate headers and expiry are tested. |
| Purchase boundary | A card binding grants no allowance. A real challenge-bound Wallet presentation and separate worker-signed intent bind card, both amounts/currencies, merchant identity, operation, initiator, fees/cash and supplied operation context. One pending intent lasts at most 60 seconds and is consumed once. |
| Retries and transactions | Full authenticated JSON contents are fingerprinted. Identical retries return the original signed committed decision. Changed contents under a reused token are refused. Cached unsigned columns must match the signed receipt. Key creation is confined to explicit initialization; receipt signing cannot commit an unfinished transaction. Uncommitted failures return HTTP 503, rather than an unpersisted decision. |
| Corrupt/unavailable state | Missing state is not implicitly recreated. Guards check file identity/header and use a fresh read-only connection to validate integrity, signing identity, authority and receipts before a transaction and before commit. Cached SQLite pages cannot acknowledge an approval after file replacement/truncation. Receipt reads have the same guard. |
| Receipt retrieval | `GET /receipts/{transaction-token}` requires an enrolled bearer credential scoped to the receipt's principal. Only its hash is stored. Reads do not consume authority or modify decisions. Wrong/missing credentials and mutation requests are refused. Receipts are separate from the documented ASA response. |

Owner approval in this proof is a real signed Wallet grant of `lithic:authorize`
to the worker, exercised under the receiver's fixed $1 USD pilot policy. The
worker separately signs the actual payment terms. No stub card mapping serves
as an authority check.

## Exact authorization semantics

The provisional Lithic transaction-group token is unavailable at
preauthorization. Permission therefore covers **one next matching purchase
within the expiry window**, not a preselected transaction UUID or merchant order.
A different merchant, currency, operation or bound context declines without
consuming the intended allowance. Two purchases with identical bound fields
remain indistinguishable; the first matching authenticated request may consume
it. That limitation is deliberately tested and requires a controlled pilot
with no competing matching purchase while permission is pending.

The token is bound when ASA is decided. The optional beta `event_token` is not
assumed available. Later changed events for a transaction group cannot inherit
the first approval. An identical retry after owner revocation acknowledges an
already committed approval; a **new** transaction token declines. No recurring,
incremental, credit, cash, clearing or settlement semantics are implemented.

## Complete validation

All required checks passed without weakened assertions or official-verifier
skips on the tested commit, from a clean installed package outside the checkout.

| Suite | Passing checks |
| --- | ---: |
| Official HMAC verifier and negative fixtures | 12 |
| Real signed Wallet admission, revocation, successor, restart and races | 21 |
| Independent-process concurrency, before/after-commit crashes and logical corruption | 19 |
| Mandatory-HMAC HTTP sequence, intent mismatches, retrieval and response budget | 10 |
| Pinned official request/response schemas | 2 |
| Live state-file replacement, truncation, header/B-tree corruption and precommit failures | 8 |
| Unchanged PR #107 atomic receipt and crash tests | 7 |
| Unchanged real Envoy Gateway + Wallet integration checks | 25 |
| **Total** | **104** |

The actual proof sequence is owner grant → ASA `APPROVED` → a pending approval
is invalidated by admitted owner-signed revocation → restart → new ASA
`CARD_PAUSED` → valid successor grant on the same card → restart → ASA
`APPROVED`. Three persisted receipts independently verify against the receiver
key pinned before any ASA response. [Public signed sequence evidence](evidence/preflight-001/ci-final/measurements/asa-sequence-public-evidence.json)
includes the real signed Wallet bundles and public pins; it includes no private
keys, receiver database, ASA secret or integrator credential.

Complete localhost response-body timings from the final Linux run:

| Workload | Samples / clients | Median | Maximum | Result |
| --- | --- | ---: | ---: | --- |
| Approval → revoked decline → successor approval | 3 / 1 | — | 8.73 ms | All HTTP 200, documented results |
| Authenticated identical retries | 80 / 8 | 35.89 ms | 41.24 ms | All HTTP 200, one durable decision |
| Unavailable SQLite writer | 8 / 8 | 1,003.64 ms | 1,009.38 ms | All HTTP 503, no decision acknowledged |

These are local budget tests, not service-capacity estimates or deployed Lithic
round-trip measurements. Three sequence observations are too few for meaningful
tail estimates. [Raw measurements](evidence/preflight-001/ci-final/measurements/budget-summary.json),
[full CI log](evidence/preflight-001/ci-final/workflow.log) and
[run metadata](evidence/preflight-001/ci-final/run.json) are preserved in the PR.

## Reproduce

From the repository root on Linux, create a clean test environment and install
the pinned official verifier plus this package:

```bash
python3 -m venv /tmp/lithic-preflight-venv
/tmp/lithic-preflight-venv/bin/python -m pip install \
  -r gateway/receiver-package/requirements-preflight.txt \
  grpcio==1.84.0 protobuf==7.36.2 ./gateway/receiver-package
mkdir -p /tmp/lithic-preflight-tests /tmp/lithic-preflight-evidence
cp gateway/receiver-package/test_lithic_hmac.py \
  gateway/receiver-package/test_lithic_wallet_revocation.py \
  gateway/receiver-package/test_lithic_atomicity.py \
  gateway/receiver-package/test_lithic_preflight.py \
  gateway/receiver-package/test_lithic_schema.py \
  gateway/receiver-package/test_lithic_live_state.py /tmp/lithic-preflight-tests/
cp -R gateway/receiver-package/fixtures /tmp/lithic-preflight-tests/
(cd /tmp/lithic-preflight-tests && \
  OPENLINE_REQUIRE_OFFICIAL_LITHIC=1 \
  OPENLINE_TEST_MEASUREMENT_DIR=/tmp/lithic-preflight-evidence \
  /tmp/lithic-preflight-venv/bin/python -m unittest -v \
  test_lithic_hmac test_lithic_wallet_revocation test_lithic_atomicity \
  test_lithic_preflight test_lithic_schema test_lithic_live_state)
/tmp/lithic-preflight-venv/bin/python -m unittest gateway/poppy/test_atomic_receipt.py -v
docker pull envoyproxy/envoy:v1.39.3
docker create --name lithic-preflight-envoy-extract envoyproxy/envoy:v1.39.3
docker cp lithic-preflight-envoy-extract:/usr/local/bin/envoy /tmp/openline-envoy
docker rm lithic-preflight-envoy-extract
chmod +x /tmp/openline-envoy
ENVOY_BIN=/tmp/openline-envoy NO_PROXY=localhost,127.0.0.1 \
  /tmp/lithic-preflight-venv/bin/python gateway/poppy/test_gateway_path.py
```

Verify the preserved receipts without importing the adapter or Wallet verifier:

```bash
/tmp/lithic-preflight-venv/bin/python gateway/receiver-package/verify_pilot_receipts.py \
  --evidence gateway/receiver-package/evidence/preflight-001/ci-final/measurements/asa-sequence-public-evidence.json \
  --pinned-public-key gateway/receiver-package/evidence/preflight-001/ci-final/measurements/receiver-pinned.pub
```

The pin file comes from trusted local initialization before the first ASA
response, not from an embedded receipt key. This is laboratory enrollment;
the pilot integrator still needs independently authenticated real key delivery.

## Failures preserved

- Intermediate local tests exposed unsigned cached-result/fingerprint changes,
  a malformed pending proof and an **8.019-second** queued writer failure.
  Their [failed logs](evidence/preflight-001/failures/) remain intact. The final
  processing-failure semantics return 503 and allow a later retry to acknowledge
  only a committed decision.
- [Initial CI](https://github.com/terryncew/openline-receipt-gate/actions/runs/38182246485)
  passed the then-current 96 checks at `52fe9e7`, but an independent probe
  subsequently proved a missing case: cached SQLite pages returned `APPROVED`
  after live database replacement/truncation. Three scenarios left state
  unreadable on restart. That candidate was **NOT READY** despite green CI.
  The [before/after reproductions](evidence/preflight-001/failures/live-db-corruption-before.json)
  and probe are preserved. Fresh durable-state guards and eight additional
  HTTP regressions are required by the final passing run.
- The old `quickstart.py` already failed at PR #107 because it pins a fictitious
  principal. Its [failure](evidence/preflight-001/local-baseline/quickstart.log)
  is preserved; the real `example_01.py` passed. The controlled pilot uses the
  reviewed adapter API and installed-package suites rather than that example.
- The original hypothetical ASA contract is retained byte for byte in
  [historical evidence](evidence/preflight-001/historical/LITHIC_CONTRACT-8a2ddf2.md).

## Limits at owner review

No live Lithic request or sandbox enrollment was performed. The public endpoint,
TLS transport, actual ASA program secret, integrator credential and out-of-band
key bootstrap remain operator steps outside this authorization. The supplied
HTTP server deliberately binds only to loopback. Retire the configured old ASA
secret when Lithic's rotation interval ends; the adapter does not fetch secrets.

Revocation takes effect upon successful admission of the signed update, not
before delivery. Protected receiver storage and independently pinned keys are
required. SQLite FULL and process-crash tests do not prove power-loss behavior
or resistance to a host administrator rewriting coherent state. Restoring an
older complete database can erase the monotonic checkpoint and is unsupported;
no multi-host or production recovery system is added. The receiver's signing
key is private state in its protected database and must not be exported with
evidence. Receipts prove ASA decisions, not settlement or delivery of goods.

[Official sources](LITHIC_SOURCES.md), [implemented contract](LITHIC_CONTRACT.md)
and [public evidence hashes](evidence/preflight-001/SHA256SUMS.json) complete the
review package. No merge, enrollment, outside contact, paid API or deployment
was performed.
