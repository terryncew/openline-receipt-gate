# A payment authorization the agent could not approve for itself

**OpenLine Lithic ASA offline preflight — October 11, 2026**  
**Result: 104/104 required Linux checks passed. Offline acceptance: PASS. External payment-provider test: NOT YET RUN.**

An AI worker proposes a $1 purchase. The owner has delegated narrow authority, but that alone does not give the worker control of the payment decision. A receiver checks the owner's signed authority and the worker's separately signed intent before answering the simulated card-authorization request. The receiver—not the agent—makes the decision and signs a record of it.

In the local test, the owner can withdraw that authority and a later request stops. A different worker can later be authorized under valid successor authority. The evidence remains verifiable without trusting the worker who proposed the action.

**The demonstrated sequence**

1. **Owner grants authority.** A pinned owner root verifies the signed Wallet delegation for the selected worker and virtual-card identifier.
2. **Worker proposes one purchase.** A separate worker signature binds the merchant, amounts and currencies, purchase operation, and available context to an owner-authorized Wallet presentation. The receiver accepts one pending, matching intent for at most 60 seconds.
3. **Receiver APPROVES.** A locally authenticated, synthetic ASA request matches the signed intent. The receiver atomically consumes the pending intent and commits a signed decision receipt.
4. **Owner revokes.** The receiver admits the newer owner-signed bundle; an unconsumed pending permission is invalidated. After a restart, a new simulated ASA request returns **CARD_PAUSED**.
5. **A successor is authorized.** Valid new authority for a different worker on the same card produces **APPROVED** after another restart. All three decision receipts independently verify against a receiver public key pinned *before* the requests.

The local ASA response contains only Lithic's documented result field. The signed OpenLine evidence is available separately through an authenticated, read-only receipt endpoint.

## What was actually tested

| Check | Evidence |
| --- | --- |
| Linux preflight | **104/104 required checks passed**, zero required verifier skips in the recorded CI run |
| Components | 72 installed-package preflight checks; 25 unchanged real Envoy Gateway/Wallet integration checks; 7 unchanged atomic receipt/crash checks |
| Provider-format compatibility | Actual Lithic Python SDK v0.132.0 verifier checked against independently constructed ASA fixtures, plus its *general-webhook* published test vector. This is not a real delivered ASA event |
| Owner succession and revocation | Signed grant → APPROVED → signed revocation → CARD_PAUSED → successor grant → APPROVED, across restarts |
| Integrity | Concurrency, duplicate requests, transaction-token reuse with changed content, unavailable SQLite writer, crash cases and state-file corruption |
| Receipt verification | Three persisted receipts checked using a separately supplied public-key pin |
| Local response timing | The three demonstration responses completed within **8.73 ms**; 80 authenticated retries across eight clients completed within **41.24 ms**; eight unavailable-writer requests returned **HTTP 503** within about **1.01 seconds** |

These times are localhost observations, **not** production latency, a provider service-level guarantee, or meaningful tail-latency estimates. An earlier seemingly green candidate had a real state-corruption defect; the preserved failing reproduction and added regressions are part of the evidence.

### Verify the public evidence yourself

- [Draft implementation and review: PR #108](https://github.com/terryncew/openline-receipt-gate/pull/108) (stacked on the separate, unmerged PR #107).
- [Passing Linux CI run, implementation commit `abf6bc72`](https://github.com/terryncew/openline-receipt-gate/actions/runs/38182746885).
- [Pinned public preflight report and exact commands](https://github.com/terryncew/openline-receipt-gate/blob/8a537d4ff598541bb21cc564b3220ec97ef09fb3/gateway/receiver-package/LITHIC_PREFLIGHT.md).
- [Pinned implemented ASA contract](https://github.com/terryncew/openline-receipt-gate/blob/8a537d4ff598541bb21cc564b3220ec97ef09fb3/gateway/receiver-package/LITHIC_CONTRACT.md).
- [Pinned source references to Lithic's official SDK, schema and examples](https://github.com/terryncew/openline-receipt-gate/blob/8a537d4ff598541bb21cc564b3220ec97ef09fb3/gateway/receiver-package/LITHIC_SOURCES.md).
- [Public signed sequence evidence](https://github.com/terryncew/openline-receipt-gate/blob/8a537d4ff598541bb21cc564b3220ec97ef09fb3/gateway/receiver-package/evidence/preflight-001/ci-final/measurements/asa-sequence-public-evidence.json), [independent verification result](https://github.com/terryncew/openline-receipt-gate/blob/8a537d4ff598541bb21cc564b3220ec97ef09fb3/gateway/receiver-package/evidence/preflight-001/ci-final/measurements/independent-receipt-verification.json), and [pinned public verifier key](https://github.com/terryncew/openline-receipt-gate/blob/8a537d4ff598541bb21cc564b3220ec97ef09fb3/gateway/receiver-package/evidence/preflight-001/ci-final/measurements/receiver-pinned.pub).

Reproduce the full suite using the exact commands in the preflight report. The standalone receipt checker can run against the published JSON and independently pinned key without importing the adapter or Wallet verifier.

## The boundary we have **not** crossed

This is an **offline, local, synthetic** preflight involving one receiver, one pinned owner, one synthetic virtual-card identifier and $1 purchase authorization terms. There was **no actual Lithic enrollment, card issuance, external ASA delivery, payment, settlement, deployment, company endorsement or production certification**. OpenLine is not claiming an official Lithic partnership.

Two external questions still prevent a credible complete sandbox experiment:

1. **Callback matching:** Not every intent-bound field is selectable through the transaction simulator. Before allowing an external request, we need a genuine, predictable provider callback to match against the separately signed purchase intent.
2. **Provider failures:** We have not established the particular program's fallback behavior when our receiver times out, returns HTTP 503, or responds incorrectly. A receiver that fails closed locally is insufficient proof if the external provider can independently approve.

Preauthorization cannot specify a transaction token that has not yet been assigned. It authorizes **the next matching purchase within 60 seconds, once**. Two identical purchases remain indistinguishable until a callback arrives; the first matching one can consume the allowance. This is **not exact order-level binding**.

The demonstrated grant constrains purchase amount to **$1 per authorization**, **not $1 total across the grant's lifetime**. Total spending needs separately enforced limits before any armed experiment. The suite also does not prove power-loss recovery, safety against restoring an older complete database, multi-host recovery, recurring or incremental charges, or settlement.

## What this demonstrates

The useful separation is simple: **an agent may propose an action without owning the authority to accept it.** Here a receiver evaluates independently signed owner authority and a worker's exact purchase intent, persists a decision, respects admitted revocation for *new* transactions, and offers a signed receipt that can be verified independently. An identical retry of an already committed transaction can still return its historical decision after revocation; a new transaction cannot inherit that decision.

These are demonstrated properties of **this local test**, not proof that OpenLine is uniquely necessary. Standard provider card limits, ordinary policy engines, signed JWTs, and other receiver-side controls may satisfy some or all of the same requirements under relevant assumptions. The market and external-interoperability questions remain open.

**Status: publish the evidence, preserve the unmerged experiment, and require separate owner approval before any real provider connection or transaction.**
