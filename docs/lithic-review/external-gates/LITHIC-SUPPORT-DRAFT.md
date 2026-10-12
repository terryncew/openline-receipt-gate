# Lithic support inquiry — owner approval required, UNSENT

Proposed recipient: **Lithic Support**, through the owner-approved official support channel. The [official OpenAPI contact URL](https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L3) is `https://support.lithic.com/`; no email address, individual recipient or active account is assumed. Owner must approve **both this final message and the actual recipient/routing** before any submission. No ticket, email or other communication has been sent.

Subject: Written sandbox ASA isolation, callback defaults and failure-policy confirmation

Hello Lithic Support,

We are assessing a narrowly bounded sandbox-only ASA interoperability test. **No program or card is selected, and no external test has run.** Before selecting resources or executing anything, we need current written documentation and any conditions requiring later program-specific confirmation. Please do not activate or enroll anything.

Our tentative profile is one VIRTUAL card, a 100-cent USD dual-message AUTHORIZATION, merchant amount 100/USD, billing currencyUSD, MCC 5999, descriptor OPENLINE PILOT, synthetic merchant ID OLPILOT001, NEW YORK/NY/USA, no PIN and no partial approval. Initial testing would grant no purchase authority and return a valid decline. Fault cases would be considered only for questions not answered in writing.

1. **Isolation and scope:** Under exactly what sandbox credential/program/card/destination conditions can simulator authorizations, partial approvals and ASA fallback be guaranteed not to create actual card-network activity or real-fund movement? What nonsecret evidence verifies those conditions? Does ASA responder enrollment/replacement affect other cards or programs? Are there sandbox/ASA fees, limits or contract-specific restrictions we must confirm before this profile is used?

2. **Complete callback profile:** For these inputs, is there a guaranteed full ASA payload/default template? Please distinguish predetermined versus per-request/program-derived values and presence/normalization, particularly acquiring institution, conversion-rate strings, nullable merchant contact data, hold/settlement, initiator, POS, AVS, authentication and risk/context fields. We must know which exact fields can reliably be signed before delivery; if no stable template is guaranteed, please state which cannot be predetermined. Please confirm the applicable 100/USD input/callback contract.

3. **Failure and safe abort:** Please provide the decision deadline/time origin, per-attempt and total retry budget, final authorization outcome and applicable default/configuration for timeout/silence or late response, repeated 503, malformed JSON, invalid shape (e.g. missing/wrong-type result), and an unavailable endpoint (DNS/TLS/refused connection). What changes when a responder is removed or a card paused during an in-flight authorization, and how should a sandbox test abort safely? Which behavior depends on the selected program or issuer/native-rule ordering?

We already have the published contract for one immediate 5XX retry and unknown string result decline; we are asking about the **final outcome and remaining cases**, not requesting another confirmation of those settled facts. We also understand the transaction token arrives in ASA before the decision and cannot be chosen in advance through the simulator.

Our references are the [official OpenAPI, September 16, 2026](https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml) and [SDK simulator parameters, October 8, 2026](https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/transaction_simulate_authorization_params.py). Please identify current source/version, guarantee scope and any further nonsecret program information needed after selection. No API key, ASA secret, PAN or private key is included or requested.

Thank you.

---

Owner-side fresh-state, destination enforcement, caller/hosting and stop-harness requirements are handled separately in [READINESS-002](READINESS-002.md); this inquiry does not ask Lithic to certify our implementation. Sending permission would not authorize credential access, enrollment, deployment, calibration or transactions.
