# LITHIC-EXTERNAL-GATES-001 — read-only evidence closure

**Recommendation: NO-GO for execution, including unarmed calibration.** Approval in principle remains distinct from execution permission. Available nonsecret evidence does not close program isolation or any of the three containment configurations. This is an evidence review, not a provider test.

Scope: existing research/acceptance packets, preserved official SDK/schema snapshots and tracked receiver sources at delivery `8a537d4ff598541bb21cc564b3220ec97ef09fb3`. Independent provider/control reviews reached the same missing-evidence findings. No credentials, secret/environment bindings or live databases accessed; no network/provider calls, contact, deployment, tests/calibration, PR changes or branch creation. Previously hashed 29 research files and 42 acceptance files verify unchanged.

## Gate matrix

**VERIFIED** means directly supported by the reviewed evidence; **UNRESOLVED** means absent or insufficient applicable evidence; **FAILED** means a contradicted property, not merely a missing artifact.

| Gate / containment requirement | Finding | Status | Minimum closure evidence |
| --- | --- | --- | --- |
| Program/card sandbox isolation | Official OpenAPI labels `https://sandbox.lithic.com` a sandbox and describes simulated acquirer requests. It does not supply an explicit no-real-network/no-real-funds guarantee for selected resources. No selected program/card or applicable dated support statement is in the packet. [S1] | **UNRESOLVED**; host designation VERIFIED | Applicable nonsecret provider isolation statement and identified sandbox resources; responder scope must exclude unrelated/live traffic. |
| Callback matching | Current SDK's 15 request inputs and absence of an advance token input are documented. Complete generated callback context/defaults are not guaranteed. ASA supplies the token before the decision; advance intent remains first-match semantics. [S2] | **UNRESOLVED**; input/token facts VERIFIED | Applicable complete profile/template or narrowly scoped actual unarmed callback observations after containment/approval. |
| Provider deadline/final failure decision | One immediate 5XX retry and custom-string decline are documented. Final timeout/exhausted503/malformed/invalid-shape decisions and deadline/time origin are unspecified in reviewed sources. Deprecated approximate `ttl` and result-code enums are not guarantees. [S3] | **UNRESOLVED**; two documented behaviors VERIFIED | Program-applicable written failure matrix/default policy and deadline; only unanswered distinctions warrant probes. |
| **C1 — fresh state/no historical approvals** | Receiver initializes missing state deliberately and preserves committed approvals on identical retry. No selected calibration state/configuration is supplied. [S4] | **UNRESOLVED** | Protected separate fresh path, new receiver/gate identity, exclusion of grants/bindings/challenges/pending intents **and historical approvals**; no old-state reuse. Review the nonsecret startup configuration before provisioning, validate actual state only after separately authorized setup. |
| **C2 — guarded sandbox destination** | No executable selected caller/transport configuration is supplied. Accepted SDK defaults permit production, URL overrides and redirects. [S5] | **UNRESOLVED chosen caller** | Pinned chosen SDK/caller, transport-enforced exact HTTPS sandbox origin and approved methods/paths/bodies, disabled redirects/retries, blocked overrides, reviewed request allowance. Recheck the chosen version; prior SDK analysis is not deployed evidence. |
| **C3 — serial latch/reconciliation/hosting/abort** | Current server is loopback-only. Packet contains instructions, not a reviewed public ingress, stop harness or operator configuration. [S6] | **UNRESOLVED** | Concrete nonsecret ingress/program routing, one-at-a-time allowance/latch, finite observation/reconciliation gate, named operator and preapproved authenticated-decline abort mode. No next POST after ambiguity. |

**FAILED sufficiency claims, demonstrated by existing source:**

- “Empty pending authority or `initialize=True` alone guarantees unarmed state.” False: the flag accepts existing valid state, and identical historical APPROVED decisions return before the pending lookup. Fresh-state isolation is required. This is accepted retry behavior, **not a PR #108 security regression**. [S4]
- “SDK defaults or an environment label alone enforce strict sandbox containment.” False: accepted SDK defaults to production, explicit base URL takes precedence, and default transport follows redirects. These source defaults fail the containment specification; no actual deployed caller failure was observed. [S5]

No provider fail-open behavior or actual unsafe deployment has been demonstrated. Missing configurations and support answers remain UNRESOLVED, not FAILED.

## Minimum questions for Lithic support — draft only, not sent

1. **Containment and scope:** For the named proposed sandbox program/card and `/v1/simulate/authorize`, confirm that approvals, partial approvals and ASA fallback cannot create real card-network activity or real-fund movement. Identify applicable environment/configuration, nonsecret verification evidence, responder enrollment scope, fees/limits and any effect on other program traffic.
2. **Matching profile:** For the proposed 100/USD dual-message purchase inputs, identify guaranteed full callback values/normalization/nullable presence versus per-request generated fields—especially acquiring institution, conversion-rate strings and bound POS/AVS/risk/context. Confirm the actual USD request/callback contract and relevant source version. No need to research CAD or unrelated operations for this pilot.
3. **Failure/abort matrix:** Give ASA deadline/time origin, retries and final authorization outcome for silence/late response, exhausted503, malformed JSON and missing/wrong-type/non-object result. Identify program-dependent defaults, relevant native-rule ordering and safe consequences of endpoint abort/removal. Treat cases as equivalent only if guaranteed in writing. Unknown-string decline and absence of advance token selection already have evidence; do not ask or probe them again.

Answers must be dated/applicable to the selected program and distinguish contractual behavior from examples. Support contact is not authorized. Owner-side missing items—resource provenance and caller/hosting/abort configuration—are separate from these provider questions; no secret values are needed.

## Smallest conditional calibration

**First exhaust the applicable written answers. Five cases are a catalogue, not an execution budget.** After nonsecret containment/configuration review, separately approved setup must validate its actual runtime boundary; a further explicit execution scope must name the remaining cases, count, resources, costs and abort operator.

| Remaining question | Smallest discriminating probe, only if still needed |
| --- | --- |
| Actual signed delivery/profile | One normal unarmed $1 AUTHORIZATION returning valid decline; compare authenticated callback and final provider event. No callback/issuer-rule short circuit is inconclusive. |
| Profile repeatability not established in writing | One second ordinary same-input decline, or reuse an independently necessary fault trial's new transaction callback. Do not introduce503 merely for another sample. Two samples are bounded observations, not universal guarantees. |
| Final exhausted503 outcome | One simulator POST; return503 on every authenticated delivery; observe retry count/timing and final provider outcome. |
| Malformed JSON outcome | One POST with authenticated callback then HTTP200 body `{`, only if this distinction remains unanswered. |
| Invalid-shape outcome | One POST with authenticated callback then HTTP200 `{"result":17}`, only if not resolved or guaranteed equivalent to another case. |
| Silence/late-response outcome | One bounded probe selected from an applicable written deadline and approved finite observation horizon. No automatic30-second rule or escalating delays; if deadline remains unobtainable, mark unresolved and defer this trial. |

Zero OpenLine grants, bindings, challenges, pending permission or historical approvals; no worker authority. An unexpected synthetic provider approval is still possible until fallback is established, so sandbox isolation must be verified first. No financial authorization, clearing, settlement, card issuance, new service or credential use is authorized here.

**Stop immediately** on provider approval/partial approval, ambiguity, extra POST/token, wrong terms/card, invalid HMAC, unsupported/drifting payload, changed pin/state/containment or excess cost. Latch the caller off; preserve evidence; permit only separately authorized reconciliation reads. The preplanned responder mode must safely decline subsequent authenticated deliveries with no authority. Do not remove an endpoint or assume teardown reverses an approval; any emergency issuer action needs its own preauthorization.

Calibration tests provider mechanics. Later signed-authority/worker-succession testing remains separately approved. One Lithic result does **not** prove provider portability; ordinary card controls may already solve the card-safety use case, and an equivalent stateful policy gate can match this enforcement.

**Exact blockers:** no applicable isolation/failure/template answers; no selected resources or concrete C1/C2/C3 configurations; no execution permission. Stop for owner review. Do not request credentials or execute a probe to compensate for those omissions.

## Source-backed evidence

- [S1 — official sandbox designation](https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L15) and [simulator description](https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L7477).
- [S2 — SDK simulator inputs](https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/transaction_simulate_authorization_params.py) and [callback token](https://github.com/lithic-com/lithic-python/blob/826a8c940571e88bd4682a38e22b1c9f999cef93/src/lithic/types/card_authorization.py#L438).
- S3: [5XX retry](https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L28708), [result contract](https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L26259), [approximate ttl](https://github.com/lithic-com/lithic-openapi/blob/0afad9e69e57f2e0bbace17c1f03f79c97c07c76/lithic-openapi.yml#L25860).
- S4: [initialization](https://github.com/terryncew/openline-receipt-gate/blob/8a537d4ff598541bb21cc564b3220ec97ef09fb3/gateway/receiver-package/openline_receiver/lithic_adapter.py#L135), [historical result](https://github.com/terryncew/openline-receipt-gate/blob/8a537d4ff598541bb21cc564b3220ec97ef09fb3/gateway/receiver-package/openline_receiver/lithic_adapter.py#L469), [pending lookup](https://github.com/terryncew/openline-receipt-gate/blob/8a537d4ff598541bb21cc564b3220ec97ef09fb3/gateway/receiver-package/openline_receiver/lithic_adapter.py#L499).
- S5, accepted SDK0.132.0: [URL selection/default](https://github.com/lithic-com/lithic-python/blob/a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f/src/lithic/_client.py#L189), [default redirects](https://github.com/lithic-com/lithic-python/blob/a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f/src/lithic/_base_client.py#L819).
- S6: [loopback/authentication restriction](https://github.com/terryncew/openline-receipt-gate/blob/8a537d4ff598541bb21cc564b3220ec97ef09fb3/gateway/receiver-package/openline_receiver/lithic_server.py#L15), [existing containment review](CONTAINMENT_REVIEW.md). Historical docs-site proxy403 is recorded in `public-source-retrieval.json`; no website content was read or newly fetched in this review.
