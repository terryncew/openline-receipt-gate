# LITHIC-EXTERNAL-GATES-002 — readiness and owner boundary

**NO-GO for operational preparation or execution of external calibration.** Written planning and the support draft are complete within the present authorization. No credential provisioning/access, host deployment, enrollment, provider API call or calibration is approved. In-principle approval remains insufficient. [Provider answers](PROVIDER-ANSWERS-002.md) and [unsent inquiry](LITHIC-SUPPORT-DRAFT.md) form this packet.

Starting point: branch `codex/openline-lithic-preflight-001`, commit `c0d4adaf13300eafbb9506e4533c80032a4928fc`. Only these three new Markdown documents change. Frozen baselines, prior reports/manifests, implementation, workflows and tests remain unchanged. Historical104/104 offline acceptance is not an external result; no test reruns or new experiments.

## Decision matrix

VERIFIED = directly documented/established within its stated scope. UNRESOLVED = missing applicable evidence. FAILED = a demonstrated contradicted property; missing evidence alone is not failure.

| Blocker/property | Status | Who supplies closure / is support required? |
| --- | --- | --- |
| Sandbox network/fund isolation, fee conditions and responder scope | **UNRESOLVED** | Provider written conditions, then owner verifies selected resources satisfy them. **Support required** unless equivalent applicable official evidence is supplied. Current generic sandbox label is VERIFIED, not a complete isolation guarantee. |
| Reliable complete 100/USD callback matching | **UNRESOLVED** | Provider template/normalization/dynamic-field answer; if no guarantee, later separately approved empirical observation. **Support required** for the written answer. Input controls/schema/token timing already VERIFIED. |
| Actual deadline and final failure/default/abort behavior | **UNRESOLVED** | Applicable provider failure matrix/conditions. **Support required.** One5XX retry and custom-string decline already VERIFIED; no broad repeat probes. |
| **C1: fresh isolated receiver state** | **UNRESOLVED actual configuration** | **Owner**, not Lithic: protected separate fresh path, deliberate new identity/gate and independently pinned public key; no grants/bindings/challenges/pending intents or historical APPROVED decisions; no old-state reuse or restoration. Review nonsecret startup specification first; actual runtime state only after separately authorized setup. |
| **C2: strict sandbox-only destination** | **UNRESOLVED actual caller** | **Owner**, not Lithic: pinned caller version, enforced exact HTTPS sandbox origin/port and allowed method/path/body; no destination override/redirect; effective zero automatic retries, finite timeouts, reviewed explicit request count. Do not infer this from an environment label. Verify resolved transport boundary before any future send. |
| **C3: one-request-at-a-time/reconcile/stop** | **UNRESOLVED actual harness/hosting** | **Owner**, not Lithic: approved nonsecret ingress/program-routing configuration, serial allowance and stop latch, reconciled final provider result/callback activity before another POST, finite observation horizon, named operator and preapproved safe-decline abort mode. Support answers only provider consequences, not our harness correctness. |
| Support contact authorization | **UNRESOLVED permission** | Owner approves final message **and actual recipient/channel**. Draft exists; nothing sent. No program/card or individual contact invented. |

## FAILED claims, not provider incidents

- “No pending intent/`initialize=True` makes any receiver DB unarmed” is **FAILED** as a sufficiency claim. [Receiver initialization](https://github.com/terryncew/openline-receipt-gate/blob/c0d4adaf13300eafbb9506e4533c80032a4928fc/gateway/receiver-package/openline_receiver/lithic_adapter.py#L135) permits reopening existing valid state; [historical decision return](https://github.com/terryncew/openline-receipt-gate/blob/c0d4adaf13300eafbb9506e4533c80032a4928fc/gateway/receiver-package/openline_receiver/lithic_adapter.py#L469) precedes pending-authority lookup. This is accepted immutable-retry behavior, not a regression; use fresh separate state.
- “SDK defaults/environment name alone meet C2” is **FAILED**. Accepted SDK 0.132.0 [URL selection](https://github.com/lithic-com/lithic-python/blob/a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f/src/lithic/_client.py#L189) allows explicit overrides/defaults to production; [default transport](https://github.com/lithic-com/lithic-python/blob/a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f/src/lithic/_base_client.py#L819) follows redirects. Recheck the chosen future version; no selected caller has been reviewed as safe or observed failing live.

No actual provider fail-open, network escape, real-fund movement or unsafe deployment was demonstrated. Those unresolved facts must not be relabeled FAILED or VERIFIED.

## Minimum next action and conditional calibration

1. Owner reviews the ready-to-send support inquiry and chooses/approves its actual recipient. No automatic contact. Equivalent existing written provider answers can substitute; do not require a ticket merely to prolong the project.
2. Evaluate dated answers against their program/configuration scope. Keep conditional answers conditional until nonsecret resource provenance is supplied. Owner-side C1/C2/C3 specifications, routing conflicts, costs and abort operator are reviewed independently. This does not require or authorize credential collection now.
3. Only after containment evidence acceptance can the owner separately authorize setup/runtime validation; external sends still require **new explicit execution approval**. For still-unanswered empirical distinctions only, select the smallest case with question, expected alternatives, discriminating observable, count and stop rule.

The optional catalogue is not a five-request budget: one valid unarmed decline for actual HMAC/payload/provider result; a second ordinary identical-input decline only if repeatability remains unanswered;503/malformed/invalid-shape cases only for missing final outcomes and only if not guaranteed equivalent; a silence/late-response case only with an applicable deadline and approved finite horizon. Written answers eliminate cases. No arbitrary 30-second deadline or automatic delay escalation. Do not repeat unknown-string verification or the 104 offline tests.

Future run remains zero OpenLine grants, bindings, challenges, pending permission and historical approvals. Isolation must first contain a possible **unexpected synthetic provider approval**: absence of OpenLine permission cannot guarantee issuer decline. No financial authorization, clearing, settlement or real funds.

**Falsifier/stop:** approval or partial approval without authority; unexpected card/terms/token/extra POST; invalid HMAC; callback drift/unsupported shape; ambiguity/unreconciled outcome; changed pin/state/containment or excess cost. Latch caller off and preserve evidence. Permit only separately approved reconciliation reads; preplanned subsequent authenticated responses decline without authority. Do not blindly remove an endpoint or assume teardown reverses an approval. Emergency issuer actions require preapproval and a named operator.

**Restrictions:** no credentials, operational provider calls, communications, enrollment/secret activation/rotation, cards/transactions, paid APIs/new services, deployment, merges or other-branch changes. This task authorizes only public written-evidence research and documentation commit/push on the existing branch. No application code or frozen evidence changed. A single-provider result cannot prove portability; a conventional stateful policy gate/native controls may already solve card safety.

**Stop here:** written-evidence packet complete; retain NO-GO and await owner review. No automatic further research project or calibration.
