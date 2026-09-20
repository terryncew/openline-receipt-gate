# DEMAND-CONTACT-001 — Preregistration

Frozen before any external contact. This file and `preregistration.json` are the
authoritative protocol. No earlier repo artifact exists.

- **Label:** DEMAND-CONTACT-001
- **Baseline main SHA:** `325a662a9d4135dba80c560c5660502da461da4c`
- **Frozen:** 2026-09-20 (pre-contact; contact has not occurred)

## Purpose

Test whether one real external consequence-owning party has a concrete need for
the capability OpenLine has now actually demonstrated:

An owner can stop one agent, replace it with a distinct agent under the same
owner-controlled authority regime, preserve history across the switch, and
prevent the stopped agent from regaining consequential authority.

This is a demand-contact experiment. It is not a product build. It is not an
integration experiment. It is not a standards effort. It is not another proof
of the mechanism.

## Earned evidence boundary

Established only within their frozen claim boundaries:

- Receipt Gate / receiver-side consequential acceptance
- BYPASS scientifically closed
- INDEPENDENT-INTEROP-002 passed clean-room contract travel
- DISTRIBUTED-STOP-001 passed
- TRUST-ROOT-SUCCESSION-001 passed
- OWNER-CONTROL-002 passed
- PLATFORM-EXIT-KILL-002 passed

Do not cite PLATFORM-EXIT-KILL-001 as evidence. It was INCONCLUSIVE_APPARATUS.

Do not claim: real-provider portability; cloud-platform exit;
cross-organization handoff; malicious-receiver tolerance; arbitrary recovery;
perfect custody; universal interoperability; production readiness; a standard.

## Research question

Does a real outside party that controls consequential AI actions have a concrete
operational need for owner-controlled authority continuity across agent/model
replacement?

Demand means evidence of an actual use, evaluation, pilot, procurement,
operational, assurance, or integration need.

Compatibility alone is not demand. Politeness is not demand. Interest in the
idea alone is not demand.

## Step 1 — prior-evidence inspection (completed pre-contact)

Inspected: openline-receipt-gate experiments, openline-bureau/demand
(DEMAND_HYPOTHESES.md, OUTREACH_LOG.md, RESPONSES.md, TARGETS.md),
openline-receiver-pilot-map (CONTACT_PACKAGE.md, CANDIDATES.md, REJECTED.md,
BEST_PILOT.md), buyer-mandate-discovery (REFRESH_2026-09-19.md, OPENLINE_FIT.md),
goals (lithic-asa-receiver-pilot-outreach, openline-commercial-outreach-follow-up).

Result: no named outside party has expressed a concrete desire to evaluate this
exact capability. Prior contacts are different questions:

- AIUC (contact@aiuc.com): Bureau demand probe sent 2026-09-18. NO RESPONSE.
- AAIF wg-identity-and-trust (Grant Miller): Bureau probe sent 2026-09-19.
  Awaiting reply. Different question (what makes an Action Record evidence).
- Arcade.dev (contact@arcade.dev), Armilla AI (hello@armilla.ai): Bureau probes
  drafted, not sent. Different questions.
- Lithic ASA pilot: outreach to Lithic technical support sent, awaiting reply.
  Different ask (pilot enrollment). Live lane; not reused here to avoid
  double-contact.
- OpenCodex #4579: design discussion only; no evaluation demand expressed.
- HolmesGPT #2492: separate receiver-surface probe, OPEN, 0 comments as of
  2026-09-20. Observed only; not modified; silence is not evidence.

## Holmes separation

Holmes is a separate receiver-surface probe. Its question is architectural: can
its existing approval point consume external current-authority standing?

Do not modify that issue under DEMAND-CONTACT-001.

Do not count Roadmap automation, reactions, views, silence, or generic
architectural interest as demand.

## Step 2 — candidate set (frozen)

### Candidate 1 — OpenCodex (lidge-jun). SELECTED.

- **Party:** OpenCodex (open-source coding-agent harness), maintainer lidge-jun
  (JUN), publicly identifiable repo owner.
- **Consequence boundary:** the agent runtime that executes commands and file
  edits; native-exec and undeclared-tool controls are the enforced boundary
  (per maintainer, #4579).
- **Pain receipt:**
  - OpenCodex ships account/model failover machinery and fixes it live:
    PR #2642 (preserve account-failover opt-out across provider overwrite),
    PR #2640 (multi-account 429 failover activation). Failover is an active
    operator pain, not a hypothetical.
  - OpenCodex issue #335: "Pool mode should retry another account after an
    account-specific unsupported-model response" — a real user hitting
    account/model rejection mid-thread and asking for bounded failover.
  - Category pain: GitHub Copilot provider incidents (community discussions
    #206338, #206731, Aug–Sep 2026: elevated errors for OpenAI models via
    Copilot; Grok 4.5/4.6 degraded; 63% of Kimi K3-routed requests failing).
    Provider dependence and failover are the documented reality of agent
    operations.
  - Maintainer's own statement on #4579: OpenCodex has "no existing
    owner-scoped capability contract for failover/subagents."
- **OpenLine capability that maps:** owner-controlled authority continuity
  across worker/account/model replacement, with history intact.
- **Who controls adoption:** the maintainer (project architecture).
- **Legitimate contact surface:** the existing public issue thread
  https://github.com/lidge-jun/opencodex/issues/4579 ("Keeping authority stable
  while the model switches"), where the maintainer is already engaged (two-way
  exchange, 2026-09-14; labels enhancement/cli/needs-design; OPEN).
- **Missing receipt:** whether operators actually need the authority to survive
  failover, or treat failover as a fresh start.
- **Falsifier:** maintainer says failover is intentionally a fresh start
  authority-wise, or that no operator has asked for continuity.

### Candidate 2 — Arcade.dev. Not selected.

- **Party:** Arcade.dev (agent tool-execution platform; 7,500+ pre-built tools;
  pre-execution hooks; SOC 2 Type II).
- **Consequence boundary:** real third-party API mutations executed for agents
  (Gmail send, Slack post, GitHub PR, Salesforce/Stripe writes).
- **Pain receipt:** none direct for authority-continuity-across-replacement.
  Their own materials describe the adjacent problem (over-scoped agents,
  "agent merged malicious code") as marketing, not operator pain. Generic
  runaway-agent cost incidents exist ($4,200/63hr postmortem) but are not
  Arcade-specific.
- **Why not selected:** pain receipt is architectural fit, not an observed
  problem; Bureau already holds an unsent draft probe to their contact channel
  on a different question; their "Agent Authorization" marketing makes an
  "already covered" correction likely without discriminating demand.

### Candidate 3 — GitHub Copilot team. Not selected.

- **Party:** GitHub (Copilot).
- **Consequence boundary:** cloud-hosted coding agent executing tasks.
- **Pain receipt:** strongest raw receipt (Aug–Sep 2026: multi-model provider
  failures, tasks running blind for 11 hours across 54+ organizations;
  63% of Kimi K3-routed requests failing).
- **Why not selected:** no identifiable operator on a legitimate contact
  surface (giant vendor, no named owner reachable); the pain is availability,
  not owner authority — mapping to authority continuity is inferred, not
  observed. Fails "shortest path to the consequence-owning party."

### Considered and excluded

- **Lithic:** live outbound lane already open (ASA pilot probe sent, awaiting
  reply). Excluded to avoid double-contact and muddying a live thread.
- **HolmesGPT:** separate receiver-surface probe by rule; does not
  automatically win because it is known.

## Step 3 — frozen contact plan

- **Selected party:** OpenCodex (maintainer lidge-jun).
- **Consequence boundary:** agent runtime execution boundary (native-exec,
  undeclared-tool controls, account/model failover mid-job).
- **Contact surface:** public comment on the existing issue thread
  https://github.com/lidge-jun/opencodex/issues/4579.
- **Contact timing:** after owner publication approval (GitHub mobile 2FA is a
  non-delegable human gate; see below). No probe posted before approval.
- **Initial window:** 7 calendar days after the initial probe.
- **Permitted bump:** one concise follow-up comment on the same thread,
  provided that is normal for the community and its norms. No new arguments,
  persuasion, or claims in the bump.
- **Final window:** 7 additional calendar days after the bump.
- **Terminal unresolved rule:** if still no substantive response, freeze
  NO_EXTERNAL_CONTACT_UNRESOLVED. Silence is not NO_DEMAND_SIGNAL. Silence is
  not architectural evidence. Silence must not hold the roadmap hostage. A
  later contact with another party requires a fresh label.

## Step 4 — exact frozen probe

The probe below is frozen. Do not change the message and try again under this
label.

> One operational question this thread left open. OpenCodex already fails over
> across accounts and models (pools, 429 rotation, #335) — the job keeps running
> under a different account. Authority-wise, is that failover a fresh start, or
> does anything carry the job's approvals across the switch?
>
> Concretely: if a job was approved for a risky native command under account A
> and fails over to account B mid-job, do B's executions inherit the same grant,
> and can the operator later reconstruct which actions ran under which account?
> Have you seen operators ask for that, or is the current model "the run is the
> run, whoever answers"?

In their vocabulary (failover, pools, accounts, native commands, approvals).
No OpenLine terminology. No selling. No adoption ask. No adapter proposed. No
diagrams. No research program explained.

## Terminal states (freeze exactly one)

**DEMAND_SIGNAL** requires the outside party to substantively identify at least
one of: a concrete operational use; a real consequence boundary they would
evaluate; a pilot/evaluation interest; a procurement or assurance need; an
existing pain this capability maps to; a request to test against their
environment.

A star, like, Roadmap move, reaction, generic "interesting," or polite
acknowledgment is not DEMAND_SIGNAL.

**NO_DEMAND_SIGNAL** requires a substantive external response saying the need
does not exist, does not matter to them, or does not fit their operating model.

**ARCHITECTURAL_CORRECTION** means the outside party explains that the
boundary/problem works materially differently from our premise. Preserve that
correction exactly, without trying to rescue the thesis.

**NO_EXTERNAL_CONTACT_UNRESOLVED**: contact history and timestamps frozen; no
claim about demand or lack of demand is earned; the roadmap may move to another
external surface under a fresh label.

## If DEMAND_SIGNAL

Freeze the exact external receipt. Then determine whether the outside party
supplied all four:

1. named consequential action or boundary
2. actual environment/system
3. identifiable owner/controller
4. desired evaluation or use

All four: PILOT_EARNED. Otherwise: PILOT_NOT_YET_EARNED.

Do not build the Pilot automatically. Do not turn vague interest into a pilot.

## Why this discriminates demand

The selected party (a) operates a boundary where replacement already happens
in production (failover), (b) has a live two-way conversation with the
consequence-owning maintainer, (c) publicly named the exact gap (no
owner-scoped capability contract for failover/subagents), and (d) is asked a
question that is answerable with a concrete operational fact (do operators need
the grant to survive failover?) rather than an opinion. A substantive "yes,
operators need this" is demand. A substantive "no, failover is a fresh start
by design" is a correction. A polite non-answer is neither. The probe
discriminates because it asks about their operations, not about the idea.
