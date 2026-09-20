# DEMAND-CONTACT-001 — Preregistration (AMENDED, pre-contact)

This is the authoritative protocol as amended by AMENDMENT-001 and
AMENDMENT-002. No external contact has occurred under this label.

- **Label:** DEMAND-CONTACT-001
- **Baseline main SHA:** `325a662a9d4135dba80c560c5660502da461da4c`
- **Frozen:** 2026-09-20 (pre-contact; contact has not occurred)
- **Amendment:** AMENDMENT-001 invalidates the original OpenCodex selection
  (duplicate contact on the same problem — see AMENDMENT-001.md). Candidate
  selection reran under the permanent contact-hygiene gate below.
- **Amendment:** AMENDMENT-002 replaces the frozen probe with a version that
  discriminates authority-continuity demand rather than credential freshness
  (see AMENDMENT-002.md).

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

## Contact-hygiene check (permanent pre-contact gate)

CONTACT-HYGIENE CHECK: before selecting any external party, search preserved
repo records, GitHub issue/comment history, and sent mail. Any party with an
active or recent materially related contact lane is ineligible unless the
experiment explicitly tests a follow-up. Drafts do not count as contact.

Hygiene audit (2026-09-20, owner-verified):

- EXCLUDED: OpenCodex/JUN (already contacted), Lithic (active lane),
  HolmesGPT #2492 (active lane), AgentHarness #408 (recent related lane),
  obsigna (recent related lane), Christopher Emerson/AgentAdmit (live thread),
  AIUC (active lane), AAIF wg-identity-and-trust (active lane), Skyfire
  (recent related lane).
- ELIGIBLE but not selected: Arcade.dev (unsent draft only; no genuine pain
  receipt), Armilla AI (draft only; no direct replacement-authority pain
  receipt), GitHub Copilot team (no prior contact; documented pain is
  availability, not authority continuity), MCP community / AuthZEN / ATF /
  Zenity (no direct replacement-authority pain receipt).

## Step 1 — prior-evidence inspection (completed pre-contact)

Inspected: openline-receipt-gate experiments, openline-bureau/demand
(DEMAND_HYPOTHESES.md, OUTREACH_LOG.md, RESPONSES.md, TARGETS.md),
openline-receiver-pilot-map (CONTACT_PACKAGE.md, CANDIDATES.md, REJECTED.md,
BEST_PILOT.md), buyer-mandate-discovery (REFRESH_2026-09-19.md, OPENLINE_FIT.md),
goals (lithic-asa-receiver-pilot-outreach, openline-commercial-outreach-follow-up),
owner-verified contact trail (2026-09-20).

Result: no named outside party has expressed a concrete desire to evaluate this
exact capability. Prior contacts are different questions or active lanes (see
hygiene audit above).

## Holmes separation

Holmes is a separate receiver-surface probe. Its question is architectural: can
its existing approval point consume external current-authority standing?

Do not modify that issue under DEMAND-CONTACT-001.

Do not count Roadmap automation, reactions, views, silence, or generic
architectural interest as demand.

## Step 2 — candidate set (amended, frozen)

### Candidate 1 — OpenHands (All-Hands AI). SELECTED.

- **Party:** OpenHands (open-source autonomous coding-agent platform;
  github.com/OpenHands; commercial company All-Hands AI), maintainers
  publicly identifiable on the repo.
- **Consequence boundary:** agent sandbox execution — the agent runs shell
  commands, edits files, and acts in cloud-hosted sandboxes; enterprise
  deployments run many scheduled/automation conversations.
- **Pain receipt:**
  - OpenHands issue #16356 (open, verified 2026-09-20): "Conversation LLM
    config is frozen at creation time — resuming after API key rotation fails
    permanently." Each conversation's resolved model + API key is persisted
    at creation; resume never re-resolves against the account's current
    credentials. Consequence observed on a shared instance: a single
    credential rotation permanently broke ~13 pre-rotation conversations
    across OpenAI, Fireworks, and a litellm-proxy token. The issue's own
    proposed structural fix is "store a profile reference and re-resolve
    live credentials whenever the conversation resumes — so credential
    rotation transparently propagates to conversations referencing that
    profile." This is the authority-continuity problem: the owner's authority
    moved (rotation), and the agents could not follow it.
  - Companion pain: killed background agents auto-respawning and "revived
    agents re-running stale prompts from old sessions" (shipped changelog
    fix) — the stopped-agent side: authority that should have died, didn't.
- **OpenLine capability that maps:** owner-controlled authority continuity
  across worker/credential replacement — succession moves authority forward
  under owner control; the superseded holder cannot regain it; history
  survives. Exactly the two directions OpenHands' pain straddles.
- **Who controls adoption:** the maintainers (project architecture).
- **Legitimate contact surface:** public comment on the open issue thread
  https://github.com/OpenHands/OpenHands/issues/16356.
- **Missing receipt:** whether operators want conversations to track the
  account's current authority automatically, or treat rotation as a
  must-recreate boundary.
- **Falsifier:** maintainers say credential pinning is intentional isolation
  (a rotated credential should never flow into an existing conversation), or
  that "recreate the conversation" is the accepted operating model.

### Candidate 2 — Arcade.dev. Not selected.

- No genuine pain receipt for authority-continuity-across-replacement.
  Prior pass already reached this; nothing new found. Draft probe exists
  but is a draft, not contact — and not a pain receipt either.

### Candidate 3 — Armilla AI. Not selected.

- AI liability insurer; genuine claims-evidence pain, but no direct pain
  receipt about agent/worker replacement with authority continuity. Draft
  only, not contact.

## Step 3 — frozen contact plan

- **Selected party:** OpenHands.
- **Consequence boundary:** agent sandbox execution; credential rotation
  across conversations (issue #16356).
- **Contact surface:** public comment on
  https://github.com/OpenHands/OpenHands/issues/16356.
- **Contact timing:** after owner publication approval (GitHub mobile 2FA is a
  non-delegable human gate). No probe posted before approval.
- **Initial window:** 7 calendar days after the initial probe.
- **Permitted bump:** one concise follow-up comment on the same thread,
  provided that is normal for the community and its norms. No new arguments,
  persuasion, or claims in the bump.
- **Final window:** 7 additional calendar days after the bump.
- **Terminal unresolved rule:** if still no substantive response, freeze
  NO_EXTERNAL_CONTACT_UNRESOLVED. Silence is not NO_DEMAND_SIGNAL. Silence is
  not architectural evidence. Silence must not hold the roadmap hostage. A
  later contact with another party requires a fresh label.

## Step 4 — exact frozen probe (AMENDMENT-002)

The probe below is frozen. Do not change the message and try again under this
label.

> Operational question on the structural fix here. If a conversation
> re-resolves to a new credential/profile after rotation, what should happen
> to any execution permissions or approvals already associated with that
> conversation—carry forward with the conversation, be rechecked under the
> replacement credential, or reset?
>
> I'm trying to understand whether operators need the conversation's
> authority state to survive credential/provider changes independently of
> whichever credential is currently backing the LLM, or whether
> re-creating/re-approving the conversation is the expected model.

In their vocabulary (conversations, profiles, credentials, resume,
agent-server). No OpenLine terminology. No selling. No adoption ask. No
adapter proposed. No diagrams. No research program explained.

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
in production (credential rotation killing live conversations), (b) documents
the pain publicly with observed blast radius (~13 conversations, one
rotation), (c) publicly named the structural fix (re-resolve live credentials
on resume), and (d) is asked a question answerable with a concrete operational
fact (do operators want conversations to survive rotation?) rather than an
opinion. A substantive "yes, operators need this" is demand. A substantive
"pinning is intentional isolation" is a correction. A polite non-answer is
neither. The probe discriminates because it asks about their operations, not
about the idea.
