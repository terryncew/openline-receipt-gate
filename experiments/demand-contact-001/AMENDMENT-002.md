# AMENDMENT-002 — DEMAND-CONTACT-001 probe correction (pre-contact)

- **Date:** 2026-09-20 (pre-contact; no external contact has occurred)
- **What changed:** the frozen probe text only. Party (OpenHands), contact
  surface (https://github.com/OpenHands/OpenHands/issues/16356), contact
  window, terminal definitions, one-contact rule, no-build rule, and all
  other preregistration terms are unchanged.
- **Why:** owner review found the old probe risked measuring credential
  freshness — which issue #16356 itself already answers (~13 conversations
  broken by one rotation; the issue proposes re-resolving current
  credentials on resume) — rather than demand for authority continuity
  across replacement. The correction separates "new key works" from "the
  job's authority survives replacement."
- **Note on the "Why this discriminates demand" section of the
  preregistration:** that paragraph was written against the old probe's
  framing ("do operators want conversations to survive rotation?"). The
  discrimination rationale now carried by the amended probe is this one:
  the new question asks for a concrete operational fact about execution
  permissions/approvals surviving credential/provider changes —
  answerable as yes-demand (operators need authority state to survive),
  no-by-design (re-create/re-approve is the accepted model), or
  architectural correction. It cannot be answered with "yes, rotation
  breaks things," which the issue already established.

## Old probe (superseded, never sent)

> Operational question on this issue's premise. Pinning each conversation's
> resolved credentials at creation means one credential rotation silently
> kills every pre-rotation conversation — your #16356 shows ~13 conversations
> dying from a single rotation on a shared box. Is that pinning intentional
> isolation — i.e., a rotated credential should never automatically flow into
> an existing conversation — or is the desired behavior that a conversation
> tracks the account's current authority, so when the owner rotates the
> backing credential, existing conversations continue under the new one?
>
> Concretely: have operators asked for conversations to survive credential
> rotation, or is "recreate the conversation under the new key" the accepted
> operating model?

## New probe (frozen, AMENDMENT-002)

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
