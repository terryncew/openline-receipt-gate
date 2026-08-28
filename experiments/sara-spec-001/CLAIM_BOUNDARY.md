# SARA-SPEC-001 Claim Boundary

SARA-SPEC-001 is a `PAPER_SPEC_RECONSTRUCTION`, not a cold integration. The
paper is independently authored; the executable SARA state and extension in
this experiment are implemented by OpenLine from the pinned v1 specification.

Published SARA is task-scoped and clears its runtime authorization state when
the task terminates. Its post-task disposition is therefore
`OUT_OF_SCOPE_AFTER_TASK_END`. That arm is recorded and never scored as a
failure.

The minimal extension may preserve SARA's published K, F, and H state
byte-for-byte, attach a standing update to an existing K item, and scan the
existing H calls and observations at evaluation time. It may not persist a new
edge class, reverse index, descendant table, causal graph, or per-decision
support record. Those structures would import the OpenLine mechanism into the
competitor.

The sealed oracle is representation-blind. It receives only the frozen
scenario and emits decision dispositions plus whether historical evidence
changed. Neither implementation defines its own success vocabulary.

If the minimal SARA extension matches the oracle, the earned verdict is
`SARA_EXTENSION_PARITY`. That narrows OpenLine's novelty claim. If it cannot
match without a forbidden dependency representation while OpenLine does, the
maximum earned claim is that runtime authorization provenance does not
necessarily contain sufficient structure for selective post-task standing
propagation.

This experiment makes no claim about SARA's reported attack-success rate,
AgentDojo or AgentDyn performance, model behavior, live external code, or
production deployment. It changes no production Receipt Gate or wallet code.

`policy_authority: NONE`
