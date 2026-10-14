# RECEIVER-001: matched conventional comparison and stop decision

## Current conclusion
**NO competitive win established.** No live standards-compliant, security-equivalent OAuth/AuthZEN competitor was executed in this branch. The prior PR #104 OPA-A path is *not* matched: it omits one-use replay protection, signed decision evidence, and Wallet authority while the OpenLine arm includes them. The older 3-step versus 5/8-step comparison and ~140ms p50 penalty describe a different, uneven setup; they cannot support a portability/adoption advantage.

The conventional control should be built/configured from standards, not intentionally weakened. Relevant standards: OAuth 2.0 token introspection (RFC 7662) for active/revoked token and scope checks, and OpenID AuthZEN Authorization API 1.0 (final January 2026) for separate PDP/PEP authorization checks. A receiver may trust an independently administered authorization server and maintain its own deny policy. Standard signed evidence can be layered on top; AuthZEN's allow/deny response alone is NOT signed effect evidence.

## Requirements of a truly matched comparison

| Requirement | OpenLine fixture | Fair conventional equivalent | Result |
|---|---|---|---|
| Owner authority | Wallet signed bundle, pinned owner root | owner-operated or independently trusted authorization server, explicit receiver trust | Conventional NOT TESTED |
| Separate receiver policy | action + required owner scopes | receiver-local PDP/PEP rules added after token status and scopes | NOT TESTED |
| Worker replacement | new owner mandate for new worker key; same bundle format | new authorized OAuth client/token or proof-of-possession binding without first AI provider | NOT TESTED |
| Replay protection | nonce/challenge single use in memory | PoP/replay cache with equivalent persistence and lifetime | NOT TESTED |
| Revocation | fresh owner bundle admission; offline TTL | online introspection or push of fresh issuer state with matched outage/freshness bounds | NOT TESTED |
| Receipts | signer-pinned Ed25519 Wallet decision receipt | independently pinned signed conventional decision receipt with equivalent fields | NOT TESTED |
| Actual effect | separate synthetic append after allow | identical receiver-local append and independently observable boundary | NOT TESTED |
| Human setup time | **not measured**; CI scripted 28 assertions | clean-room unfamiliar developer same hardware/requirements | NOT TESTED |
| Maintenance | private Wallet Gate internals and vendored reference contracts | IdP/PDP/PET integration and operation, update/rotation costs | NOT TESTED |

A system can already reproduce these mechanisms using conventional components. Neither standards nor the current synthetic result establishes that OpenLine reduces integration time, total code, security complexity, or ongoing cost.

## Decision
Technical synthetic mechanism: tested after CI completion, read-only independent signature verifier required. Competitive differentiation: **INCONCLUSIVE**. Commercial adoption: **NOT TESTED**. Stop feature expansion and do not invent a production network. The next comparison needs a real independent receiver choosing its usual standards-based path for the same action, then independently measured receipts, setup time, code burden, revocation, and maintenance. No outreach or deployment without separate owner authorization.

The shared owner trust root does not create a shared global effect ledger. For example, two receivers cannot enforce a *combined* budget ceiling merely by verifying the same signed grant; safe cross-organization budget conservation requires separately coordinated state, outside this test and not authorized as a feature.
