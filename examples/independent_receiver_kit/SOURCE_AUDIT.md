# Source audit before implementation

Mission OPENLINE-INDEPENDENT-RECEIVER-001. Base `main` at
`81db6acb72149df989aac1827e5f621b0873d57b`. Written before kit code.

Existing Receipt Gate components: `olp_gate.crypto` provides strict JSON,
integer-canonical OLP Ed25519 signing and verification. `mandate_owner` provides
receiver-pinned owner slots and portable owner-signed lifecycle records binding
native `principal_mandate/v1` hashes; `MandateSpec` and `assess_effect` validate
scope. `SubjectBoundCommitGate` consumes receiver-authenticated identity but does
not establish it. `MandateOwnerView` caches reads; a long-lived cached view cannot
establish current revocation at an independently running receiver. Reconstructing
its view from transaction-local signed history avoids that cache. No core change
is necessary. Original Verified Commit remains unchanged and is not required for
this different, reusable-mandate integration.

Wallet read-only source: `terryncew/openline-wallet` main
`f309aac8aecae36c4f354c7455281af6dbce486a`. It exports
`openline.wallet.receiver_bundle.v1`; verification reports `EVIDENCE_VALID`,
`wallet_policy_authority=NONE`, `decision_authority=RECEIVER_GATE`. Wallet's mandate
subject/scopes/history are not the native Receipt Gate principal mandate and
owner authorization schemas. Common signature primitives do not establish semantic
interoperability. This kit must not claim to accept a Wallet export unchanged.
The exact file references and observed CLI behavior will accompany the final audit.
No Wallet or Lite files are modified and no Wallet runtime dependency is added.

PR #119 (`1749a226b5f77cabc98f04a8655636229e0b11c2`) changes the refund example's
owner-cap behavior and distinguishes unsigned preflight refusal from signed gate
decision. PR #120 (`46d42565ac4cec6e8dbe17d5bc01b9c57e8e79c9`) concerns atomic SQLite
consequences and a conventional baseline. Both are context-only; neither is merged,
modified or imported. This branch is cut from main, not either PR.

APS means Agent Passport System, authoritative project
https://github.com/agent-passport-system/agent-passport-system and
https://agent-passport.org. Its documentation overlaps scoped delegation,
revocation, enforcement gateways and signed receipts. Legacy Delegation and draft
AuthorityDelegationV1 must be distinguished. The APS comparison is documentation-
only unless an equivalently configured offline integration is practical; do not
compare unlike runtime workloads or invent a result. Pinned source findings follow
in the comparison evidence. OAuth/JWT can supply an external trusted issuer,
subject/audience/time/action claims, worker proof of possession, revocation checks,
receiver-owned policy, replay protection and signed audits without OpenLine.
RFC 7519, RFC 8725 and RFC 9068 describe relevant JWT safeguards; offline signed
fixtures do not constitute a deployed OAuth authorization server.

Minimum addition justified: one experiment-only local receiving API for a fixed
SQLite document-intake operation, owner-side fixture issuance, authenticated worker
proof over the exact request, receiver-pinned config, transaction-local history,
replay state and signed decisions; a matched EdDSA JWT mode; small offline driver,
adversarial tests and independent evidence verifier. Reuse native owner authority
and scope checks in the OpenLine mode. No new core feature, cryptographic primitive,
standardized protocol, hosted service or general policy platform is proposed.

Unproven claims: external organizational adoption; real provider identity; secure
key provisioning/custody; acceptance of Wallet export semantics; global latest-head
knowledge offline; outside-system atomicity; physical power-loss durability; database
rollback detection. Provider names are fixture labels. Owner-signed heads are fresh
for at most 60 seconds from signed issue time (also bounded by authorization and
mandate expiry); duplicate delivery never renews that window. Revocation becomes
operative when this receiver accepts it, and no known revoked standing may be
reinstalled by old receipts. Missing/stale history fails closed. A withheld remote
revocation can remain unknown until the bounded freshness window ends.

Fair baseline: standard EdDSA compact JWT owner grants and lifecycle evidence,
pinned issuer/audience, owner-bound worker public key and worker-signed exact-action
JWTs, the same 60-second freshness ceiling, monotonic history, policy, replay SQL
constraints, fixed effect and signed audit. Both may reuse existing signature
libraries. No comparison with a weak bearer-only token, and no claimed OpenLine
advantage from merely passing internal tests. Setup timing is an internal clean
venv/isolated source run, not a cold external developer or organization test.
