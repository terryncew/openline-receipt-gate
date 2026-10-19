# Reviewer handoff

Task branch: `study/wallet-receiver-interop-001`.
Base: `76f72ccccce79622f40163763cf614bd1d7ff776`.

Review `adapter.py` first: external root pin precedes Wallet verification; only
the named signed scope maps to a document action; history projection never
becomes replacement owner-signed native authority. Then review codec injection
and persistent quarantine in the two existing kit files. All other implementation
and evidence are confined to this example directory.

Reproduce using README. Inspect run-003 `summary.json`, both `allow` snapshots,
both `revocation` and `succession` traces, and both deliberately failing
`mutated_document/verification.stdout` reports. Hash manifests bind raw evidence;
they are integrity inventories, not external attestations. Fixture private keys
are deliberately public and have no production authority.

Wallet, canonical wire, protected main, Muse proof-package files and Gemini
research files are unchanged. No deployment, real effect, outreach or merge.
No owner approval is needed to reproduce the synthetic demonstration. Production
rollout, broader scopes, revocation transport, quarantine recovery, key rotation
and external-effect atomicity are explicitly outside this PR.

Do not promote an ACCEPT (authority evidence admitted), ALLOW signed decision,
or a valid signature alone into a claim that an external action committed.
Only the captured synthetic SQLite effect is independently reconciled here.
