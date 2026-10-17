The existing JSON Verified Commit ledger cannot atomically cover an external
SQLite mutation: controlled process death reproduced both spent-without-effect
and effect-without-completed-evidence windows. This adds a fixed local SQLite
commissioning adapter that runs the unchanged Verified Commit consumer against
transaction-local storage and commits consumption, protected rows and signed
outcome evidence together. Existing authorization modules remain unchanged.

The same-input conventional SQLite baseline reaches PARITY. The local matrix
ran 42 tests (41 passed, one inapplicable conventional JSON-ledger check skipped),
plus 27 existing authorization tests and four isolated PR #119 tests. Independent
verifier processes accepted 38 snapshots and rejected six expected tamper cases.
Raw failures, databases, inspected rows, fixture hashes and commands are in
`experiments/openline-consequence-002/evidence/`; see its README for limits.

Overall mission verdict remains PARTIAL: the canonical OPENLINE-CONSEQUENCE-001
scenario specification is absent from the supplied reference, so the matrix is
explicitly reconstructed. No real robots, production changes, deployment, paid
APIs, merge, or reliance on PR #119. Keep this PR Draft and unmerged.
