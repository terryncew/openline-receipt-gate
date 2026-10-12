# Independent state and receipt acceptance audit

Audited repository HEAD `8a537d4ff598541bb21cc564b3220ec97ef09fb3`, current source under `gateway/receiver-package`. Result: **no material state or receipt blocker reproduced within the documented controlled offline pilot** (one owner, one card identifier, exactly 100 USD cents per authorized purchase, protected host, no old database restoration). This result is not an external Lithic acceptance or deployment verdict.

The existing SDK environment held an older installed adapter, so all execution explicitly set `PYTHONPATH` to the current checkout and confirmed the imported adapter and HTTP server filenames. Python 3.12.14, cryptography 50.0.1, official Lithic SDK 0.132.0. Tests and fault-injection outputs live outside the repository; tracked and untracked status remained clean.

## Independent execution

- `state-regression.log`: **31 tests, all passed, no skips, 12.139 seconds**. Includes 19 existing independent-process/atomicity tests, 8 live-corruption HTTP tests, and 4 HTTP credential/reused-token/503 recovery tests. Independent processes with unique tokens consume pending authority exactly once; duplicate tokens produce one identical durable decision. OS exits during signing roll back authority consumption; exits after commit preserve the signed decision and retry. Unsigned cached result/fingerprint corruption cannot rebind or promote a signed decision. Live missing/replaced/truncated/header/B-tree-corrupt state cannot acknowledge approval from cached pages. Writer unavailability and signer failure return empty HTTP 503 without committing or consuming pending authority, then a recovered retry approves once.
- `extra-state-probes.py`, `extra-state-probes.json`, `extra-state-probes.log`: independently checked all **39** files in the preserved evidence SHA-256 manifest, with zero mismatches. The explicit pin file matches the published laboratory pin, and three distinct transaction receipts verify cryptographically as APPROVED / CARD_PAUSED / APPROVED, each for 100 USD cents.
- The standalone verifier accepts the actual evidence and rejects a different independently supplied receiver key, a changed receipt result, and a changed signature. The verifier establishes signed receiver decisions; it does not itself verify bundle history or prove a real settlement. Trusted local pin initialization before ASA is exercised by the fixture; real independently authenticated key delivery is still explicitly outside this offline authorization.
- Receipt reads using the correct enrolled bearer return HTTP 200. The synthetic ASA secret, receiver public pin, worker private key, unrelated bearer, and a valid bearer for an unknown receipt each return HTTP 401. These checks do not print credential material. Reads produce zero application changes. Only the bearer SHA-256 hash is in `integrators`; main SQLite/WAL/SHM files are all mode 0600. Public sequence evidence contains no private-key, secret, bearer, password, or credential fields.

## Boundary reproduced, not an in-scope defect

The custom probe saves a complete database while a valid intent is pending, then consumes it, admits owner-signed revocation, and restarts. The old identical transaction token correctly returns its committed APPROVED decision and a new token correctly returns CARD_PAUSED. Intentionally restoring the old complete database and reopening it under the same separately pinned receiver key permits a new token to consume the restored pending intent and returns APPROVED.

This demonstrates that the receiver pin authenticates signing identity, not storage freshness. It is explicitly documented as unsupported in `LITHIC_PREFLIGHT.md:174-180`: old complete restoration can erase the monotonic checkpoint, and coherent host-administrator rewriting is outside the guarantee. Minimal operational condition for this pilot: keep receiver storage protected and do not restore old complete state. No HSM or production recovery redesign is required to substantiate the stated offline preflight scope.

## Relevant code boundaries

- `openline_receiver/lithic_adapter.py:159-175`: bounded in-process lock, BEGIN IMMEDIATE, pre/post durable guards, commit/rollback ownership.
- `openline_receiver/lithic_adapter.py:180-209`: live file identity/header, fresh read-only integrity/reference/signing identity, authority, and signed-decision checks.
- `openline_receiver/lithic_adapter.py:435-474`: stored receipt signature must match the independently known receiver key, signed fields must match cached columns and token, full JSON fingerprint prevents changed-token reuse, immutable historical decisions survive revocation.
- `openline_receiver/lithic_adapter.py:530-555`: transaction errors acknowledge no decision; bearer hashes are scoped to the receipt principal and receipt reads revalidate state/signature.
- `openline_receiver/lithic_server.py:36-80`: duplicate auth/content headers and transfer encoding are refused; processing/state failures map to HTTP 503.

HTTP 503 is evidence that this receiver acknowledged no decision, **not proof of provider-level decline**. Any future external pilot must independently configure and verify Lithic's failure/fallback behavior; the current report explicitly claims no real ASA delivery. The bounded local concurrency results are plausible for this scope; they are not capacity or external latency guarantees.
