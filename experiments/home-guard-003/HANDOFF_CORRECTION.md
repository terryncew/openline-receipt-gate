# HANDOFF — HOME-GUARD-003 Reproducer and Cost Study (correction pass)

**Date:** 2026-10-18
**Branch:** `study/home-guard-003-reproducer-costs` (stacked on PR #123's branch)
**Status:** READY_FOR_FINAL_INDEPENDENT_RECHECK (pending owner acceptance)

## Provenance (exact)

| Item | SHA / identifier |
|---|---|
| Frozen PR #113 mechanism | `44486057320e908ec091c327112d830f65e20caa` |
| CI-tested execution (run 39152946810) | commit `708dc537` |
| Reviewed documentation (PR #123) | commit `2ce3bd05` |
| Original artifact SHA256SUMS digest | `67f5f7e7f8fb821b0bfc00b5fdd884ed964f5716fdce1ecfa8ef1b417a011c1c` |
| This correction commit | a6c1f095427b5d7edaa5ed2c4b583ddaea43a183 |

The corrected runner reuses PR #113's six protected files byte-identical; it
executes a copied orchestration script (`run_measured.sh`) and temporary
wrappers (`measure_phases.py`) around `policy_gate` functions and
`subprocess.run` for timing only. No security-mechanism change.

## Reviewer findings — disposition

| # | Finding | Status | Evidence |
|---|---|---|---|
| 1 | Cold setup 1.36s → correct 1.562s | FIXED | Recomputed from raw monotonic_ns; COST_REPORT.md §1 |
| 2 | Conflated internal (28.467ms) vs outer (179.131ms) revocation | FIXED | Separated as §3a/§3b with exact boundaries |
| 3 | 1.41s mislabeled; correct 1.610s blocked-probe, not enforcement latency | FIXED | §3c; explicit non-claim |
| 4 | Verification 156ms → 156.235ms | FIXED | §4 |
| 5 | 568ms = five fixture policies, not device onboardings | FIXED | §5 |
| 6 | Dependency provisioning ~11.8s omitted | FIXED | §2 (CI log timestamps) |
| 7 | Marginal onboarding claimed; actually NOT MEASURED | FIXED | §6 explicit |
| 8 | Fifth device: UNSUPPORTED (was implied measurable) | FIXED | §6 explicit |
| 9 | Recovery/repeat performance: NOT MEASURED | FIXED | §6 explicit |
| 10 | SHA256SUMS 28/29; cost-timeline.jsonl stale; 3 files omitted | FIXED | Packaging corrected (finalize-before-hash, full glob, strict self-check); original preserved with digest; derived manifest labeled |
| 11 | Frozen-mechanism check did not fail CI on diff | FIXED | Workflow now exits 1 on any diff; negative test [1] passes |
| 12 | Tamper check accepted any nonzero exit | FIXED | Workflow requires `signature_invalid`; negative test [2] passes |
| 13 | No negative-test validation | FIXED | `test_safeguards.py`: 3/3 pass locally, no privileges |
| 14 | HOME-GUARD-004 naming collides with PR #114 | FIXED | Renamed to HOME-GUARD-003 Reproducer and Cost Study |
| 15 | Provenance SHAs not distinguished | FIXED | Table above; per-section labels |
| 16 | Receipt timestamp presented as enforcement instant | FIXED | Explicit non-claim in §3c and RESULTS |

## Second correction pass (2026-10-18, PR #124 residual safeguards)

| # | Finding | Status | Evidence |
|---|---|---|---|
| S1 | Manifest globs omitted nested policies/ and .log files | FIXED | Recursive `find . -type f` manifest in `run_measured.sh` + workflow; 48/48 files on real evidence; negative test [2] covers policies/ and .log |
| S2 | Tamper check required only error text, not nonzero exit | FIXED | Workflow requires BOTH `rc != 0` AND `signature_invalid`; negative test [3] asserts both |
| S3 | Negative tests vacuous (no baseline, hash-only, no exit check) | FIXED | Rewritten `test_safeguards.py`: baseline-then-fault for all three; real `git diff --quiet` on disposable checkout; dual tamper assertion. 3/3 pass locally, unprivileged |
| S4 | Handoff correction SHA vs final head | FIXED | Lineage below; substantive content commit named; tip is administrative |

Commit lineage (newest last):
- `a6c1f095` — first correction pass (PR #124 base content)
- `4dca2d32` — SHA-record amendment; reviewed head at second review
- `eceb6a11` — substantive content of THIS pass (recursive manifest, dual
  tamper requirement, non-vacuous tests, handoff updates)
- final head — administrative; no content change. The substantive correction
  is `eceb6a11`; the tip only records provenance. Resolve the tip via
  `git rev-parse study/home-guard-003-reproducer-costs`.

No frozen mechanism file was touched in any of these commits.

## Negative findings preserved

PR #114 startup leak + rollback failure; PR #115 nftables parity / no unique
advantage; public test keys; trusted updater; single receiver/run; no
real-home proof; no onboarding/commercial superiority claim. Corrected cost
numbers unchanged from the first pass.

## Safe review mechanism

The corrected workflow triggers on `workflow_dispatch` ONLY. Pushing this
branch does not run the privileged experiment. To incorporate: owner approves,
then either merges the stacked PR or manually triggers the workflow for a
fresh evidence run with corrected packaging.

## Remaining blockers

None for the correction pass itself. The privileged re-run with corrected
packaging is owner-gated (not auto-triggered).
