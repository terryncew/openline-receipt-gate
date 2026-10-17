# OPENLINE-CONSEQUENCE-001 acceptance reconciliation (post hoc)

**Status:** Retrospective mapping only, not recovered preregistration, independent rerun, or new proof. Prepared from the original twelve requirements supplied in the owner mission and the checked-in OPENLINE-CONSEQUENCE-002 README at commit `15e5eebcc4738495fcb5b4760cab766f5e6be7f2`. Do not treat a test name or reported pass as an independently verified assertion about every requested property.

**Scope:** Draft PR #120, unmerged. This note adds no runtime code and changes no acceptance threshold. The recorded run is 42 tests: 41 passed, one conventional-only inapplicable skip; 27 existing authorization tests reported passing. The two original dual-write crash tests intentionally failed. Local comparison: **PARITY**. Overall evidence remains **PARTIAL**, not `LOCAL_CONSEQUENCE_VERIFIED`, pending an independent rerun and scenario-level audit.

| # | Original mission acceptance requirement | Reported test mapping (both arms unless noted) | Reconciliation / audit target |
|---|---|---|---|
| 1 | Correctly approved commissioning change commits once | `test_01` exact commit and authenticated retry; `test_11` fresh authorization for already committed transition | Inspect initial and final protected rows, one-use ledger and signed outcome; verify no second mutation |
| 2 | Simulation evidence changed refused | `test_08` stale simulation/configuration/site | Check a distinct altered simulation digest and zero protected row changes |
| 3 | Robot software/configuration changed refused | `test_08` | Check distinct configuration alteration and unchanged rows |
| 4 | Site snapshot/version changed refused | `test_08` | Check distinct site-version alteration and unchanged rows; supplied digest is not physical-site truth |
| 5 | Owner approval expired or revoked refused | `test_06` revocation, `test_07` expiry under lock, `test_16` callback expiry, `test_19` revocation before waiting writer | Check signed owner head, lock ordering and zero mutation for each denial |
| 6 | Receiver policy tightened refused | `test_09` changed/disabled policy | Verify actual policy revision and zero protected mutations |
| 7 | Replayed one-use authorization refused | `test_01` authenticated idempotent retry; `test_11` distinct valid receipt for committed transition; `test_18` SQL uniqueness | Distinguish safe `ALREADY_COMMITTED` response from permission to execute again; inspect consumption uniqueness |
| 8 | Concurrent workers same commitment at most one succeeds | `test_03` four writer processes | Verify exactly one committed mutation and all other writers' dispositions |
| 9 | Crash before commit leaves zero protected mutation | `test_04` real process death before COMMIT | Check post-crash rows, authorization consumption and signed outcome absent together |
| 10 | Crash after commit before response recovers without duplicate | `test_05` real process death after COMMIT | Check committed rows, consumption and signed outcome survive and authenticated retry does not mutate |
| 11 | Claude-to-Codex-style worker succession preserves owner authority; new subject must be valid | `test_10` succession under stable subject and foreign-subject denial; `test_06` stale receiver worker | Confirm separate worker labels are not treated as authenticated subjects; owner head continuity and subject authorization must be independently inspected |
| 12 | Forged, mismatched or stale evidence refused | `test_02` forged/changed bindings; `test_08` stale artifacts; `test_12`, `test_20`, `test_21` independent tamper checks | Verify negative cases and zero protected mutation; distinguish post-commit verifier rejection from pre-commit admission refusal |

## Evidence anchors and limitations

- Experiment narrative and reproduction commands: `experiments/openline-consequence-002/README.md`.
- Matrix output: `experiments/openline-consequence-002/evidence/after/raw.log`; hashes/commands: `evidence/after/manifest.json`.
- Scenario DBs, row snapshots, verifier process results: `evidence/after/scenarios/`.
- Original negative-control failures: `evidence/before/raw.log` and `negative-result.json`.
- PR metadata and tested SHA: `evidence/delivery.json`.
- The experiment README says independent verifier processes accepted 38 valid snapshots and rejected six tampered cases (four in matrix and two additional consumption tamper cases). This is **reported** evidence; this reconciliation did not rerun those processes.
- This mapping is based on the README's scenario descriptions. It is not yet a line-by-line audit of test implementations and raw SQLite state for every subcase. In particular, requirements 2–4 share one test grouping; confirm each distinct altered input is exercised. Requirement 12 combines admission refusals with post-commit verifier rejection; they are different properties.
- The conventional arm uses the same signed OpenLine authorization inputs and verification, so this demonstrates **parity of local consumption/atomicity**, not parity between fully independent commercial identity/authority ecosystems.
- SQLite provides local atomicity in both arms. OpenLine's possible remaining differentiator is portability and independent trust across organizations; this experiment does not establish that advantage.
- No physical execution, safety certification, independent organization, external receiver adoption, or market demand is proved.

## Closure recommendation

Keep Draft PR #120 unmerged. Freeze the local consequence-adapter feature scope. An independent reviewer should verify the twelve mapped assertions against actual test bodies and raw rows before declaring the acceptance list fully covered. Preserve **PARITY** for the matched local baseline and **PARTIAL** for the larger mission. Then return to external-receiver acceptance and measured cross-organization trust costs rather than expanding this adapter.
