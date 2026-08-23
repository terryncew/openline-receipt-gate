# CPG-001 — pinned-mirror replication

Build base observed: `main@1755a0c84004ab6121328c79899289117c2c3988`.

This is the deliberate exit from the source-acquisition loop. R1–R4 remain `BLOCKED_SOURCE_ACQUISITION`; they are not rewritten or retried here. This patch leaves the canonical workflow alone and runs the already-frozen primary analysis on a public Jain transcription pinned to an immutable Git commit and Git blob.

1. In Working Copy, open `openline-receipt-gate`, switch to `main`, and pull.
2. Create branch `test/cpg-001-jain-mirror-replication`.
3. Overlay this ZIP at repository root.
4. Commit: `test(cpg): add pinned Jain mirror replication`.
5. Push and open PR: `CPG-001: add pinned Jain mirror replication`.
6. Merge only after ordinary PR checks are green.
7. After merge, `cpg001-jain-mirror-replication` runs automatically.
8. Read its `scientific_signal` as replication evidence only.

Decision rule after the run:
- Negative signal: stop CPG-001 source-acquisition work. Do not build R5/R6 canonical fetchers.
- Positive signal: one later human-browser/archive acquisition of the publisher XLSX trio is justified solely as canonical confirmation. No retuning before that confirmation.

Pinned mirror:
- repository: `HPuntu/hogroast-teaching`
- commit: `4ad3ec59ff1f6ddb886ca0cf2a9d47b1ba0f136a`
- path: `jain_data.csv`
- Git blob SHA-1: `15235ba7afc16cd9564c34078fbc1670e7383d09`
- bytes: `42777`

The workflow computes and records SHA-256 after proving the downloaded bytes reproduce the frozen Git blob identity.
