# CPG-001 normal workflow

Build base observed: `main@8fdc354b524f7351096d67264989d5659d7c655f`.

1. In Working Copy, open `openline-receipt-gate`, switch to `main`, and pull.
2. Create branch `feat/cpg-001-candidate-promotion`.
3. Overlay this ZIP at repository root. It is additive; do not delete unrelated repository files.
4. Commit: `feat(gate): add CPG-001 candidate promotion profile`
5. Push the branch.
6. Open PR titled `CPG-001: add candidate promotion profile and replay harness` against `main`.
7. Merge only after the existing `release-check` and new `candidate-promotion-001` workflow are green.

The synthetic report is an architecture self-test only. Do not describe CPG-001 as experimentally confirmed until the exact Jain supplementary artifacts are bound and the frozen replay is executed. GDPa1 remains a second-pass replication because its current Hugging Face files are gated.
