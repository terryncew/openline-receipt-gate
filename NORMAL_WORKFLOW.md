# CPG-001 Jain assay-preflight workflow

Build base observed: `main@cb1167f62a02b857f9dd9bedf0f19c89ac30657e`.

1. In Working Copy, open `openline-receipt-gate`, switch to `main`, and pull.
2. Create branch `feat/cpg-001-jain-preflight`.
3. Overlay this ZIP at repository root. It changes only CPG-001 preflight tooling/docs, `.gitignore`, and CPG CI coverage.
4. Commit: `test(cpg): add Jain source binding and assay preflight`.
5. Push the branch.
6. Open PR titled `CPG-001: add Jain source binding and assay preflight` against `main`.
7. Merge only after `release-check` and all four `candidate-promotion-001` matrix jobs are green.

This branch does not contain Jain source workbooks and does not run the confirmatory outcome analysis. It creates the fail-closed boundary for the next physical step: bind the exact three publisher supplements, open only SD03 for assay normalization/correlation, seal the assay-only artifact, and keep SD01 clinical labels unopened until the preflight receipt says `ready_for_label_unseal: true`.
