# CPG-001 Jain design-lock workflow

Build base observed: `main@e457eeeb514709b5b92b3e4faaf4c4c91b2aa622`.

1. In Working Copy, open `openline-receipt-gate`, switch to `main`, and pull.
2. Create branch `feat/cpg-001-jain-design-lock`.
3. Overlay this ZIP at repository root. It changes only CPG-001 benchmark/design files and CI coverage.
4. Commit: `test(cpg): freeze Jain 2017 confirmatory design`.
5. Push the branch.
6. Open PR titled `CPG-001: freeze Jain 2017 confirmatory design` against `main`.
7. Merge only after `release-check` and all four `candidate-promotion-001` matrix jobs are green.
8. Do not run the Jain outcome replay in this branch. This branch freezes the claim, baseline, cohort rule, correlation audit, and numeric falsifier before source artifacts/status labels are used.

After merge, the next branch is the source-binding/normalization run. GDPa1 remains untouched until Jain CPG-001 is complete.
