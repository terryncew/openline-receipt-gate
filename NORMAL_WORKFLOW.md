# CPG-001 Jain source-acquisition R4 workflow

Build base observed: `main@f27e9683ea22499f672989ce2eaf7aaeee864e9c`.

R1, R2, and R3 are preserved as `BLOCKED_SOURCE_ACQUISITION`; none reached assay preflight and none produced a scientific verdict. R4 changes source transport only. It does not change thresholds, folds, baseline weights, assay normalization, label-unseal order, selection budgets, endpoints, or verdict rules.

1. In Working Copy, open `openline-receipt-gate`, switch to `main`, and pull.
2. Create branch `fix/cpg-001-jain-source-acquisition-r4`.
3. Overlay this ZIP at repository root.
4. Commit: `fix(cpg): use BioStudies public file transport`.
5. Push and open PR: `CPG-001: use BioStudies public file transport`.
6. Merge only after `candidate-promotion-001` and `release-check` are green.
7. After merge, `cpg001-jain-real-evidence-r4` triggers automatically on `main`.
8. Do not alter the frozen experiment after R4 begins. Read the uploaded `cpg001-jain-evidence-r4-*` artifact as the execution record.

Scientific boundary:
- R4 uses only EMBL-EBI BioStudies public-file/static-storage routes frozen before execution, plus the already-frozen official fallbacks.
- The exact three publisher-named XLSX files are required and XLSX-container validated before any worksheet cells are opened.
- A public-file transport family must yield the complete triplet before any files are persisted; partial families are discarded.
- Third-party processed mirrors remain forbidden.
- R4 execution id: `CPG-001-JAIN-EVIDENCE-04`.
