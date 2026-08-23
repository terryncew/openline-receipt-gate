# CPG-001 Jain source-acquisition R2 workflow

Build base observed: `main@a75d16fa31f33a208fd2bf3cd1a2746a83356c87`.

The first real-evidence execution is preserved as `BLOCKED_SOURCE_ACQUISITION`; it produced no scientific verdict. This patch changes only the source transport authority by adding the official Europe PMC supplementaryFiles endpoint for PMCID PMC5293111. It does not change thresholds, folds, baseline weights, assay normalization, label-unseal order, or verdict rules.

1. In Working Copy, open `openline-receipt-gate`, switch to `main`, and pull.
2. Create branch `fix/cpg-001-jain-source-acquisition-r2`.
3. Overlay this ZIP at repository root.
4. Commit: `fix(cpg): add Europe PMC archival acquisition`.
5. Push and open PR: `CPG-001: add Europe PMC archival source acquisition`.
6. Merge only after `candidate-promotion-001` and `release-check` are green.
7. After merge, `cpg001-jain-real-evidence-r2` triggers automatically on `main`.
8. Do not edit the experiment after the R2 run starts. Read the uploaded `cpg001-jain-evidence-r2-*` artifact as the frozen outcome.

Scientific boundary:
- Europe PMC is used only through the official `/{PMCID}/supplementaryFiles` API documented by Europe PMC.
- The archive must contain all three exact publisher-named XLSX files.
- Each XLSX is container-validated and SHA-256 bound before any worksheet cells are opened.
- Third-party processed mirrors remain forbidden.
- R1 remains immutable blocked-acquisition evidence; R2 has execution id `CPG-001-JAIN-EVIDENCE-02`.
