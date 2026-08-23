# CPG-001 Jain source-acquisition R3 workflow

Build base observed: `main@357bcab6cd56faa84948ee56805aa551ed820799`.

R1 and R2 remain preserved as `BLOCKED_SOURCE_ACQUISITION`; neither produced a scientific verdict. R3 changes source transport authority only. It adds the official EMBL-EBI BioStudies accession `S-EPMC5293111`, whose S-EPMC collection is populated from Europe PMC supplementary data. The frozen CPG-001 design is unchanged.

1. In Working Copy, open `openline-receipt-gate`, switch to `main`, and pull.
2. Create branch `fix/cpg-001-jain-source-acquisition-r3`.
3. Overlay this ZIP at repository root.
4. Commit: `fix(cpg): acquire Jain supplements from BioStudies`.
5. Push and open PR: `CPG-001: acquire Jain supplements from BioStudies`.
6. Merge only after `candidate-promotion-001` and `release-check` are green.
7. After merge, `cpg001-jain-real-evidence-r3` triggers automatically on `main`.
8. Do not alter the experiment after R3 starts. Read the uploaded `cpg001-jain-evidence-r3-*` artifact as the frozen outcome.

Scientific boundary:
- BioStudies is accepted only through accession `S-EPMC5293111` and its `/info` API.
- The resolved file host must be `ftp.ebi.ac.uk`, with storage mode `fire` or `nfs`, under the exact S-EPMC accession path.
- All three exact publisher-named XLSX files must be present and XLSX-container-valid.
- Each file is SHA-256 bound before worksheet cells are opened.
- Third-party processed mirrors remain forbidden.
- No thresholds, weights, folds, budgets, label-unseal rules, or verdict rules changed.
