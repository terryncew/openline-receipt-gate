# CPG-001 Canonical Result — Working Copy workflow

Repository: `terryncew/openline-receipt-gate`

1. Pull current `main`.
2. Create branch `test/cpg-001-jain-canonical-result`.
3. Overlay this ZIP at repository root. Do not add the three raw XLSX files.
4. Confirm the diff contains the parser correction, focused test/workflow update, and `benchmarks/candidate_promotion/results/jain_canonical_01/` evidence only.
5. Commit with `test(cpg): record canonical Jain result`.
6. Push and open PR titled `CPG-001: record canonical Jain result`.
7. Merge only after CI is green.

Scientific disposition: `NO_COMPENSATION_SIGNAL` under the frozen primary 25% design. The parser correction is structural only: canonical SD03 contains one textual footnote below the 137 antibody table, and rows with no numeric value in any resolved assay field are ignored as non-data rows. No policy, threshold, ranking formula, fold, selection budget, or verdict criterion changed.

Raw publisher XLSX artifacts are intentionally excluded from this overlay. Their byte counts and SHA-256 hashes are recorded in the evidence receipts.
