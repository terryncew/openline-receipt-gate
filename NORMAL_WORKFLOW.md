# CPG-001 Jain real-evidence workflow

Build base observed: `main@146058b371bb2316f20843f88cdfeeb996690af2`.

1. In Working Copy, open `openline-receipt-gate`, switch to `main`, and pull.
2. Create branch `feat/cpg-001-jain-evidence-run`.
3. Overlay this ZIP at repository root. It adds the canonical-source acquisition/unseal runner and one dedicated post-merge evidence workflow; it does not vendor Jain XLSX files.
4. Commit: `test(cpg): automate Jain real-evidence replay`.
5. Push the branch.
6. Open PR titled `CPG-001: automate Jain real-evidence replay` against `main`.
7. Merge only after the ordinary `candidate-promotion-001` and `release-check` workflows are green.
8. After merge, `.github/workflows/cpg001-jain-evidence.yml` runs automatically on `main`. Do not alter thresholds, folds, weights, or source fallbacks in response to its result.

The real-evidence workflow treats scientific negative verdicts as valid completed outcomes. CI becomes red only for acquisition/binding/preflight/execution failure. Raw publisher workbooks are deleted before the evidence artifact is uploaded.
