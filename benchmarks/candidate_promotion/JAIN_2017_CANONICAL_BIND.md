# CPG-001 Canonical Source Bind

This stage retires automated source acquisition and the 143-row teaching mirror as scientific inputs.

The runner performs **no network access**. Supply the three Jain/PNAS XLSX supplements in a local directory, plus a manual browser-acquisition attestation. It then reuses the already-frozen CPG-001 pipeline:

1. Hash and XLSX-container-validate SD01/SD02/SD03 without opening worksheet labels.
2. Open SD03 only; normalize the frozen ten assays; require exactly 137 candidate identities; compute and seal the assay-only preflight and correlation audit.
3. Only after that seal, open SD01 publication-era status labels and require the SD01 and SD03 identity sets to match exactly.
4. Emit an immutable 137-name canonical cohort manifest.
5. Run the unchanged four-fold × three-budget confirmatory replay.
6. Emit a canonical transformation receipt and final experiment receipt.

Any 137-count or identity mismatch produces `SOURCE_COHORT_MISMATCH` with no scientific verdict. A negative scientific verdict is still a successful completed experiment.

The raw workbooks are local inputs and are not required to be committed to the public repository.

Example after the source files are available:

```bash
python benchmarks/candidate_promotion/run_jain_canonical_bind.py \
  --source-dir /path/to/jain-source \
  --attestation /path/to/JAIN_2017_MANUAL_ACQUISITION.json \
  --out-dir /tmp/cpg001-jain-canonical
```
