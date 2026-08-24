# Jain sequential assay selector — discovery freeze

This benchmark asks a different question from CPG-001.

CPG-001 tested whether hard non-compensable promotion improved candidate selection on the Jain 2017 panel. It did not establish that advantage and remains frozen.

This benchmark treats assays as scarce sequential measurements. For a held-out antibody, the selector chooses which assay to run next. It stops efficiency counting when the first already-predeclared Jain developability liability is exposed.

The frozen dynamic selector uses continuous values from assays already observed to estimate the liability probability of every remaining assay. The core question is whether conditional measurement ordering exposes a declared liability with fewer assay units while reducing false reassurance.

The Jain panel is now a discovery set, not a confirmation set. No tuning after this freeze is allowed. Any generalization claim requires an independent antibody panel.

## Reproduce locally

The historical source XLSX is not committed. Supply the exact SD03 file whose SHA-256 is bound in `JAIN_SELECTOR_FREEZE.json`.

```bash
python -m pip install scikit-learn==1.8.0
python benchmarks/trial_selector/run_jain_selector.py --sd03 /path/to/pnas.1616408114.sd03.xlsx
python benchmarks/trial_selector/verify_jain_selector_result.py --sd03 /path/to/pnas.1616408114.sd03.xlsx
```

## Interpretation boundary

A "liability" here means only a crossing of a frozen Jain Table-1 warning threshold. One assay is one cost unit because assay-specific dollar/time costs are unavailable. This benchmark does not predict clinical success or failure.
