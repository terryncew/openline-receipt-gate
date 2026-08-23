# CPG-001 — Jain 2017 Canonical Result

**Execution:** `CPG-001-JAIN-CANONICAL-01`  
**Evidence tier:** `CANONICAL_SOURCE_BOUND_CONFIRMATORY`  
**Frozen primary verdict:** `NO_COMPENSATION_SIGNAL`

The three original publisher-named Jain supplementary XLSX files were manually supplied, SHA-256 bound, structurally validated, and processed through the previously frozen CPG-001 design. No policy threshold, ranking weight, fold, budget, or verdict criterion was changed.

## Bound source artifacts

- `pnas.1616408114.sd01.xlsx` — 16292 bytes — SHA-256 `7ae53f9151c4be89b75cc43a7cc1de885aeb6e0a88206e140e396dea7741338c`
- `pnas.1616408114.sd02.xlsx` — 26709 bytes — SHA-256 `aa0b4734ebf4cb5674564ee0659aa95792602259c8493a4cdf1e92ba0a5c2c6f`
- `pnas.1616408114.sd03.xlsx` — 31008 bytes — SHA-256 `8538513ca1ffc1408372aebb4eb79a2c6699f5352674fa98135cde82ad483a78`

## Parser correction before scientific execution

Canonical SD03 contains a textual footnote in column A after the 137 antibody rows: `aArbitrarily long RT of 25 min to indicate no elution`. The generic parser initially treated that footnote as candidate 138. The correction ignores a row when every resolved assay field is null/non-numeric. This rule uses spreadsheet structure only; it does not inspect candidate outcomes, ranking scores, thresholds, or clinical status. After correction, SD03 has exactly the same 137 candidate identities as SD01.

## Primary 25% result

| Held-out group | Composite-control declared liability | Gate declared liability | Reduction | Held-out control | Held-out gate | Fill |
|---|---:|---:|---:|---:|---:|---:|
| group_1_cross_or_self_interaction | 2.9% | 0.0% | 2.9% | 11.4% | 11.4% | 100.0% |
| group_2_hydrophobicity_or_colloidal | 2.9% | 0.0% | 2.9% | 2.9% | 2.9% | 100.0% |
| group_3_polyspecificity | 8.6% | 0.0% | 8.6% | 2.9% | 2.9% | 100.0% |
| group_4_accelerated_stability | 2.9% | 0.0% | 2.9% | 5.7% | 5.7% | 100.0% |

The preregistered compensation signal required a **≥10 percentage-point liability reduction in at least 3 of 4 primary folds**. Observed: **0/4**.

Yield passed: **4/4** folds met the ≥80% fill condition; pooled fill was **100.0%**. Held-out quality passed: pooled held-out flag rate was **5.7%** in both arms. Authority parity passed: constrained ranking with the identical frozen constraints matched Receipt Gate exactly. Coverage was **100.0%** (137/137 complete cases).

## Interpretation

Receipt Gate removed every declared gated liability from the selected set, but at the preregistered 25% selection budget the composite ranker was already selecting too few liability-bearing candidates for the prespecified compensation effect to appear. The reductions were 2.9, 2.9, 8.6, and 2.9 percentage points—below the frozen 10-point bar in every fold.

So the canonical experiment does **not** support a large compensatory-ranking failure signal in this Jain cohort at the primary budget. This is not `FRICTION_ONLY`: yield and held-out quality both passed. The frozen verdict is `NO_COMPENSATION_SIGNAL`.

At the prespecified 50% secondary budget, the effect grows and one fold exceeds 10 percentage points, but secondary-budget behavior cannot rescue the failed primary endpoint.

The surviving OpenLine claim is narrower: a receiver-owned hard gate can enforce non-compensable constraints and produce auditable promotion decisions, but this experiment does not show that such a gate improves biological candidate selection over an equivalently constrained ranker, nor that compensatory ranking is a large practical failure mode in this historical cohort.
