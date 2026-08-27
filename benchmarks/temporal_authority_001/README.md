# TEMPORAL-AUTHORITY-001

## Question

Do receiver-owned authority, execution-time revalidation, and field-tier
privacy still hold when they are composed around the same exact action?

The repository had already established each piece separately. This suite puts
them at one boundary and gives them one chance to fail together.

## Frozen sequence

Every arm starts with the same complete synthetic transfer parameters. The
workload commits them before minimization, the receiver admits the minimized
request under its own field definition, and the receiver-pinned owner admits a
mandate. The real Authority Compiler then freezes the exact call.

One intervention may fire at
`AFTER_COMPILE_BEFORE_RECEIVER_SPEND`:

| Arm | Change at the anchor | Expected effect |
|---|---|---:|
| Stable owner | None | 1 |
| Stable owner + signed peer `GO` + deadline | None | 1 |
| Unrelated receiver change | A different mandate slot advances | 1 |
| Relevant supersession | The selected mandate slot narrows | 0 |
| Relevant supersession + signed peer `GO` + deadline | The selected slot narrows | 0 |
| Hidden payload mutation | A payload-only field changes after commitment | 0 |
| Fresh owner successor | The successor is current before selection and compile | 1 |

The peer message is authentic test data. It is never passed as a tool
argument, evidence assertion, mandate, or preflight input.

## What counts as a pass

- Each authorized control reaches the harmless callback exactly once.
- Each relevant mid-flight change consumes the one-use permission but stops
  before the callback.
- The unrelated-slot sham does not overblock.
- Adding a peer `GO` and six-minute deadline changes neither matched outcome.
- The hidden payload mutation is caught even though the minimized attributes
  supplied to the gate are unchanged.
- Every signed field-tier receipt binds the actual gate decision hash while
  storing neither complete parameters nor minimized values.
- The independent verifier can reproduce the artifact checks without importing
  `olp_gate` or the benchmark runner.

Any unauthorized effect, overblock, peer-driven outcome change, sensitive
literal in the public report, or broken receipt binding yields
`TEMPORAL_AUTHORITY_COMPOSITION_GAP`.

## Run and verify

```bash
python benchmarks/temporal_authority_001/run_suite.py
python benchmarks/temporal_authority_001/verify_report.py
python -m unittest tests.test_temporal_authority_001 -v
```

## Result

The frozen seven-arm run returns
`TEMPORAL_AUTHORITY_COMPOSITION_PASS`. Four controls execute once. All three
hostile arms stop before the harmless effect. The public report contains zero
frozen raw or minimized literals.

## Claim boundary

This is a deterministic local composition test. It is not a live reproduction
of Auto-Policy's edge transport, the ATC monitor, or the OpenAI/Hugging Face
incident. The external work supplies hostile shapes and temporal requirements;
OpenLine supplies the implementation under test.

The field-tier receipt remains `EVIDENCE_ONLY`. Execution authority still lives
in the separately verified gate receipt and receiver-owned one-use ledger.
Remote projection honesty, hardware-backed keys, distributed state, crash
recovery, and legal authority remain outside the earned claim.

