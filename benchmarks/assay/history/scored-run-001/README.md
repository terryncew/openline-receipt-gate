# Preserved scored run 001

This is the first complete passing run after `AMENDMENT-001`. It met every
frozen expectation. Before release sealing, inspection found that the signed OLP
decision details retained Assay's raw success diagnostic, which included a
temporary filesystem path. `AMENDMENT-002` removes that unnecessary disclosure
and normalizes temporary paths in the human/machine benchmark report. It does
not change fixtures, commands, expectations, source pins, scoring, verdicts, or
dispositions.

Preserved SHA-256 values:

| Artifact | SHA-256 |
|---|---|
| `RUN_REPORT.json` | `01adb2a86a4f0490978381b691f2d223037e699ffb82ff182825efaa9c680ec6` |
| `REPORT.md` | `c5e1f83f0622b0bd082dc8d071a955812b61162ff88a55021ae6c081e2cc0a8b` |
| `results/decision_receipts.jsonl` | `ad1846a3715c7e7a283d391e7236e817ce2803656514015a2be19e1420434e08` |
| `results/assay_receiver_predicate.attestation.json` | `60379132137d6d77b30c645bba19798c2849fa74b4dd2270ce772b5b524fafb7` |

The paths embedded in this historical report point to the then-current sealed
result directory. Use the artifacts in this directory when checking the hashes
above; use the top-level benchmark report for the release result.
