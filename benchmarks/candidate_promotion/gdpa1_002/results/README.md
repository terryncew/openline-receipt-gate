# CPG-002 results

No external benchmark score is checked in at installation.

The `CPG-002 GDPa1 Replication` workflow fetches the pinned Ginkgo source, runs the frozen replay, performs a stdlib-only independent replay under `python -I`, and uploads:

- `source-receipt.json`
- `score.json`
- `verdict.json`
- `independent-verification.json`

The first repository-visible full result must come from that workflow.
