# Published Lithic reviews

Start at [HANDOFF.md](../../HANDOFF.md). This directory transfers workspace-only nonsecret reviews/evidence to GitHub; application code and verified tests are unchanged.

Authoritative order: [latest closure](external-gates/EVIDENCE_CLOSURE.md), then [containment review](external-gates/CONTAINMENT_REVIEW.md), then [earlier source research](external-gates/REPORT.md) and [acceptance audit](acceptance/AUDIT.md). Old five-probe/30-second suggestions and result JSON are historical, superseded by written-evidence-first case selection. Execution remains unauthorized.

[TRANSFER_ORIGINS.json](TRANSFER_ORIGINS.json) records original and published hashes. Historical workspace manifests are provenance, not checksums for adapted publication paths/Markdown. [PUBLICATION_SHA256SUMS.json](PUBLICATION_SHA256SUMS.json) is the publication map, keyed relative to repository root. Original preflight39-file evidence remains unchanged under `gateway/receiver-package/evidence/preflight-001`.

Clickable links and two independent scripts' evidence/output paths were made portable. No cryptographic/test logic changed and no suite was rerun for handoff. Old stdout/prose `/workspace` references identify original execution; use HANDOFF's portable commands. Public/synthetic identifiers, signatures and published verifier vectors are evidence, not real pilot credentials or real enrollment.

No private key, DB/WAL/SHM, credential/environment file, cache or virtualenv is included. Official demo sources are research evidence; optional unsigned/default-approval behavior is unsuitable for calibration and must not be deployed from this bundle.
