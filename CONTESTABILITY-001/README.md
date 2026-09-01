# CONTESTABILITY-001 — SUPERSEDED PROTOTYPE

This directory is retained for provenance only.

The receipt-gate implementation from PR #75 was the first architectural prototype of the foreign-contestation boundary. It demonstrated the core separation:

`foreign artifact -> receiver validation -> receiver-owned consequence assignment`

It is **not** the canonical CONTESTABILITY-001 experiment.

## Canonical home

The canonical experiment belongs in:

`terryncew/openline-claim-graph / CONTESTABILITY-001`

Canonical handoff branch:

`feat/contestability-001`

Canonical handoff ZIP SHA-256:

`c2bd8a6c1a1c897b71a9fc00f0b672071696484d0d1d42cd1720ce868cf7b282`

The Claim Graph version is authoritative because it tests the actual post-execution standing/reconsideration seam:

`foreign filing -> ingest only -> receiver-local standing decision -> local application -> selective reopen`

It also demonstrates that the already-executed action remains `EXECUTED`, the independent lineage remains closed, and draft-specific fields are isolated behind an adapter profile rather than production OpenLine core.

## Status of this directory

The source, tests, preregistration, and confirmatory artifacts remain here so the prototype can be audited and reproduced historically.

Do not cite this directory as the authoritative CONTESTABILITY-001 result and do not extend it as CONTESTABILITY-002.

Any future contestability work should start from the canonical Claim Graph experiment.
