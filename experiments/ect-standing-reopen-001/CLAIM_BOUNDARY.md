# ECT-001 Claim Boundary

ECT-001 is a cold external integration of Jason Liu's Evidence-Carrying Termination (ECT), arXiv:2608.23623v1.

The authority split is fixed:

- **t0 / COMPLETE support:** author-owned. OpenLine does not implement, reconstruct, approximate, or second-guess ECT's certificate verifier or closed replay.
- **t1 / standing:** OpenLine-owned. Given an already author-verified t0 certificate and its admitted dependency basis, OpenLine may decide only whether a later standing event requires `REOPEN` or `NO_REOPEN`.

A missing public author verifier is therefore a hard boundary, not an invitation to recreate one. The cold external run must return `AUTHOR_VERIFIER_UNAVAILABLE` and leave t1 `UNASSESSED` until an authentic author-verifier result is available.

ECT-001 claims no result about ECT correctness, external truth, safety, alignment, or OpenLine effectiveness while t0 authority is unavailable.
