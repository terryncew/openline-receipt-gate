# Portable standing claim — KILL-SWITCH-RECEIPT-INTEGRATION-001

Frozen with the implementation on branch `integration/portable-kill-switch-001`.
The portable contract baseline is openline-kill-switch @ a303796 (read-only
reference; never a runtime dependency).

## Exact claim

The tested OpenLine Receipt Gate / Wallet path can consume the portable
kill-switch standing at its existing consequence boundary: current owner
revocation causes old worker authority to be refused without rewriting
historical receipts.

## What this means, concretely

- Portable owner-STOP is the existing owner-signed terminal standing:
  `MandateOwnerView` head → REVOKED for the covered mandate slot, or
  `ReceiverStandingView` head → INACTIVE for the covered action, admitted
  through the existing `admit` successor rules. No new authority machinery,
  no new store, no wallet change.
- STOP_EFFECTIVE is the monotonic head sequence at which the terminal state
  was admitted.
- The final-authority standing check runs inside the same ledger `_locked()`
  region as permission consumption in `VerifiedCommitLedger.check_and_consume`
  / `execute_once`, so the final standing check and commit-or-refuse share
  one serialization point. Compiled or preliminary authorization is
  explicitly non-authoritative at finalize time.
- If standing cannot be established at finalization, the effect does not
  commit (fail closed) and the inability to check is journaled.
- The attempt journal binds (commit_seq, stop_effective_seq, attempt outcome)
  and carries STOPPED / ESCAPED / UNKNOWN path verdicts plus the
  PRE_STOP_COMMIT ordering classification. An independent appraiser can
  re-derive every verdict from the journal plus the standing admission
  history via `olp_gate.stop_standing.derive_path_verdicts`, without trusting
  the live system.

## What is NOT claimed

- Production-ready.
- Every action covered: only actions whose finalize path installs the
  final-authority check are covered.
- Boundary unavoidable: the claim holds for consequences that actually go
  through `VerifiedCommitLedger.execute_once`; paths that bypass the ledger
  are outside it.
- Distributed STOP.
- Arbitrary infrastructure.
- Model replacement solved.
- External adoption.

## Limits

- Single-boundary integration only: one receiver's consequence boundary, one
  covered authority at a time.
- Ordering is mechanical (monotonic commit_seq vs monotonic head sequence),
  never wall-clock.
- The adapter is a protocol adapter in repo vocabulary
  (`olp_gate/stop_standing.py`); it creates no second authority engine.
