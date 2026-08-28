# WALLET-STANDING-003: Distributed Freeze and Fork Quarantine

WALLET-STANDING-002 proved that a receiver can replace a compromised wallet
root after receiving a valid guardian-quorum succession. It also exposed a
five-minute execution window before that event arrived. This experiment asks
what a receiver can safely do sooner without giving one guardian the power to
redirect authority.

## Result

`RECEIVED_FREEZE_AND_FORK_QUARANTINE_ENFORCED_WITH_DECLARED_INFORMATION_LAG`

All 15 frozen arms passed.

- One precommitted guardian could impose one 600-second, reduce-only freeze for
  the current root generation.
- A freeze received within 60 seconds stopped old-root effects at that Gate.
- A Gate that had not received the event still executed once. A Gate that first
  saw it after 60 seconds rejected the stale event and also executed once.
- Replay and a second guardian event could not extend the freeze.
- A malicious guardian caused the full declared 600-second denial of service.
- At exact expiry, current-root execution resumed if quorum recovery had not
  arrived.
- Two guardians installed a successor during the freeze; both tested Gates then
  admitted the new root.
- A virgin Gate required both the succession lineage and a fresh quorum
  checkpoint before execution.
- During a partition, two valid competing quorum successions each executed at
  one Gate. After cross-delivery, both Gates quarantined; neither pretended to
  have solved consensus.

## Run it

From the repository root:

```bash
python -m pip install -e .
python -m unittest discover -s experiments/wallet-standing-003/tests -v
python experiments/wallet-standing-003/scripts/run_frozen.py
python experiments/wallet-standing-003/scripts/verify_release.py
```

The runner is deterministic. CI preserves the committed result, runs the
experiment again, and requires byte-for-byte equality.

## Authority model

The wallet carries continuity evidence and has policy authority `NONE`.

| Actor | Permitted change |
|---|---|
| One precommitted guardian | Temporarily reduce execution for one root generation |
| Guardian quorum | Install one exact successor root or attest a known receiver view |
| Receiver Gate | Admit events and decide whether an effect may occur |
| Wallet message or old root | No power to enlarge, cancel, or redirect authority |

A checkpoint confirms a root view the Gate already derived from succession
events. It cannot introduce a new root. A freeze stops consequences only after
the receiver learns it.

## Deliberate limits

This is a controlled event-delivery schedule, not a network implementation. It
does not test mobile devices, guardian custody, offline synchronization, a live
witness service, transport adversaries, or independent operators. The
two-of-three threshold-compromise floor from WALLET-STANDING-002 remains.

The experiment also leaves conflict resolution outside the Gate. Cross-seeing
two valid branches produces quarantine and an explicit
`EXTERNAL_RESOLUTION_REQUIRED` receipt. It does not select a winner.

See [CLAIM_BOUNDARY.md](CLAIM_BOUNDARY.md) for the earned claim and
[frozen_result.json](frozen_result.json) for every arm and exposure.

## Files

- `wallet003/distribution.py` — freeze, checkpoint, distributed receiver, and
  fork-quarantine kernel
- `scripts/run_frozen.py` — 15-arm deterministic experiment
- `tests/test_wallet003.py` — protocol, attack, boundary, and release tests
- `preregistration.json` — fixed schedule, predictions, metrics, and forbidden
  rescue moves
- `DEPENDENCY_PIN.json` — immutable WALLET-001/002 dependency pins
- `FREEZE.json` and `RELEASE_MANIFEST.json` — frozen and release integrity

