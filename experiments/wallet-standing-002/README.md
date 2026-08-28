# Wallet Standing 002

**Frozen verdict:** `QUORUM_ROOT_SUCCESSION_ENFORCED_WITH_DECLARED_RECOVERY_LAG`

WALLET-STANDING-001 assumed the principal root remained safe. WALLET-STANDING-002
removes that assumption.

The governing rule is simple:

> A compromised root cannot certify its own replacement.

Before any emergency, the receiver pins a recovery-policy hash naming three
guardian keys and a two-signature threshold. After root loss or compromise, two
guardians may sign one exact succession: old root, new root, generation, reason,
and effective time. The receiver verifies the quorum and advances its local
root view. The old wallet supplies evidence; it gets no vote.

This is a controlled recovery kernel, not a production identity or custody
service.

## What is tested

| Arm | Condition | Frozen result |
|---|---|---|
| 1 | Legitimate action under generation 1 | pass |
| 2 | Compromised root acts before recovery acceptance | pass; declared exposure |
| 3 | Old root poses as a guardian | reject |
| 4 | One of three guardians signs | reject |
| 5 | One approval is duplicated | reject |
| 6 | Two of three guardians install generation 2 | accept |
| 7 | Compromised old descendant after acceptance | block |
| 8 | Legitimate old descendant after acceptance | block |
| 9 | Old certificate checked as history | authentic, noncurrent |
| 10 | Fresh successor-root action | pass |
| 11 | Unrelated principal | pass |
| 12 | Tamper, replay, and rollback variants | reject all |
| 13 | Two compromised guardian keys install attacker root | accept; declared trust floor |

All 13 arms match the preregistration. Once the receiver accepts generation 2,
old-root post-acceptance execution is zero. A successor acts, old signatures
remain available as historical evidence, and the unrelated principal loses
nothing.

## The hard limits

Recovery does not erase lag. In the frozen timeline the root is compromised at
13:01 and succession is accepted at 13:06. During those five minutes the old
root can create a fresh epoch, mandate, and ACTIVE witness that the receiver
still accepts. Already executed consequences stay executed.

Recovery also moves the ultimate trust anchor rather than abolishing it. One
guardian cannot recover the wallet. Two guardians can—and two stolen guardian
keys can install an attacker root. The Gate sees valid signatures, not the
human circumstances behind them.

Finally, root succession is necessarily broad. Every descendant of the old
root becomes noncurrent, including legitimate mandates issued before the
compromise. Selectivity survives across principals, not inside a compromised
root's lineage.

## Boundary of this result

- The recovery policy was pinned before compromise.
- Guardian keys and delivery are controlled fixtures.
- One receiver maintains one linear root history.
- Guardian replacement and policy rotation are frozen.
- Competing valid successions, cross-device propagation, virgin-Gate freshness,
  partitions, and convergence remain untested.
- Wallet policy authority remains `NONE`; the receiver Gate owns admission and
  execution.

Those distribution and fork questions are WALLET-STANDING-003.

## Run

From the repository root:

```bash
python -m unittest discover -s experiments/wallet-standing-002/tests -v
python experiments/wallet-standing-002/scripts/run_frozen.py
python experiments/wallet-standing-002/scripts/verify_release.py
```

The release verifier is standard-library-only. It checks the dependency pin,
source closure, all frozen arms and metrics, both declared exposures, and the
receiver/wallet authority split.
