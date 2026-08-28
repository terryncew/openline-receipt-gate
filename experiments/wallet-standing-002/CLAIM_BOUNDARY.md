# WALLET-STANDING-002 Claim Boundary

## Earned

Given one receiver, a recovery policy pinned before compromise, controlled
guardian keys, and delivery of one succession event:

- the old root cannot appoint its own successor;
- fewer than two distinct guardian approvals cannot advance the root view;
- two valid guardian approvals can install generation 2 without the old root;
- once accepted, every old-root descendant is blocked before effect;
- the successor root can issue a fresh executable lineage;
- old signatures remain verifiable as historical-but-noncurrent evidence; and
- an unrelated principal remains executable.

This earns:

`QUORUM_ROOT_SUCCESSION_ENFORCED_WITH_DECLARED_RECOVERY_LAG`

## Exposed on purpose

Two conditions remain visible in the result:

1. Before the receiver accepts succession, the compromised root still carries
   its previous authority. The frozen five-minute interval includes one
   successful compromised-root action.
2. A threshold compromise is terminal under the pinned policy. Two valid stolen
   guardian keys install an attacker root because the cryptographic evidence is
   indistinguishable from legitimate recovery.

## Not earned

WALLET-STANDING-002 does not establish:

- retroactive reversal of effects during the recovery lag;
- real guardian identity, independence, availability, or secure custody;
- safety after compromise of the configured threshold;
- policy rotation or guardian replacement;
- recovery-event discovery or delivery to another device or a virgin Gate;
- convergence when two valid quorum events name different successors;
- a global ordering service, transparency log, blockchain, or consensus layer;
  or
- selective survival of descendants beneath a compromised root.

Recovery places ultimate succession authority in a precommitted quorum. The
receiver still decides whether the evidence changes executable standing. The
wallet itself has policy authority `NONE`.
