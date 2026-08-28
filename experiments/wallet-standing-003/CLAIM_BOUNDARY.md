# WALLET-STANDING-003 Claim Boundary

## Earned

Given three receiver states on a controlled event-delivery schedule, a recovery
policy pinned before compromise, controlled guardian keys, a 60-second delivery
freshness ceiling, and a 600-second freeze ceiling:

- one configured guardian can temporarily reduce authority without selecting a
  successor;
- a fresh freeze blocks old-root effects at each receiver that has accepted it;
- freeze replay or another freeze for the same generation cannot extend the
  deadline;
- the old root cannot pose as a guardian or cancel the freeze;
- two configured guardians can install the next root while the freeze is live;
- a virgin Gate stays closed until it has both the succession lineage and a
  fresh quorum checkpoint for its already-known current view; and
- once a receiver observes two different valid quorum successions from the same
  prior generation, execution is quarantined pending external resolution.

This earns:

`RECEIVED_FREEZE_AND_FORK_QUARANTINE_ENFORCED_WITH_DECLARED_INFORMATION_LAG`

## Exposed on purpose

The result retains four losses:

1. Gate B executed one compromised-root action before receiving the freeze.
2. Gate C rejected a first-seen freeze older than 60 seconds and executed one
   compromised-root action. The system does not backdate an unseen event.
3. One malicious guardian denied legitimate execution for the full 600-second
   lease. At exact expiry, current-root risk resumed because no quorum recovery
   had arrived.
4. Two partitioned Gates each accepted and executed under a different valid
   generation-2 root. Cross-delivery stopped later effects but did not undo the
   two earlier executions or choose the true branch.

These are properties of available information and the precommitted trust model,
not implementation noise.

## Not earned

WALLET-STANDING-003 does not establish:

- real event transport, gossip, push delivery, device synchronization, or
  offline recovery behavior;
- a bound on propagation time outside the controlled schedule;
- secure guardian identity, independence, availability, or key custody;
- safety after compromise of the configured guardian threshold;
- root-policy rotation, guardian replacement, or root-level recovery beyond the
  frozen policy;
- a consensus, global-ordering, transparency-log, or automatic fork-resolution
  mechanism;
- reversal of effects executed before freeze or fork knowledge arrived;
- availability after fork quarantine; or
- production readiness of a local-first wallet CLI or witness service.

Evidence may travel. The wallet has policy authority `NONE`. One guardian may
only reduce authority for a bounded lease, a quorum may redirect it within the
pinned policy, and the receiver Gate owns consequences.

