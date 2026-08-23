# IAC-004 — Hostile Unaware-Runtime Race Containment

**Status before CI:** `UNWARE_RUNTIME_RACE_READY_UNRUN`  
**Maximum standing:** `UNWARE_RUNTIME_RACE_CONTAINMENT`  
**Policy authority:** `NONE`

IAC-004 is the terminal portability test for the inherited-authority containment line.

The earlier soft asyncio design was rejected because it let the harness place the check politely before execution. This version deliberately creates a race.

All downstream coroutines are dispatched **before** the compromise receipt arrives. They execute concurrently and race toward a consequential effect boundary. Some start before detection and reach the effect boundary afterward. The runtime itself is ordinary Python `asyncio` and has no OpenLine awareness.

## What is being tested

> When correction and already-dispatched work race each other, can a receiver-owned boundary prevent tainted state that has not yet committed from committing after the correction becomes authoritative?

This is a TOCTOU problem.

A stale pre-check is not enough: work may check while authority is still valid, pause, then commit after revocation. The hardened receiver gate therefore makes correction application and effect authorization contend on the same linearizable boundary.

## Frozen arms

- `NO_PROPAGATION`
  - descendants continue after the source is compromised.

- `GLOBAL_KILL`
  - after detection, every effect is blocked, including clean work.

- `STALE_PRECHECK`
  - each task checks once before an intentional scheduling gap;
  - it does not re-check at commit;
  - this arm exposes stale-authorization laundering.

- `ATOMIC_RECEIVER_GATE`
  - correction application and effect commit share one receiver-owned atomic boundary;
  - the standing decision is made at commit time;
  - tainted state after correction blocks;
  - unresolved state quarantines;
  - clean state continues.

## Ground-truth event ordering

The receiver assigns a monotonically increasing logical sequence number while holding the same lock used by both:

- `APPLY_CORRECTION`
- `COMMIT`
- `BLOCK`
- `QUARANTINE`

A "post-detection escape" means a tainted or unresolved effect receives `COMMIT` at a sequence number greater than the correction sequence.

Wall-clock timestamps are recorded for observability, but the verdict uses the linearized receiver sequence, avoiding clock-resolution ambiguity.

## Frozen pass bar

Across 256 seeded concurrent trials:

- atomic receiver gate post-detection tainted escape rate = 0;
- atomic receiver gate post-detection unresolved escape rate = 0;
- clean commit rate >= 0.95;
- stale-precheck must have a strictly higher tainted escape rate;
- no-propagation must demonstrate tainted escape;
- global-kill must demonstrate clean-work loss.

Any failure returns:

`UNWARE_RUNTIME_RACE_CONTAINMENT_NOT_EARNED`

A pass earns at most:

`UNWARE_RUNTIME_RACE_CONTAINMENT`

## Boundary

This does not prove arbitrary code can be preempted. If an effect has already crossed the receiver commit boundary before correction linearizes, it is a pre-correction effect and is not undone.

This also does not establish cloud credential revocation, compromise detection, universal runtime portability, or protection for effects that bypass the receiver boundary.

The claim is narrower:

**correction can win against already-dispatched concurrent work at a receiver-owned commit boundary without scheduler cooperation.**
