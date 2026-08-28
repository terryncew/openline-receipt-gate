# WALLET-STANDING-004 Claim Boundary

## What 004 changes

004 does not revise wallet authority. WALLET-STANDING-003 stays byte-pinned. The only changed substrate is how a Gate learns: three separate OS processes, one private SQLite database per Gate, TCP delivery through an untrusted relay, crash/restart behavior, and a measurement clock that never participates in admission.

There is one necessary interface correction. WALLET-003's signed freeze/succession/checkpoint schemas are closed shapes, so adding `t_event_emitted` inside those records would mutate the frozen protocol. 004 therefore wraps the unchanged 003 artifact in a signed **measurement envelope** containing the inner artifact hash and `emitted_ns`. The envelope has `measurement_authority: NONE`; the Gate removes it before calling 003. This makes emission timing tamper-evident without letting the clock layer become policy.

## Earned only after a passing live run

A passing `live_result.json` earns only:

`LIVE_TRANSPORT_CONTINUITY_ENFORCED_WITH_MEASURED_PROPAGATION_LAG`

Specifically, on the tested process/socket substrate:

- a Gate produces no old-root effect after it has durably committed a received freeze;
- a crash before durable commit produces no admission and no ACK, and restart restores only the prior state;
- pre-delivery old-root exposure remains explicit rather than being backdated away;
- a cold Gate remains closed until it has successor lineage and a fresh quorum checkpoint;
- duplicate delivery and cross-epoch reordering do not regress standing;
- co-observed, genuinely valid competing successors cause quarantine rather than invented consensus; and
- `tau` is reported per admitted event as raw time, offset-corrected time, and a calibration uncertainty bound.

## Still exposed on purpose

004 does not erase propagation lag. A partitioned Gate can execute under authority it has not yet learned was reduced. A relay can starve delivery indefinitely, in which case `tau` is censored rather than zero. Effects before local knowledge remain effects.

The inherited 600-second malicious-single-guardian denial-of-service ceiling and the 2-of-3 guardian-compromise floor remain exactly where 003 left them.

## Not earned

Even a passing run does not establish independent-machine or Internet-wide propagation bounds, secure guardian custody, mobile/offline synchronization, a production witness network, consensus, automatic fork resolution, Byzantine availability, production SQLite schema stability, or a consumer wallet product. The initial 004 transport is real TCP between isolated processes on one host; cross-host and independently operated relay/witness tests remain a later falsifier.
