# RUNTIME-CONTRACT-002 — Receiver-owned ancestry closure

Status: **FROZEN BEFORE REMEDY IMPLEMENTATION**

Base:

`3f7874dde7e0e1b7918ceac00eee0f251c452b94`

## Why this exists

`RUNTIME-CONTRACT-001B` produced:

```text
TRANSITIVE_CONSEQUENCE_NOT_DISCOVERED
```

The runtime already handled the direct case:

```text
X loses standing
A blocks
```

But the fixture also encoded:

```text
X -> A_receipt -> B
```

and B still executed after X was revoked.

That result earned one thing: **receiver-owned ancestry closure**.

It did not earn a general graph platform.

## Minimum model

At commit time, the receiver records only dependencies that actually earned the
decision:

```text
support hash --BASIS_FOR--> committed decision receipt hash
```

For the frozen fixture:

```text
X         -> A_receipt
A_receipt -> B_receipt

CONTROL_C -> C_receipt
```

The producer cannot authoritatively add those edges. They are admitted by the
receiver at the same boundary that commits the decision.

## Standing loss

When the receiver later admits:

```text
X -> INACTIVE / REVOKED
```

the closure layer computes downstream reachability over the already-admitted
`BASIS_FOR` edges.

Expected result:

```text
affected:
  A_receipt
  B_receipt

unaffected:
  C_receipt
```

No `X -> B` standing update is allowed. No B-specific reopening instruction is
allowed.

That is the entire point of the experiment.

## What “affected” means

`AFFECTED_UPSTREAM_STANDING_LOSS`

The old receipt remains authentic. Its hash and signature are not rewritten or
invalidated.

But an affected receipt can no longer continue earning unchanged execution
standing at the Receiver Gate.

So after X is revoked:

```text
A_receipt  authentic, affected
B_receipt  authentic, affected
C_receipt  authentic, unaffected

retry B    QUARANTINE / BLOCK
retry C    ALLOW
```

Authenticity and current legitimacy remain separate.

## Receiver-owned state

The minimum state is:

```text
admitted receipt/support hashes
BASIS_FOR edges
monotonic edge sequence
processed standing-loss event IDs
affected receipt hashes
causal path for each affected receipt
monotonic closure-event sequence
```

No producer writes.

## Adversarial requirements

The remedy must also prove:

```text
producer-forged dependency edge  -> reject
cycle-producing edge             -> reject
standing-loss replay             -> idempotent
unrelated C                      -> unaffected
historical A/B receipts          -> still cryptographically authentic
```

## Pass

`TRANSITIVE_CONSEQUENCE_CLOSURE_ENFORCED`

Only if X's standing loss reaches A and B transitively, B is blocked without a
manual X-to-B update, C survives, and historical receipts remain authentic.

## Fail

`TRANSITIVE_CONSEQUENCE_CLOSURE_STILL_ESCAPABLE`

Any manual descendant update, missed B consequence, false-positive C,
producer-owned edge, cycle escape, replay duplication, or receipt rewriting is
enough to fail.

## Deliberately outside this experiment

Not yet:

```text
multi-basis sufficiency
partial invalidation
graph database architecture
cross-receiver propagation
distributed consistency
automatic undo
provider integrations
scale / latency claims
```

Those are separate questions. In particular, this contract does **not** say
that losing one of several independent bases should always reopen a decision.

Build only the smallest receiver-owned closure view and Gate integration needed
to test this contract.
