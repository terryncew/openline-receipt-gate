# RUNTIME-CONTRACT-002 — Frozen problem/remedy proof

Status: **FROZEN**

Main after remedy merge:

`50cb779d486f0b4dba14f4f8f509b1561373d9dc`

## Before

`RUNTIME-CONTRACT-001B`

```text
TRANSITIVE_CONSEQUENCE_NOT_DISCOVERED

X loses standing
A blocks
B still executes
C still executes
```

The fixture had already encoded:

```text
X -> A_receipt -> B
```

B used A's receipt as its exact support. A's receipt recorded X as its basis.
There was no manual `X -> B` update.

Result SHA-256:

`44db09e4c229e7f5654059a64b047fbe31f22f4e67afd0b18ad6f89d91634f7f`

Artifact ZIP SHA-256:

`4aa21bb254b874a144b0cab19935003a2f39f0b2fbd84993ba86f429a89b2b81`

## Frozen obligation

The earned remedy was deliberately narrow:

```text
receiver-owned BASIS_FOR edges
single accepted basis per committed receipt
transitive downstream closure on standing loss
historical receipts remain authentic
```

Contract SHA-256:

`2fd83bc34ee459f80ef03aeff71df3579f907fc448398e5e410794efd3f538b2`

Contract git blob:

`0d8ca58d86c108d2a7d1365b4986aa9fba474403`

## After

`RUNTIME-CONTRACT-002`

```text
TRANSITIVE_CONSEQUENCE_CLOSURE_ENFORCED

before X revoke:
  A COMMIT
  B COMMIT
  C COMMIT

after X revoke:
  A QUARANTINE
  B QUARANTINE
  C COMMIT
```

Exact affected closure:

```text
A_receipt
B_receipt
```

Recovered causal path:

```text
X -> A_receipt -> B_receipt
```

No explicit `X -> B` update was used.

Adversarial checks:

```text
producer-forged edge       PASS
cycle edge                 PASS
standing-event replay      PASS
unrelated control          PASS
historical authenticity    PASS

5 / 5
```

Result SHA-256:

`1f9b484430e9e2c6edaf02197d368af6a56f99ea83feb70122898d9d2132759c`

Artifact ZIP SHA-256:

`4f9645144fc2f223388a6fe316990184b963c3ca39661b4da8a3846561b702d6`

Ancestry module SHA-256:

`cbf73f1c35ce84c76036029700f3380f4f1dd573c03ef066b73f74b0dd21f8ff`

## Earned

For a **local receiver-owned single-basis dependency chain**, OpenLine can
record ancestry at the receiver commit boundary and later propagate an
upstream standing loss transitively to exactly the downstream receipts that
depended on it.

Affected descendants stop earning unchanged execution standing. Unrelated
receipts remain executable.

Historical receipts are not rewritten.

## Not earned

Still outside this proof:

```text
multi-basis sufficiency
automatic undo of historical effects
cross-receiver propagation
distributed consistency
production graph storage / scale
latency guarantees
```

## State after freeze

```text
RUNTIME-CONTRACT-002   CLOSED
multi-basis semantics PARKED_UNTIL_EARNED
next thread           STOLEN-AUTHORITY-001
```
