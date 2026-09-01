# CONTESTABILITY-001 — frozen protocol

## Question

Can OpenLine ingest a foreign, cryptographically bound contestation event after a valid action has already executed, keep the foreign artifact as evidence rather than authority, and selectively reconsider only the downstream decisions whose standing depends on the challenged authorization?

## External substrate

The adapter is modeled on `draft-pinto-agent-authz-contestability-00` (29 August 2026), which separates the issuer's declared effect policy, executor acceptance, authenticated filing trigger, and executor evidence that an effect was applied.

This experiment uses a deterministic HMAC fixture for authenticity testing. It does not claim wire-format or cryptographic conformance with the Internet-Draft.

## Frozen receiver policy

OpenLine recognizes one forum (`forum.example/review`) and one authorization (`auth-001`) in the fixture.

- `filed`: evidence recorded; standing unchanged.
- `accepted`: dependent consequences `QUARANTINE`; independent consequences preserved.
- `applied`: challenged authorization standing `LOST`; dependent consequences `REOPEN`; independent consequences preserved.

The foreign artifact never directly writes OpenLine consequence state. The receiver computes consequence state from local policy after validating authenticity, exact authorization/action binding, forum recognition, ordering, and replay status.

## Frozen claim graph

`auth-001 -> D1 -> D1A`

`D2` is independent.

Expected outcomes:

| foreign state | D1 | D1A | D2 |
| --- | --- | --- | --- |
| filed | PRESERVE | PRESERVE | PRESERVE |
| accepted | QUARANTINE | QUARANTINE | PRESERVE |
| applied | REOPEN | REOPEN | PRESERVE |

## Adversarial cases

The run must reject or neutralize signature tampering, authorization/action substitution, unrecognized forum, replay, out-of-order regression, a foreign direct-consequence instruction, and contestation of an unrelated authorization.

## Admission criterion

PASS requires every positive and adversarial case to satisfy the frozen receiver policy with zero independent-claim reopen events.

## Falsifier

FAIL if a valid foreign filing can self-authorize a local consequence, if an independent claim reopens, if replay/older evidence can roll standing backward, or if OpenLine cannot distinguish `filed`, `accepted`, and `applied`.
