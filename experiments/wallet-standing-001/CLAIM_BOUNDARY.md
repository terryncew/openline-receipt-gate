# WALLET-STANDING-001 Claim Boundary

## Earned

Under the frozen receiver policy and a controlled root-signed witness source:

- fresh `ACTIVE` standing admits the bound high-risk action;
- fresh `REVOKED`, stale, and absent high-risk standing block before effect;
- a root-certified successor and an independent sibling remain usable after
  the first epoch is revoked;
- an expiry-only low-risk mandate stops at its exact signed expiry;
- selective field disclosure remains bound to the mandate's signed Merkle
  root; and
- copied or replayed presentations fail holder and receiver-challenge checks.

This supports:

`EPOCH_REVOCATION_ENFORCED_WITH_BOUNDED_OFFLINE_LAG`

## Exposed on purpose

The low-risk offline arm passes after revocation while its ten-minute mandate
is still unexpired. The Gate has no fresh witness and therefore no information
about the later event. The result records this as bounded exposure, not success
at instant offline revocation.

## Not earned

WALLET-STANDING-001 does not establish:

- instant revocation at an offline or partitioned verifier;
- witness replication, discovery, availability, or equivocation resistance;
- root recovery or succession after total wallet loss or compromise;
- production-grade key storage, transport, CLI ergonomics, or interoperability;
- unlinkable disclosure, hidden predicates, or BBS+ equivalence;
- nested or arbitrary JSON disclosure; or
- safety of a wallet that can enlarge its own mandate.

The wallet carries evidence and continuity. It has no policy authority. Only a
receiver-recognized root and the receiver's local policy can admit an effect.
