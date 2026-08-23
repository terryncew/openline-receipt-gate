# Inherited Authority Containment 001 (IAC-001)

**Status:** `PROTOCOL_CONFORMANCE_UNRUN` before CI  
**Policy authority:** `NONE`

IAC-001 tests one narrow security question:

> After compromise becomes known, can a receipt-aware receiver identify which descendants inherited tainted authority without indiscriminately revoking unrelated state?

This is a controlled-ground-truth benchmark. It is not an intrusion detector, IAM system, CIEM product, EDR product, or credential revocation service.

## Four policies

1. `NODE_ONLY` — revoke only the compromised node.
2. `GLOBAL_REACHABLE` — revoke every graph-reachable descendant.
3. `TIME_WINDOW` — revoke descendants created after compromise and before detection.
4. `OLP_SELECTIVE` — classify descendants using represented dependency evidence and explicit unknowns.

## Ground truth

Each synthetic graph contains one compromised source, true tainted descendants, clean descendants, and partially observed dependency edges. The full graph is retained as hidden ground truth; the policy sees only the represented graph.

## OLP outputs

- `REVOKE` — represented evidence proves dependence on compromised authority.
- `RETAIN` — represented evidence proves disjoint provenance.
- `UNKNOWN` — dependence or independence cannot be established.
- `QUARANTINE` — receiver treatment for `UNKNOWN`.

`UNKNOWN` is never converted into permission.

## Primary metrics

- taint recall
- retain precision
- false quarantine rate
- missed-taint rate
- false revoke rate
- weighted harm

## Frozen pass bar

OLP_SELECTIVE must achieve taint recall >= 0.95, retain precision >= 0.95, missed-taint rate <= 0.05, reduce false quarantine by >= 0.20 versus GLOBAL_REACHABLE, and beat NODE_ONLY, GLOBAL_REACHABLE, and TIME_WINDOW on weighted harm.

Maximum verdict:

`CONTROLLED_GROUND_TRUTH_SELECTIVE_CONTAINMENT`

Failure verdict:

`SELECTIVE_CONTAINMENT_NOT_EARNED`

## Claim boundary

IAC-001 does not detect compromise, undo completed side effects, revoke credentials outside the receipt-aware perimeter, prove correctness on real cloud/IAM graphs, replace IAM/CIEM/EDR/SIEM tooling, or grant policy authority.
