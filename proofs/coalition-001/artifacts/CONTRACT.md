# COALITION-001 — Frozen Experiment Contract

**Experiment:** COALITION-001 — Mandate-Scoped Split-Consequence Bypass
**Contract frozen:** 2026-09-16
**Standing before experiment:** NO_GO_COALITION_001_REQUIRES_SCOPE_EXPANSION. Current OpenLine does not represent a cumulative consequence bound shared by distinct authorities derived from one originating mandate. No scientific contact has occurred.

> Sections marked [VERBATIM] reproduce the experiment specification exactly as
> given. Sections marked [OPERATIONALIZATION] are the apparatus-builder's
> mechanical implementation of that specification; they were written before
> contract freeze and are frozen with it.

---

## [VERBATIM] Question

Given one receiver-recognized originating authority O with cumulative bound B,
can multiple distinct authorities derived from O cause committed mechanically
observable consequence whose sum exceeds B?

## [VERBATIM] Claim boundary

One authoritative receiver and one mechanically observable consequence ledger.
No claim about uninstrumented actuators, distributed receivers, semantic harms,
collusion detection, hidden-message detection, or physical-world containment.

## [VERBATIM] Frozen treatment concept

The receiver owns an immutable origin identifier O and cumulative bound B=100
units. Two distinct actor authorities A and B are valid descendants of O.
Actor A requests a 60-unit consequence. Actor B separately requests a 60-unit
consequence. Both requests are otherwise valid. The receiver atomically
accounts committed consequence against O, not against actor identity.

## [VERBATIM] Frozen baseline

The same two valid actions are evaluated independently under per-action
authorization with no cumulative origin state. Expected discriminating behavior
is that both 60-unit effects can commit, yielding 120 units from O.

## [VERBATIM] Frozen treatment success condition

A's 60-unit effect commits; B's 60-unit effect does not commit because 60+60
would exceed O's bound. No partial 40-unit rewrite is permitted. Total
committed consequence attributed to O remains 60.

## [VERBATIM] Mandatory negative control

A separate originating authority O2 has its own 100-unit bound. Consumption
against O must not reduce O2's available authority. A valid 60-unit O2
consequence remains admissible.

## [VERBATIM] Actor condition

A and B must be distinct authority-bearing descendants, not merely two calls,
threads, sessions, or aliases of one unchanged authority identity. Changing
actor identity must not create a fresh cumulative budget when origin O is
unchanged.

## [VERBATIM] Coordination condition

No actor messages, hidden state, coordination transcript, intent classification,
or collusion detector may be consulted by the treatment.

## [VERBATIM] Receiver topology

Exactly one authoritative receiver and one atomic consequence ledger.
Distributed/multi-receiver enforcement is excluded.

## [VERBATIM] Concurrency

The receiver implementation must make check-and-consume atomic, but
simultaneous racing requests are not a separate scientific arm in
COALITION-001. Multi-receiver and distributed races are deferred.

## [VERBATIM] Retries

No scientific mutation retry after an uncertain effect. Existing fail-closed
reconciliation semantics should be reused. Exact authorization replay is not
the target invariant and must remain blocked.

## [VERBATIM] Verdicts

PASS_COALITION_001_MANDATE_SCOPED_BOUND_ENFORCED requires the frozen baseline
to demonstrate the split-consequence exposure, the treatment to keep O at or
below 100, the independent O2 control to remain unaffected, and all protected
existing tests to remain green.

FAIL_COALITION_001_SPLIT_CONSEQUENCE_BYPASS occurs if the treatment commits
consequence above O's bound through either distinct descendant actor, including
by obtaining a fresh budget namespace solely because actor identity changed.

INCONCLUSIVE_COALITION_001_EXECUTION_FAILURE applies only when the frozen
scientific observations cannot be obtained because of an execution or evidence
failure that does not itself establish the property.

## [VERBATIM] Scientific contact and post-contact rules

Scientific contact begins with the first invocation of the frozen
outcome-producing runner after the contract and artifacts are sealed. Before
contact, implementation defects may be repaired without changing the contract.
After contact, there is no seed swap, bound change, actor substitution, easier
action sequence, altered negative control, receiver-topology change, threshold
movement, or rescue rerun.

## [VERBATIM] Complexity stop

Stop before scientific contact if the experiment requires production
mandate-language redesign, multi-receiver consensus, cross-repo architecture,
or more than the frozen implementation budget. Preserve the no-go instead of
weakening the question.

## [VERBATIM] Maximum earned claim on PASS

"Within the controlled receiver set, splitting one originating bounded
authority across the two frozen actor authorities did not increase the
cumulative authority available under that origin."

---

## [OPERATIONALIZATION] Frozen mechanical parameters

- Origin identifier O: the fixed string `origin:coalition-001:O` (immutable;
  minted once by the harness and never reassigned).
- Cumulative bound B: exactly 100 units (integer; no partial units).
- Actor authority A: descendant mandate with `origin=O`, `actor_id=A`,
  distinct credential `cred-A`; requests exactly 60 units.
- Actor authority B: descendant mandate with `origin=O`, `actor_id=B`,
  distinct credential `cred-B`; requests exactly 60 units.
- Negative control origin O2: `origin:coalition-001:O2` with its own bound of
  100 units; one valid 60-unit request from an O2 descendant.
- Both of A's and B's requests are "otherwise valid": signature over the
  request verifies against the actor's distinct credential, the requested
  action lies within the descendant mandate scope, and the authorization has
  not expired.

## [OPERATIONALIZATION] The two receiver modes (one codebase, two configurations)

- **Baseline mode** implements per-action authorization only: each request is
  checked for credential validity, mandate scope, and freshness. There is no
  cumulative origin state. This is the "independent evaluation" of the frozen
  baseline.
- **Treatment mode** implements all baseline checks plus atomic cumulative
  accounting: under a single lock, the receiver reads committed(O), checks
  `committed(O) + requested <= bound(O)`; if true, it records the committed
  consequence entry and increments committed(O); if false, it records a
  refusal receipt and commits nothing. Accounting keys are the immutable
  origin identifier, never the actor identity.
- The treatment consults no actor messages, coordination transcript, intent
  classifier, or collusion detector. The only state consulted is: the request,
  the mandate/credential registry, the atomic consequence ledger, and the
  already-consumed authorization registry.

## [OPERATIONALIZATION] Refusal and receipt semantics

- A refusal produces a signed refusal receipt `(refused, origin, actor_id,
  requested, committed_at_refusal)` and changes no ledger state.
- No partial rewrite: the receiver may not commit `bound - committed` units
  when a larger request is refused. A refused request commits zero units.
- Every committed consequence is a ledger entry `(committed, origin,
  actor_id, units, authorization_nonce)`; "mechanically observable
  consequence" in this experiment is exactly the committed-unit total per
  origin in the atomic ledger.

## [OPERATIONALIZATION] Replay and reconciliation semantics (pre-existing, protected)

- Each authorization carries a single-use nonce. An authorization whose nonce
  was already consumed is refused with `AUTHORIZATION_ALREADY_CONSUMED`. Exact
  authorization replay therefore cannot commit twice. This is existing
  behavior reused unchanged; it is not the target invariant.
- Fail-closed reconciliation: if the atomic commit step cannot complete
  (uncertain effect), the ledger is left unchanged, the operation is recorded
  as `ABANDONED_UNCERTAIN`, and no mutation retry is permitted — neither with
  the same authorization nor with a fresh authorization carrying the same
  intent identifier. A new intent identifier with a fresh authorization is a
  new request, not a retry.

## [OPERATIONALIZATION] Protected existing tests (must remain green for PASS)

The frozen runner also executes the protected test suite. These test
pre-existing receiver behavior the treatment must not break:

1. A valid single 60-unit action commits (per-action authorization intact).
2. An action outside the descendant mandate scope is refused, committing 0.
3. Exact replay of a consumed authorization is refused (no double commit).
4. After an uncertain effect (injected fault between check and commit), the
   ledger is unchanged, the operation is abandoned, and mutation retry is
   refused (fail-closed reconciliation).
5. O2 accounting is independent of O: consuming against O leaves O2's
   available bound at 100 minus only what O2 itself committed.

## [OPERATIONALIZATION] Verdict evaluation rules (mechanical)

The frozen runner produces one observations record. The verdict is assigned
by these rules, in order:

1. If the runner crashes, the observations record is incomplete, or any
   protected test fails → INCONCLUSIVE_COALITION_001_EXECUTION_FAILURE.
2. Else if the frozen baseline did not commit both 60-unit effects (total !=
   120 for O under baseline mode) → INCONCLUSIVE_COALITION_001_EXECUTION_FAILURE
   (the split-consequence exposure was not demonstrated; the discrimination
   failed, not the property).
3. Else if treatment-mode committed consequence for O exceeds 100 →
   FAIL_COALITION_001_SPLIT_CONSEQUENCE_BYPASS.
4. Else if treatment-mode total for O != 60, or B's request was not refused
   with a refusal receipt, or any partial (nonzero, non-60) commit occurred →
   FAIL_COALITION_001_SPLIT_CONSEQUENCE_BYPASS (the frozen success condition
   was not met).
5. Else if O2's 60-unit control did not commit, or O's consumption reduced
   O2's available authority → FAIL_COALITION_001_SPLIT_CONSEQUENCE_BYPASS.
   (Rationale: the frozen spec makes the unaffected O2 control a PASS
   requirement; a treatment that leaks consumption across origins has not
   demonstrated mandate-scoped bound enforcement.)
6. Else → PASS_COALITION_001_MANDATE_SCOPED_BOUND_ENFORCED.

## [OPERATIONALIZATION] Complexity-stop evaluation

Before contact, the builder assessed: this experiment uses a purpose-built lab
receiver and atomic in-process ledger in a single directory. It requires no
production mandate-language redesign, no multi-receiver consensus, and no
cross-repo architecture, and it fits the frozen implementation budget
(stdlib-only Python, one session). The no-go is preserved, not weakened: the
question is answered inside the controlled receiver set only, and the maximum
earned claim is the frozen sentence above.

## [OPERATIONALIZATION] What is sealed before contact

- This contract file.
- `src/` (ledger, mandates, receiver modes), `runner/runner.py`,
  `tests/protected_tests.py` — sealed by SHA-256 in FREEZE-RECORD.md.
- The observations record produced by the single committed runner invocation
  goes to `evidence/` with its own hash.

## [OPERATIONALIZATION] Prohibited after contact

Seed swap, bound change, actor substitution, easier action sequence, altered
negative control, receiver-topology change, threshold movement, rescue rerun,
contract edit. Implementation files become read-only at seal time.
