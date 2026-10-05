# BASELINE-EXIT-001 comparison

**No OpenLine-exclusive property was observed.** The owner-signed JWT plus
signed revocation-list profile reproduced all six primary OpenLine outcomes
without a mandate lifecycle object, Authority Compiler, or Verified Commit.
The OAuth Token Exchange profile also reproduced them, with a surviving AS
issuing a new B token. The offline JWT continued after owner revocation intent
until its short expiration. These are differences in credential binding and
freshness dependencies, not evidence of OpenLine architectural superiority.

All six preregistered arms completed on their first run. A separate fresh
process reconstructed **107 signed receiver events**, using only O's initial
public pin and portable evidence, after the services had stopped. No apparatus
failure or product repair occurred. Comparative OpenLine superiority is
**INCONCLUSIVE: no discriminating exclusive outcome**. The observed binding
and revocation outcomes themselves are conclusive for this local fixture.

## Frozen provenance

- Initial branch `work`; base HEAD `abc610be560284130e0d08b2fd51e59ef0b1c623`.
- Experiment branch `experiment/baseline-exit-001`.
- Preregistration SHA `e259c854458fcbf741b4610e85626edf3c29eebb`.
- Preregistration SHA-256 `e97b0d4bce3fc8bb78c657d07c6e83de864c13ed341265fb037ab850e3fd5483`.
- Implementation SHA used by the run `74f23d5650ce119e066df07ec3c1b01d8c49c70c`.
- The final evidence/report commit is the branch HEAD, obtained with
  `git rev-parse HEAD`; it is deliberately not embedded in its own hashed files.
- Python 3.12.14; PyJWT 2.15.1; cryptography 50.0.2; setuptools 82.0.1;
  wheel 0.47.0; OpenLine Receipt Gate 0.6.0rc6. Exact runtime metadata is in
  [run_001/metadata.json](run_001/metadata.json).

The preregistration was committed before any apparatus implementation. The
apparatus was committed before executing any scenario arm. Its source remained
unchanged through execution and verification. `audit_evidence.py` was added
afterward only to challenge preserved evidence and seal hashes, with no rerun
or change to an arm. The experiment changes no `olp_gate/` files, historical
evidence, film or production assets. It does not reopen an earlier experiment.

## What was actually removed and retained

For each arm, A was an actual dedicated worker/provider subprocess with its
own random Ed25519 request-authentication key. It executed a 25-cent effect,
then was terminated, reaped, and its unique directory removed. The supervisor
discarded its A private-key reference. There was no restart, outage recovery,
A callback, provider fallback or A-to-B message. B was a new process with a
different key and directory, created only after that removal. Removal evidence,
PIDs and timestamps are in each arm's `removal.json` and `timeline.json`.

O retained J's original grant independently of A and supplied it directly to B.
R retained J's effect counter. Primary arms had a job grant independent of
worker identity; both transport actors were permitted in O's initial signed
contract. B was therefore preknown and preauthorized, not an arbitrary unknown
replacement. The bound controls instead restricted the original consequential
grant to A. No arm received a new owner authorization at succession.

The original provider and every non-owner authority service unique to A were
absent after removal. No such unique service was part of initial authority:
this is a **deliberately owner-rooted architecture**, not a demonstration that
a provider-rooted grant can survive removal of its own ultimate issuer.
O/R survived all arms. Arm B retained its independent owner-delegated AS.
This distinction is material to the scope of the result.

## Six-property comparison

P1 = owner-originated authority; P2 = receiver enforcement; P3 = succession
without departed-party/new-owner reauthorization; P4 = owner revocation;
P5 = portable verifiable history; P6 = post-exit independent verification.
The exact PASS/PARTIAL/FAIL rules remain in the frozen preregistration.

| Arm | P1 | P2 | P3 | P4 | P5 | P6 |
|---|---|---|---|---|---|---|
| OL_JOB | PASS | PASS | PASS | PASS | PASS | PASS |
| A: JWT_OFFLINE | PASS | PASS | PASS | PARTIAL | PASS | PASS |
| B: OAUTH_EXCHANGE | PASS | PASS | PASS | PASS | PASS | PASS |
| C: OWNER_LIST | PASS | PASS | PASS | PASS | PASS | PASS |
| OL_BOUND | PASS | PASS | FAIL | PARTIAL | PASS | PASS |
| JWT_BOUND | PASS | PASS | FAIL | PARTIAL | PASS | PASS |

No aggregate winner is assigned. For each arm, exact observations and each
receiver event index are in [verification_001.json](verification_001.json).

| Arm | Exact observed evidence |
|---|---|
| OL_JOB | 9 signed events, 6 effects. A and B executed the same J counter; the 101-cent probe did not execute. First post-revocation refusal: `mandate_owner_authority_revoked`. Fresh reconstruction checked O's mandate/head chain and existing Gate receipts. |
| JWT_OFFLINE | 68 signed events, 65 effects. B reused O's original 8-second JWT, with no R status fetches. The 101-cent probe was denied. B remained accepted after O's revocation intent; refusal was `expired_token_or_status` at signed JWT expiry. |
| OAUTH_EXCHANGE | 10 signed events, 7 effects. A and B each made one authenticated exchange (2 total). B's token bytes were new, `act.sub=B`, with unchanged O/J subject and original owner-grant hash. 10 signed introspections bound exact token hashes. Refusal: `revoked_at_as`. |
| OWNER_LIST | 10 signed events, 7 effects. B reused O's original 60-second JWT; 10 signed-list fetches. Sequence advanced from 1/empty to 2/revoked jti. Refusal: `owner_revoked_jti`. |
| OL_BOUND | 5 signed events, 1 A effect. B was denied `authority_subject_mismatch` before O revoked. Later refusal was `mandate_owner_authority_revoked`. A's original grant failed the non-executing post-STOP verifier probe. |
| JWT_BOUND | 5 signed events, 1 A effect. B was denied `holder_mismatch` before O revoked. That reason remained first because binding is checked before list status. The non-executing A-holder probe separately verified `owner_revoked_jti`. |

P1 is supported by each O-signed original grant and initial trust contract,
including O's explicit AS delegation in B. Worker signatures authenticate
requests; they do not authorize J. P2 is supported by signed before/after
effect counters, the separate final R effect query, denied cap probes and
refusals with zero counter movement. P3 is supported by B's post-removal
effect or, in the controls, the authentic-holder mismatch. P4 uses signed
O revocation evidence, status/expiry and measured refusal time. P5/P6 use the
fresh verifier's signature checks and independent decision reconstruction.

For P5/P6, **the common O-certified R audit signer is extra apparatus in every
arm**, including the baselines. OAuth/JWT alone does not automatically create
these portable signed decision logs. Existing OpenLine successful decision
receipts were preserved as well; early OpenLine refusals were often exceptions
without a shipped signed refusal receipt, so the common audit envelope matters.
P5 is a result of the configured arm plus this disclosed audit machinery.

P6 demonstrates offline reconstruction and bounded authorization from the
presented artifacts. A fresh verifier also derives post-exit B outcomes at
their observation times without any departed service or new trust pin beyond
O. It does **not** prove that a stale offline verifier can discover an omitted,
later revocation. Fresh current status requires delivery of an unexpired signed
snapshot, or waiting for JWT expiry. The surviving runtime queries in the next
table remain necessary even though history reconstruction is offline.

## Reachability and reauthorization ledger

These are required parties, not every process that happened to be running.
An optional O process recorded revocation intent in the offline arm; R never
queried it. The original provider is only needed for A's initial work.

| Arm | Initial issuance / A start | B succession and live decision | Owner revocation and R learning | Later independent verification |
|---|---|---|---|---|
| OL_JOB / OL_BOUND | O signs exact mandate and trust pins; R installs head; A/provider authenticates | B, R, retained original grant; O's reachable standing endpoint. No A/provider, AS or other trust service | O signs linked REVOKED head; R fetches and admits it; B probes | No online party. O public pin, signed trust contract, head chain/status and R audit; Gate public keys come from O's contract |
| JWT_OFFLINE | O signs token/trust contract; R installs pins; A/provider authenticates | B, R, retained token, R clock. O and every authorization/revocation service may be unavailable | O records intent; R does not learn the event. R rejects at local JWT expiry | No online party. O pin, token, R audit and recorded observation times |
| OAUTH_EXCHANGE | O signs subject grant and AS delegation; A/provider, surviving AS issues narrowed token; R introspects | B authenticates to surviving AS; AS issues new B token; R introspects AS. O need not perform a new action | O sends authenticated revocation to AS; AS marks subject and descendants inactive; R introspects; B probes | No online party. O pin, delegation, subject grant, AS-signed B token/introspection and R audit |
| OWNER_LIST / JWT_BOUND | O signs token/trust contract; R pins; A/provider authenticates | B, R, original token, reachable O list service; no AS or departed service | O publishes sequence-2 signed list; R fetches; B probes | No online party. O pin, token, signed list, R audit |

No active recovery guardian, blockchain, DNS/PKI key discovery, model provider
or separate Wallet service was needed. O's private key is needed for issuance
and STOP, not later verification. R's pinned trust in O is an unavoidable
initial assumption for this test, not discovered from the presented grant.

In B, token exchange **is new delegated issuance/rebinding by a surviving AS**.
It is not predecessor reauthorization and not a new O authorization under the
preregistered P3 criterion. Claims requiring *no new issuer action at all*
would not be satisfied by B. In OL_JOB/A/C, B reused the original grant bytes;
fresh status assertions and R's exact-action permissions do not change that
grant. O's initially signed contract permitting B is disclosed rather than
mistaken for an unanticipated successor obtaining authority for free.

## Revocation timing

Times below are actual monotonic seconds after that arm's issuance marker.
All nanosecond UTC/monotonic values, owner revocation signature, request
boundaries and reasons are in [timing_summary.json](timing_summary.json), each
`run_001/<arm>/revocation.json`, and the signed R events. Probing interval was
100 ms; one local host supplied the shared clocks. Values are observations
from one run, not latency guarantees or statistically ranked performance.

| Arm | O revokes | Last R accepts (25 cents) | First B refuses (25 cents) | Observed lag after O revokes | Cause |
|---|---:|---:|---:|---:|---|
| OL_JOB | 1.200124 s | 1.201647 s (B) | 1.306770 s | **0.106646 s** | Next request fetches O's REVOKED head and shipped mandate resolution refuses |
| JWT_OFFLINE | 1.200142 s | 7.095236 s (B) | 7.197289 s | **5.997147 s** | Offline JWT expiry, not propagation of STOP |
| OAUTH_EXCHANGE | 1.200095 s | 1.176926 s (B) | 1.281460 s | **0.081365 s** | R's next AS introspection observes inactive descendant token |
| OWNER_LIST | 1.200090 s | 1.175752 s (B) | 1.279464 s | **0.079373 s** | R's next O-signed list contains revoked jti |
| OL_BOUND | 1.200091 s | 0.292109 s (A) | 0.771294 s | **Not measurable for B** | B already denied for subject mismatch; post-STOP original-A grant probe also denied |
| JWT_BOUND | 1.200160 s | 0.269020 s (A) | 0.773748 s | **Not measurable for B** | B already denied for holder mismatch; post-STOP A probe separately verifies revocation |

Scope/cap denials are excluded from this timing table; they happened earlier
and are not revocation observations. The bound controls receive P4 PARTIAL,
not zero latency, because there was no accepted B authority to revoke.

OL_JOB event index 6 straddled O's revocation intent: the request began before
STOP and completed approximately 1.523 ms after that intent. It used the active
standing fetched before the update. No request starting after revocation was
accepted in the online main arms. This experiment earns no instantaneous or
linearizable wall-clock STOP claim. Standing transport is the harness's
per-request fetch; it is not a new hosted OpenLine capability.

The JWT iat/exp used integer NumericDate and zero leeway. Its configured TTL
was 8 seconds, so fractional issuance time leaves slightly less than 8 seconds
of actual validity. B's observed first refusal occurred about 72.5 ms after
the absolute JWT expiration, within the 100 ms probe interval. This is bounded
offline exposure. Calling it merely PASS or FAIL would hide the mechanism.

## Baseline audit details

All signature operations use mature PyJWT/cryptography Ed25519/EdDSA, with an
algorithm allowlist, explicit token types, issuer/audience checks and required
claims. The token claims/configurations are fully preserved in each
`presentation.json` and `workers.json`. Owner roots and O-certified worker,
AS and R keys are public; no private key is in committed evidence.

A/C tokens have `iss=O`, `sub=O`, `aud=R`, `job_id=J`, `scope=refund`,
`client_id=job-client`, `max_amount_cents=100`, iat/nbf/exp/jti. This is a
standard signed-JWT application profile with RFC 9068-style claims, not a claim
of full RFC 9068 deployment conformance: fixture issuer/audience identifiers
are URNs and there is no HTTPS issuer-metadata discovery. C adds a signed,
fresh, monotonic application revocation list; its JSON list schema is not an
IETF JWT-CRL standard. JWT_BOUND adds RFC 7800 cnf.jwk and the common
receiver-authenticated worker-key proof.

B's request/response fields and authentic client assertions follow the frozen
RFC 8693 / RFC 7523 profile. It preserves O/J subject, narrows scope, adds
`act.sub` and owner-grant hash, and never extends the owner grant's expiration.
The full form exchange requests and responses survive in `workers.json` and
the authority network-call ledger. Revocation invalidates all grant descendants.
R uses an authenticated introspection client and a signed JWT response with
`token_introspection` and exact token-hash binding. Introspection/revocation
transport uses a **fixture JSON API**, rather than full RFC 7662/7009 wire
conformance; signed response semantics are RFC 9701-shaped. All HTTP is on
loopback. These are serious auditable local mechanism profiles, **not a
certified AS or standards-compliant production deployment**. They establish
the bounded behaviors here, not interoperability with a commercial OAuth AS.

Authoritative rfc-editor.org retrieval was proxy-denied (403) during inspection;
a subsequent attempted GitHub XML mirror returned 404. The standards references
and full profile are preserved for an OAuth expert's audit. No inaccessible
documentation was represented as retrieved. No check disabled TLS or signature
verification. In a real deployment, authenticated TLS and operational key
custody would be required; they are not tested by these local processes.

## Validation and reproducibility

- 15 apparatus security tests passed, including forged owner STOP, JWT header
  confusion, required claims, audience/issuer, exact expiry, scope/amount cap,
  holder proof, stale/list rollback, exchange replay, and signed introspection
  token binding. See [validation/protocol-tests.log](validation/protocol-tests.log).
- 6 post-run evidence-integrity controls detected corrupted R signatures,
  owner contract/grant/revocation, effect query and deleted events. See
  [evidence-integrity.json](evidence-integrity.json).
- Repository discovery ran 379 tests: **355 passed, 24 optional integrations
  skipped**, no failures. See [validation/repository-tests.log](validation/repository-tests.log).
- All 107 R decisions reconstructed with matching counters; all required arms
  ran. No zero-test run was used as readiness evidence.
- Exact executed commands and working directories are in
  [commands.json](commands.json); runtime and subprocess implementation are
  in `run.py`, `service.py`, `worker.py`. Reproduction creates a new directory,
  random keys and live timings; it should reproduce properties, not token bytes
  or exact latency values.
- [ARTIFACT_MANIFEST.json](ARTIFACT_MANIFEST.json) seals the configuration,
  source, evidence, tests and report with SHA-256. Verify it with
  `.venv/bin/python experiments/baseline-exit-001/audit_evidence.py check`.

The receiver statuses, grants, trust certificates, revocation events, exchange
tokens/assertions, request timestamps, effect counters, public OpenLine logs
and per-arm service stderr are preserved under `run_001/`. Keys were randomly
generated and passed via process stdin; temporary private files were removed.
This does not claim guaranteed memory zeroization or security between hostile
processes sharing one OS user. The job and worker authorization tokens expired
before branch publication; signed audit envelopes remain verification material.
There are no real provider credentials or real payments.

## Claims falsified

1. **OpenLine-specific machinery is necessary for these six portable-authority
   observables.** OWNER_LIST reproduces all six primary outcomes using owner
   JWT/list signatures, receiver checks and the common signed audit apparatus.
2. **These outcomes distinguish OpenLine from a well-configured delegated OAuth
   design.** The surviving-AS exchange arm also matches them; the AS dependency
   and new delegated issuance are explicit rather than concealed.
3. **A's holder-bound authority automatically passes to unrelated B without a
   new binding or owner action in the shipped OpenLine path.** OL_BOUND fails
   P3, just as JWT_BOUND does. PLATFORM-EXIT-KILL-002's new M_B remains a new
   owner authorization and supplies no evidence for this stronger assertion.
4. **An offline unexpired JWT immediately reflects owner revocation intent.**
   It demonstrably does not; roughly 6 seconds of continued acceptance occurred.

These are overbroad proposed claims tested here, not assertions that every
one was previously advertised. Prior frozen evidence is left intact.

## Claims supported

- With an owner-rooted, independently retained job grant and a preauthorized
  replacement worker, current OpenLine can execute J after A's permanent local
  removal, without a new owner grant, then refuse after receiving owner STOP.
- Receiver checks, cryptographic owner traceability, bounded revocation and
  signed portable history can be composed with ordinary JOSE-based designs.
- Surviving-AS token exchange allows B continuation without predecessor or
  new-owner authorization, at the cost of a new AS issuance and live AS checks.
- Holder restriction and freshness policy predict the observed difference.
  Offline expiry trades revocation immediacy for fewer live dependencies.

## Claims still unresolved

Real commercial-provider/account deletion; unanticipated new workers; a grant
whose ultimate trust root is a departed non-owner provider; secure recovery
after loss of all retained artifacts; separate production Wallet interoperability;
hostile OS/process isolation; root compromise/recovery; outage/partition behavior
and distributed freshness; production OAuth interoperability/conformance;
clock attacks; revocation-latency distributions or performance ranking;
aggregate budgets or actual refund idempotency (the frozen ceiling is per action);
and whether other, untested OpenLine properties justify additional machinery.
This experiment is not a proof of universal minimality of any design.

## Exact OpenLine claim earned

> In this local fixture, a preauthorized replacement worker continued the same
> independently retained owner-authorized job through current OpenLine after
> its predecessor's permanent removal, without a new owner grant. The receiver
> refused subsequent requests after fetching owner revocation; the first
> observed refusal was 106.6 ms after revocation intent. Presented owner-rooted
> artifacts and common signed audit evidence allowed offline reconstruction.
> The JWT/list and surviving-AS baselines reproduced these observable properties;
> no exclusive OpenLine advantage was established.

No new feature is recommended from this comparison. The experiment stops at
the frozen comparison, evidence preservation and branch push. No merge,
flagship video or production work is part of the result.
