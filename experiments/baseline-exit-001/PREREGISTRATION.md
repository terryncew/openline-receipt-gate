# BASELINE-EXIT-001 — frozen scientific contract

Purpose: identify necessary machinery for portable authority succession, not
demonstrate architecture superiority. No arm has been executed when this file
is committed. Production OpenLine, historical experiments, film and production
assets remain untouched. The commit containing this file is the preregistration
SHA; its SHA-256 is recorded before implementation. Implementation and evidence
are later commits. No tuning of this contract after contact.

## Inspected baseline

Initial branch `work`, HEAD `abc610be560284130e0d08b2fd51e59ef0b1c623`.
Dedicated branch: `experiment/baseline-exit-001`.
Existing untracked refund-demo state is preserved and excluded from commits.

Inspected: `olp_gate/{mandate,mandate_owner,subject_bound_commit,stop_standing,
tool_adapter,mandate_gate,verified_commit,crypto}.py`, owner/authority/commit
documentation and tests, Wallet standing 001–004, owner-control-002 and
platform-exit-kill-001/002. Wallet 001 binds a subject key and explicitly bounds
offline freshness; Wallet 002–004 concern root recovery and delivery, not
automatic substitution of a worker's identity. PLATFORM-EXIT-KILL-002 succeeds
after O issues M_B at succession. Its result is not evidence of continuation
without a new owner authorization. Wallet kernels are in this checkout; the
separate production Wallet repository is not selected or silently imported.

## Scenario and matched initial conditions

O signs authority for job J: perform a simulated 25-cent refund at R, with a
100-cent ceiling, exact J, audience R and purpose. A begins successfully. At
approximately 0.4 seconds after that acceptance, A's entire worker/provider
process is terminated and reaped, its unique working directory is removed, and
its private key reference is discarded. This is permanent removal for the run:
no restart, fallback, query, authority migration or A callback. A's provider is
the actual local subprocess; no commercial cloud exit is claimed. B starts only
after removal, has a distinct fresh key, and has never communicated with A.
B gets only a presentation package retained by O outside A, plus B's private
authentication key. No A private key or A-only mutable state crosses the exit.
An append-only receiver effect counter/checkpoint for J remains at R. B must
continue the same counter. No new O authorization is issued at succession.

Primary arms use job authority, intentionally independent of A's identity:
OpenLine's mandate agent_id is the stable job agent J; JWT subject is O with a
job_id claim J. The credentials are bearer-like with respect to worker choice.
O permits both A and B at initial issuance; R pins their request-authentication
keys in the same initial owner-signed experiment contract. Worker authentication
is distinct from job authority and never silently treated as a transfer from
A. Independent retention of the grant is a real necessary assumption, allowed
to every arm. It is not a recovered A-bound credential.

A paired control changes only initial holder binding: the OpenLine mandate's
agent_id is A and its shipped subject gate receives the receiver-authenticated
worker identity; the JWT grant has RFC 7800 cnf.jwk bound to A and R checks the
same authenticated worker key. Both must attempt B without rebinding or rescue.
This controls against interpreting bearer portability as authenticated
succession of an A-only grant.

After B's first attempt, O revokes at approximately 1.2 seconds after initial
issuance (actual time is measured, not assumed). B attempts every 100 ms until
the first rejection, and makes a second post-rejection attempt. The deadline
is 12 seconds after issuance. All timers use actual UTC and monotonic clocks;
NumericDate expiry is integer UTC with zero leeway. No fake clock, clock patch,
or changed token expiration. Arm A TTL is 8 seconds from integer iat; other
job grants last 60 seconds. Standings/status snapshots last 1 second. A request
spanning revocation is separately labeled; last accepted and first refused
receiver decisions are recorded along with request boundaries. Timing tolerance
for the bounded fast lanes is 1 second; polling accounts for detection resolution.

## Arms and services removed/retained

1. **OL_JOB**: current `authorize_owned` + `LocalAuthorityRuntime`, real
   Authority Compiler/Gate/Verified Commit, `MandateOwnerView` admitting O's
   ACTIVE and linked REVOKED records. Receiver fetches O's standing snapshot
   before each attempt; O signs a fresh snapshot of the unchanged head on
   demand. Admission uses the existing successor rules. No new product API or
   authority engine. Job identity is stable; A/B are distinct transport actors.
2. **JWT_OFFLINE (A)**: RFC 7519 / RFC 9068-style scoped access JWT, EdDSA,
   owner issuer, pinned key/iss/aud/typ, required iat/nbf/exp/jti/sub/client_id,
   job and refund scope, 8-second TTL, no refresh/revocation query. Receiver
   verifies signature/claims/scope/amount locally. Explicit bearer design.
3. **OAUTH_EXCHANGE (B)**: RFC 8693 token endpoint; owner-signed JWT subject
   token, `subject_token_type=urn:ietf:params:oauth:token-type:jwt`,
   `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, requested
   access-token type, audience R, refund scope; client authenticated by a
   one-use asymmetric RFC 7523 private_key_jwt assertion. The surviving AS
   narrows scope, preserves O/J subject, records act.sub A/B and owner grant
   hash, returns access_token, issued_token_type, token_type and expires_in.
   O's initial signed trust contract delegates this job to that AS key.
   Each worker exchanges at startup; B's exchange is explicitly new delegated
   issuance/rebinding by a surviving AS, not an action by O or departed A.
   R obtains signed JWT introspection (RFC 7662 / RFC 9701-shaped) on each
   attempt, binding the exact access-token hash, active, exp, O/J and 1-second
   freshness. O revokes the subject grant at AS; AS invalidates all descendant
   tokens. AS is common owner-controlled infrastructure independent of A,
   survives exit, and is fully counted rather than penalized for being online.
4. **OWNER_LIST (C)**: O's 60-second scoped signed JWT with an O-signed complete
   job revocation list (jti, sequence, iat, exp, revoked identifiers). Receiver
   fetches on every attempt, validates signature/audience/freshness, maintains
   monotonic sequence, rejects listed grants, and fails closed on unavailable
   or expired status. This is a standards-plausible signed-list application
   profile using JOSE, not a claim of a standardized JWT CRL format.
5. **OL_BOUND**: OL_JOB with shipped `authorize_subject_bound_owned` and initial
   mandate agent_id A. No new subject mapping from B to A.
6. **JWT_BOUND**: OWNER_LIST with initial RFC 7800 cnf.jwk for A. Distinct B key
   cannot satisfy the binding. Same successful A start and O revocation run.

All remove A and Provider A permanently. No unique non-owner authority service
at Provider A remains. O, R and the independent artifact store survive every
arm. Only arm B additionally retains a non-owner delegated AS/status service.
Worker keys never sign consequential job grants. Trust contract and common
audit envelopes are apparatus for all arms, never an OpenLine improvement.

## Six observable criteria (no aggregate winner)

| Property | PASS | PARTIAL | FAIL |
|---|---|---|---|
| P1 owner-originated authority | Fresh verifier verifies O signature on exact J/scope and all delegated issuer pins back to O | Authority only attributable to intermediary with non-cryptographic owner consent | Only A or untrusted issuer authorizes |
| P2 receiver enforcement | R executes allowed exact effect and counter does not move on denied/mutated/out-of-scope attempts | Only acceptance path demonstrated or effect absence not independently checked | Denied request effects, or worker alone decides |
| P3 succession without predecessor reauthorization | B executes same J after permanent exit with no departed party or new O authorization; new issuance by surviving AS disclosed | Works only after new O authorization (no rescue will be performed) | B cannot execute the original grant without changing binding/authority, or departed dependency remains |
| P4 owner revocation | B was accepted; O-authenticated revocation leads to rejection within 1 second and stays rejected | B accepted, but refusal waits for expiry or exceeds 1 second within declared bound; OR B already refused for independent holder mismatch, so B revocation not discriminated | Continues past declared expiry/freshness+poll tolerance, wrong-owner revocation works, or no refusal before deadline |
| P5 portable history | Offline fresh verifier checks signed decision evidence, exact authority, status/expiry and effect checkpoint and independently reproduces an earlier ACCEPT and later REFUSE | Signed tokens authentic but necessary decision/status evidence absent | Only mutable prose/unverifiable claims or reconstruction disagreement |
| P6 post-exit independent verification | Fresh uninvolved verifier, with only O's initial public pin and presented signed artifacts, reproduces post-exit authorization/refusal with no departed query or extra non-owner trust pin | Authentic history but new trust pin or surviving external query necessary for the tested verification | Departed service or its unsupported trust assertion necessary |

INCONCLUSIVE replaces a property result if apparatus failure, absent necessary
observation or ambiguous trace prevents grading. A known holder-binding denial
is a P3 FAIL, not apparatus failure. P4 in bound controls is PARTIAL because B
is already refused; measure A's post-STOP refusal in a non-executing verifier
probe separately, without resurrecting the removed A process. For P5/P6,
verification of earlier signed snapshots at their recorded observation time is
historical verification. It cannot establish absence of a later undisclosed
revocation. Fresh offline current evaluation is only valid within presented
status expiry (or arm A token TTL). That freshness limit must accompany PASS.

Operational provider dependence means a required network query to, secret/key
issued after exit by, or externally pinned trust in a non-owner authority
service unique to the departed A relationship. Owner-certified delegated keys
in a portable contract are not a hidden external pin. Online freshness at
surviving owner/AS services is separately recorded, including outages; offline
history reconstruction does not erase those runtime dependencies.

Reauthorization means issuance/rebinding/narrowing of a new consequential
grant or token, not authentication of a request, a fresh status assertion about
an unchanged grant, or a receiver-created exact one-use decision. Record at
succession: new O action, departed action, surviving issuer action, and token
bytes reused/new. Preauthorization of B at issuance is stated explicitly.

## Dependency ledger (required reachability, not just processes present)

| Arm | Initial issuance | Succession/live R check | O revocation | Later offline verification |
|---|---|---|---|---|
| OL_JOB / OL_BOUND | O signs; R installs owner pin/admitted head; A authenticates | B, R, O status endpoint, retained grant; no A/provider | O signs REVOKED successor, R fetches/admit; B probes | O public pin + portable trust contract/head chain/status/audit; no live party |
| JWT_OFFLINE | O signs; R installs pin; A authenticates | B, R, retained token; O not required | O records intent; R learns only token expiry on local clock | O public pin + token/audit/clock evidence; no live party |
| OAUTH_EXCHANGE | O signs/delegates AS; AS exchanges; A and R with AS status | B, R, AS issuance/introspection, retained subject grant; no new O action | O signs revocation request; AS records; R introspects | O public pin + delegation/subject/access JWT/signed introspection/audit; no live party |
| OWNER_LIST / JWT_BOUND | O signs; R pins; A authenticates | B, R, O list endpoint, retained token; no new O grant | O publishes signed list; R fetches; B probes | O public pin + token/list/audit; no live party |

Original provider and A are absent at succession/revocation/verification for
all. Status issuer in OpenLine/C is O; issuer/introspection in B is surviving
AS. R's signing key is O-certified at setup, only for common audit records.
No blockchain, DNS/PKI lookup, model provider, recovery guardian or independent
wallet service is necessary for these local fixtures.

## Implementation, safety, evidence and falsifiers

Use PyJWT 2.15.1 with cryptography 50.0.2 for JOSE signing and claim validation;
current OpenLine Ed25519 implementation is unchanged. Python 3.12.14 is the
runtime. stdlib HTTP/subprocess for isolated local services. Exchange and list
endpoints are auditable experiment profiles, not certified OAuth products.
No homemade JWT signature codec. Algorithm allowlists, required claims,
audience, issuer, type, expiry, scope, holder binding, assertion replay and
scope-escalation rejection are verified. TLS is not disabled: HTTP is used only
on loopback for local fixture transport, never claimed suitable for deployment.
Public standards URLs: RFC 7519, 8725, 9068, 8693, 7523, 7662, 9701, 7800.
The cloud proxy blocks rfc-editor.org during inspection; preserve this access
limitation and the exact implemented protocol profile for external audit.

Private keys are random, ephemeral, kept outside committed evidence, never
printed or committed. JWTs authorize only local fake effects and expire in
seconds. Commit public keys, tokens, grants, signed statuses, signed receiver
events, decisions, event timestamps, effect counters, network-call ledger,
commands, library versions, preregistration/implementation SHAs, verifier
outputs, meaningful security-test output and SHA-256 manifests. R audit events
are JOSE envelopes common to every arm; P5 includes this extra audit machinery
explicitly. Existing OpenLine signed receipts are preserved too. Refusal
evidence must identify expiry, revocation or holder mismatch distinctly.

Receiver, owner/AS service, A and B run as separate processes; independent
verification is another fresh process after service shutdown, consuming only
evidence and O public trust pin. B cannot access A files. Services bind loopback
ephemeral ports. Receiver effects are local simulation only. Record request
start/end, receiver decision time, monotonic and UTC O revoke time, last R
ACCEPT, first R REFUSE, propagation lag, sample interval and reason. At least
one pre-revocation B attempt plus both post-refusal probes in primary arms.
Keep already-denied controls separate from revocation latency.

Security controls include tampered signature, wrong issuer/audience, expired
token/status, missing required claims, scope escalation, wrong holder, client
assertion replay and stale/rollback list. No changed expectations, passing
substitutes or disabled assertions. Unexplained failures are INCONCLUSIVE.
Apparatus repairs may fix transport/serialization only, with failed output
retained and disclosure; shipped defects causing total inability to run stop
the affected arm and are classified without repair. No production changes.

After all runnable arms, publish a property-by-property comparison and dependency
ledger with revocation lag, falsified/supported/unresolved claims and the
narrowest earned OpenLine claim, including explicit lack of superiority if
baselines reproduce it. If no distinguishing property is observed, superiority
is INCONCLUSIVE rather than manufactured. Freeze evidence, commit and push the
experiment branch; no merge or flagship work.
