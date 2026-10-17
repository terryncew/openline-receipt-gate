# OPENLINE-INDEPENDENT-RECEIVER-001 result

**Verdict: PARITY, bounded to this local reference integration.** No material
OpenLine adoption, cost or capability advantage over the competent conventional
implementation was demonstrated. This is not independent organizational adoption.
Stop condition reached: the minimum comparison and adversarial verification pass;
no follow-on product feature is added.

Base main: `81db6acb72149df989aac1827e5f621b0873d57b`.
Source audit was recorded in commit `56fc1980ce999cbd9ffc1ecffbccea7ae108ab96` before kit implementation; use
`git log --oneline -- examples/independent_receiver_kit/SOURCE_AUDIT.md` for its exact
history. Tested implementation: `09b821da175f8dd3dbe2b0bcaf051b1fa0b840d3`.
Branch: `study/independent-receiver-kit-001`. Final evidence/documentation commits
retain identical tested implementation files; delivery SHA/PR is reported separately.

## What ran

One real loopback HTTP API, configured entirely by a simulated receiving lab,
performs a fixed local SQLite document-intake insert. It accepts externally signed
owner authority on `/authority`, and independently authenticates worker possession
of the owner-bound key on `/submit`. Public fixture issuers and clients run outside
the receiver process; the receiver receives no issuer or worker private-key files.
The native owner records are unchanged `openline.mandate_owner_authorization.v1`
plus `principal_mandate/v1`, issued through the existing Receipt Gate implementation.
Native `validate_mandate_authorization`, `MandateSpec`, `assess_effect` and OLP crypto
are reused. The receiver pins the owner ID/key/slot, receiver ID/key and policy.

The worker signs the entire exact effect/document, receiver audience, subject,
policy hash, head hash, issue/expiry and nonce. The owner-signed subject is the
worker public key. A matching caller string, provider label or valid untrusted
signature alone cannot authorize. The local worker-envelope and decision schemas
are integration glue, not a new standardized protocol or core feature. This kit
is not a new Verified Commit primitive; existing core files are unchanged.

The receiver persists current owner heads, monotonic sequence/predecessor history,
replay state and signed decisions without any provider/hosted service. It reads
that history in the same `BEGIN IMMEDIATE` transaction as current policy, proof
validation, unique nonce/proof consumption and the fixed document insert. There is
no arbitrary executor. The response is signed and stored before the local commit;
no protected effect occurs on denial. Lost responses may be recovered by verifying
the saved DB; replayed requests are denied rather than executing again.

Each demo mode uses three fresh receiving processes over retained state:
A admitted and acts; owner revocation accepted; A denied; successor B admitted and
acts; A remains denied. Provider A/B are deterministic labels, not authenticated
commercial model hosts. Two documents, three owner-head rows, seven signed
decisions and two consumed nonces remain per mode.

## Actual timing and adoption friction

Measured by `clean_install.py` using committed source exported with `git archive`,
a brand-new venv, isolated package paths/user-site disabled and pip download cache
disabled. Existing host Linux x86_64/glibc2.41, Python 3.12.14. Installed cryptography
50.0.0, PyJWT 2.10.1, cffi 2.1.1 and pycparser 3.11. Exact commands, stage monotonic
timings, archive hash and package inventory: `evidence/clean_run/summary.json` and
`versions.json`. The source archive SHA-256 is
`b32d5472f4ae32a8db3d825929e34032282c2abf33b88dc681af7ee91a71931c`.

| Stage | Observed seconds |
|---|---:|
| Source archive and extraction | 0.39 from start |
| Fresh venv/ensurepip | 2.42 |
| Dependency installation | 6.60 |
| Both-mode demo and independent verification | 3.06 |
| First successful end-to-end run from start | **12.62** |
| Additional 32-test suite | 10.66 |
| Entire clean run | **23.28** |

This meets the internal under-10-minute target on this host. Clone/network transfer
time is excluded: source was exported from local Git. It is not a fresh operating
system, uncached package-registry service, external cold developer or independent
organization test. Both modes share the same two pinned direct requirements and
editable Receipt Gate install in this kit. Fresh developer commands are in README.

Per-mode complete demo: native 1.33 s, conventional 1.13 s; process startup ranges
were approximately 0.17–0.35 s. Single-run timings are observations, not a controlled
performance advantage. Both have the same startup, config, key, state, requests,
verification and administration steps. Production issuer enrollment, real identity,
TLS, key custody and revocation delivery integration time were not measured.

## Tests and preserved negative results

**32/32 adversarial HTTP-boundary tests passed**, zero failed/skipped. Sixteen cases
ran for each mode. Every test inspects actual SQLite documents/history/consumption
and invokes the separate verifier process against saved evidence. Thirty snapshots
are valid; two deliberately privileged-write snapshots are correctly rejected.
`evidence/clean_run/tests.log` and per-test `rows.json`/`verifier.json` preserve the
raw results. The earlier source-host 32-test pass is retained separately.

| Cases in each mode | Protected result |
|---|---|
| External owner, A → revoked → B succession, retained history/restart | exactly two approved documents; old A denied |
| Forged worker/owner signatures | zero document effects |
| Unknown principal | zero effects, no admitted history |
| Wrong subject/audience | zero effects |
| Changed target, oversized or signature-tampered document | zero effects |
| Expired call | zero effects |
| Known revocation + attempted old-head reinstall | zero effects, frontier retained |
| Missing/stale history | zero effects |
| Replay and four concurrent identical HTTP calls | exactly one document |
| Receiver policy changed | zero effects |
| Unauthorized B or missing successor history | zero effects |
| Raw-write/admin HTTP route bypass | zero effects |
| Nonzero value, mismatched record ID, extra caller identity | zero effects |
| Duplicate old history/freshness boundary | no renewed standing |
| Privileged direct SQLite write | **bypass succeeds outside HTTP guard; verifier rejects unmatched state** |

The last case is a deliberately preserved negative result, not a claim that this
HTTP adapter prevents local filesystem/database administration. Database writer
access and receiver process/config/key integrity remain trusted.

Independent verifier review additionally rejected ten mutations across both modes:
changed documents, removed nonce consumption, changed history admission timestamps,
forged decision body, and correctly receiver-signed outcomes with expired effect
times. Two separate clean CLI checks passed. Raw audit logs/script are under
`evidence/verifier_checks/`; the archived original audit script records its original
host paths, while the supported portable CLI is `python -m ...verify` in README.
The verifier does not import Receiver/dispatch; it independently replays successful
checks using shared cryptographic codecs and compares durable rows. Denial reasons
are signed receiver testimony, not independently proven exhaustive reasoning.

Existing regression tests: **12 Verified Commit + 8 subject-bound + 7 owner-control
= 27 passed**. No existing core source, tests, project dependency declaration or lockfile was changed.
No PR #119/#120 code is imported. All costs were local package/Git reads and CPU;
no paid model APIs, real customers, devices, money, release or external deployment.

## Fair conventional comparison

The conventional arm is normal EdDSA compact JWT using PyJWT, with pinned issuer
keys, strict issuer/audience/algorithm, subject-bound worker proof, iat/nbf/exp/jti,
exact effect/document claims, and the same signed lifecycle sequence, revocation,
current receiver policy, 60-second freshness and SQL replay constraints. JWT does
not itself provide these application controls; the receiver provides them equally.
This is an offline signed JWT fixture experiment, not a deployed OAuth issuer or
claim of DPoP-profile conformance. Both may use signed audit evidence.

| Dimension | Matched result |
|---|---|
| Correctness | equivalent 16-case results per mode |
| Dependencies/integration | same install/start/run/verify workflow and two direct packages in bundled kit |
| Trust configuration | same five public identity/root fields, same five policy fields, receiver signing key and retained SQLite state |
| Revocation | same signed local admission order; unknown remote revocation bounded by same freshness ceiling |
| Provider succession | same owner-controlled A-to-B transition, no provider contact |
| Verification portability | same signed decision schema, snapshot replay and external root trust |
| Maintenance | shared 170-line receiver, 258-line verifier and 312-line combined codec; each format needs issuer/call mappings and scope rules |

Counts include comments/docstrings and are descriptive, not a complexity score.
The conventional baseline shares application data shapes and audit helpers to hold
policy/effect semantics constant; it is not a separately developed enterprise
OAuth deployment. Native OpenLine reuses typed mandate/lifecycle validators, while
JWT reuses a standard library and needs application claims. Neither format removes
receiver integration, trust onboarding or revocation-delivery work. No practical
material advantage was measured; convenience of existing validators is not proof
of ecosystem/adoption superiority.

## Wallet and APS source findings

Wallet was audited read-only at `f309aac8aecae36c4f354c7455281af6dbce486a`. Its actual
init/grant/export/verify CLI produced `EVIDENCE_VALID`, policy authority `NONE`, and
decision authority `RECEIVER_GATE`. Receipt Gate verifies its signature, but its
native owner validator rejects the export with `mandate_authorization_shape_invalid`.
Wallet's exported `openline.wallet.receiver_bundle.v1` subject/scopes/timeline is
not native principal mandate authorization. The original signed export, exact raw
CLI output, source references and negative compatibility check are preserved under
`evidence/audit/wallet/`. This kit does **not** import Wallet bundles unchanged or
manufacture owner authority with a receiver key. Wallet interoperability remains
an explicit integration gap, not a feature quietly added here.

APS is Agent Passport System, pinned source
`bbd5a7d4cd77b5068b1023ccd418682ba8924109` (SDK 8.0.1), official repo
https://github.com/agent-passport-system/agent-passport-system . Source overlaps
trusted-root policy, delegation narrowing, expiry, revocation-aware verification
and typed signed evidence. Missing revocation knowledge can be indeterminate;
its store interfaces do not promise durability. Legacy Delegation and the draft
AuthorityDelegationV1 are distinct. Public ProxyGateway currently throws a
migration error; MIGRATION.md identifies the relocated runtime as a private
product. A matched runtime receiving operation was therefore not established.

**APS comparison is documentation/source-only**, with no runtime winner claimed.
Report, exact source hashes/URLs, commit metadata and retrieval failures are under
`evidence/audit/aps/`. Relevant JWT/OAuth RFC references are cited there; direct IETF
retrieval was blocked and is not represented as freshly read source evidence.
None of delegation, provider independence, signature verification or signed audits
is shown to be uniquely supplied by OpenLine under the matched conditions.

Draft PR #119 at `1749a226b5f77cabc98f04a8655636229e0b11c2` and #120 at
`46d42565ac4cec6e8dbe17d5bc01b9c57e8e79c9` were inspected for context only. Their
separate code was not merged, modified, or used as a dependency. Remote metadata
is preserved in `evidence/audit/pr_context.json`.

## Limits, trust assumptions and falsifiers

- External issuer/root enrollment, secure key custody, receiver administration,
  database writes and system clock are trusted. Fixture keys are public; signatures
  demonstrate contract integrity, not independent trusted identities/certification.
- Offline latest authority is unavailable by magic: a head is current only in this
  receiver's admitted sequence and is usable for less than 60 seconds after signed
  issuance, further bounded by expiry. Withheld remote revocation can leave a
  legitimate pre-admission window. Known revocation stops new effects immediately
  in local transaction order; duplicate delivery never extends freshness.
- Missing/stale history is denied. Deleting/replacing/rolling back the DB loses
  continuity; initialization can create a fresh DB. An external checkpoint and
  stronger provisioning would be needed to detect whole-DB rollback. None is built.
- The trusted clock must not roll back or lie. Signed effect time is sampled just
  before the SQLite insert, not an atomic physical timestamp inside COMMIT.
- The transaction covers only this local fixed insert and audit. It does not cover
  external APIs/files/robots, provider execution, distributed revocation, power-cut
  durability or arbitrary system-call failures. No external consequence guarantee.
- Malformed transport may produce unsigned HTTP 400, and unsupported HTTP methods
  use stdlib behavior. Validly parsed supported requests produce signed decisions.
  Availability, hostile client exhaustion, TLS and production hardening are untested.
- Whole-history truncation and compromised receiver signing keys can defeat evidence
  without an external anchor. Independent replay shares audited codec dependencies;
  it is process-independent, not an independently developed cryptographic stack.
- A mutated protected row after DENY, accepted wrong signer/subject/audience/action,
  a known revoked worker acting after accepted revocation, old history restoring
  standing, or a duplicate protected effect falsifies the bounded result.
- This does not establish independent developer adoption. No external company or
  human was contacted, no paid API used, and no production integration was attempted.

The central answer under the tested conditions is **no demonstrated additional
capability, easier adoption, or lower cost**. Preserve the parity and Wallet gap;
stop rather than expand the product to manufacture differentiation.

The integrity seal can be checked with `python -m examples.independent_receiver_kit.seal --verify`.
Its fixture signature does not replace external trust in the receiver or source commit.
