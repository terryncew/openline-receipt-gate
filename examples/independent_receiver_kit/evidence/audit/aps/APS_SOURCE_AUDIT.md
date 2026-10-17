# APS source audit — OPENLINE-INDEPENDENT-RECEIVER-001

This is a documentation/source-only comparison. No APS runtime was installed or executed, and no matched APS correctness, setup-time, performance, or maintenance result is claimed.

## Identification and immutable reference

APS here is **Agent Passport System**. Identification is supported by maintainer aeoess's public profile linking the protocol repository and agent-passport.org, by the repository README naming Agent Passport System, and by independent AgentID interop documentation calling APS authorization and naming contributor @aeoess. Receipt Gate itself had no `APS`, `Agent Permission`, or `Agent Policy` references when searched. The mission supplied no APS URL; this identification is the best supported interpretation, not an assertion that every acronym APS denotes this project.

- Maintainer identity: https://github.com/aeoess/aeoess
- Authoritative repository: https://github.com/agent-passport-system/agent-passport-system (old https://github.com/aeoess/agent-passport-system redirects here).
- Site: https://agent-passport.org
- Audited revision: `bbd5a7d4cd77b5068b1023ccd418682ba8924109`, commit timestamp 2026-10-15T15:59:06Z, package.json version 8.0.1.
- Retrieval: 2026-10-17T18:48:31Z onward via GitHub HTTPS API and raw.githubusercontent.com, with normal TLS verification. `commit.json`, `tree.json`, `retrieval-metadata.json`, `sources.json`, and retrieved files preserve exact sources and SHA-256 hashes.

All source paths below refer to https://github.com/agent-passport-system/agent-passport-system/blob/bbd5a7d4cd77b5068b1023ccd418682ba8924109/ plus the path.

## Supported overlap

| Receiver requirement | APS source evidence | Scope of conclusion |
| --- | --- | --- |
| Receiver selects trusted external principal | `src/v2/authority-delegation/verify.ts` lines 214–229 requires `trustRoot`; missing/undecidable trust is indeterminate, rejection is invalid. `src/v2/trust-policy/types.ts` defines issuer pinning, offline `cached_pins_only`, signed policy, minimum-version anti-rollback. | Trust is receiver-derived, not established merely by an artifact's key. |
| Cryptographic delegation and narrowing | `src/v2/authority-delegation/verify.ts` checks signatures/content identifiers, parent linkage, issuer/subject continuity, seven facet attenuation checks, issuance windows. | Delegation verifier, not a complete receiving API or business operation. |
| Expiry and accepted revocation | Same verifier lines 267–289 checks every member's current time and revocation; unknown status is indeterminate. `src/v2/authority-revocation/resolver.ts` requires verified revocation and distinguishes tracked active from unknown. | Resolver-supplied state needs independent currency and custody policy. Absence alone does not establish active authority. |
| Caller proof, action/evidence linkage, signed receipts | README describes signed agent intent, policy evaluation and execution records; `THREAT_MODEL.md` requires principal/policy/budget/replay context checks; `docs/verification-boundary.md` distinguishes authority-aware APIs from integrity-only APIs. | These are documented interfaces/requirements, not an executed end-to-end result here. |
| Offline evidence | README describes JCS/Ed25519 receipt bundles; `interop/oauth-liu-composition/README.md` documents standalone Node verification with fixed public test keys and digest-linked inputs. | Signed declarations and integrity are verifiable; truth of an external effect is not established by the signature. |
| Durable replay/revocation/state | `src/v2/authority-revocation/types.ts` explicitly says the store interface promises no durability, requires atomic first-write for durable stores, and says no gateway implementation lives here. | Must be provided and validated by the receiving integration. |

The draft-native `AuthorityDelegationV1` and older `Delegation` APIs are explicitly different: the README deprecates/freezes the older compatibility API and warns its prefix scope semantics differ from the current draft. A comparison must not silently substitute the easier legacy API and claim current-draft equivalence.

## Why APS was not run as the matched third implementation

The pinned `src/core/gateway.ts` exports a `ProxyGateway` constructor that throws because the implementation moved to `@aeoess/gateway`. `MIGRATION.md` lines 124–140 describes the reference gateway as a private product; lines 479–490 say the runtime moved while public interface types remain. The new revocation-store interface also explicitly disclaims durability.

The public SDK contains useful verifiers and standalone vectors, so absence of the reference runtime does **not** prove APS cannot support an independently implemented receiver. It means running a few signature fixtures would not be the matched protected-state/revocation/persistence experiment requested here. Building another APS receiver, choosing between legacy and draft-native paths, and implementing its durable store would add substantial unmatched integration work. Under the mission's minimal-kit scope, the defensible result is documentation/source-only, with no runtime ranking. No proprietary gateway, account, paid service, or production system was accessed.

## Conventional authorization: equivalent controls and actual costs

A competent conventional receiver can accept externally issued JWS/JWT credentials using receiver-pinned issuer keys, `iss`, `sub`, `aud`, `exp`, `nbf`, and `jti`; require proof from the authenticated subject key; and bind a custom exact-action digest and policy/version claims. It can accept issuer-signed revocation/history material under receiver freshness rules, enforce durable replay constraints, mutate protected local state and append a signed audit record within its own SQLite transaction. Provider labels are irrelevant to the cryptographic identity in both designs.

JWT is a credential representation, not the complete security system. It does not itself deliver live revocation, prove caller possession, establish issuer trust, impose exact application-action semantics, persist replay state, guard a database write, or make a signed audit statement true. Those mechanisms must be implemented in the conventional baseline and given the same trust inputs, current-history availability, clock, local-state custody, and failure behavior as OpenLine. This baseline is permitted to use custom application claims and signed audit evidence; disallowing them would manufacture a disadvantage.

OAuth introspection can deliver current state while connected; offline credentials/snapshots need a bounded freshness window or must deny when currency cannot be established. The same information limit applies to APS and OpenLine: none can observe an undisclosed revocation while fully offline.

Standards references for the conventional design:

- RFC 7519 §4.1.1–4.1.7: issuer, subject, audience, expiry, not-before, issued-at, JWT ID. https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1
- RFC 8725 §3.1, §3.8, §3.9, §3.11–3.12: algorithm restrictions, issuer/subject/audience validation, explicit token typing and separate validation rules. https://www.rfc-editor.org/rfc/rfc8725.html#section-3
- RFC 9068 §2.2 and §4: JWT access-token claims and resource-server validation; application policy remains necessary. https://www.rfc-editor.org/rfc/rfc9068.html#section-4
- RFC 7662 §2.2: token introspection response and active status. https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2
- RFC 9449: DPoP is a conventional sender-constraining option; a kit's signed exact-action challenge is not automatically a conformant DPoP implementation. https://www.rfc-editor.org/rfc/rfc9449.html

Retrieval limitation: requests to rfc-editor.org and ietf.org/datatracker were denied by the environment proxy (HTTP CONNECT 403); these standards citations identify stable published requirements, and are **not claimed as freshly retrieved source artifacts**. No TLS verification was disabled and no domain restriction was bypassed.

## Differentiation finding and falsifiers

Portable issuer authority, provider-independent subjects, revocation-aware receiver policy, and signed portable evidence overlap both APS and a competent conventional implementation. APS additionally defines delegation-chain/narrowing and typed receipt vocabulary. Those capabilities are not unique differentiators for OpenLine on the basis of the examined sources.

OpenLine may offer reusable signing, validation, history and receipt integration for a receiver already using its format. Whether that saves implementation and maintenance work is an empirical kit result, not established by APS's larger advertised feature set or by this source inspection. No material OpenLine advantage over APS was demonstrated. Do not infer APS inferiority from the missing public reference gateway or infer parity from docs alone.

Remaining falsifiers: a matched self-hostable APS receiver may need fewer steps or provide stronger typed delegation evidence; a conventional integration may be smaller; unpublished revocation or stale local history may allow actions inside the freshness interval; anyone controlling receiver code, database, clock or signing keys can invalidate the threat assumptions; a signed receipt need not prove the claimed effect; worker succession and independent organizational adoption must be tested separately.
