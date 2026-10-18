# HOME-GUARD-004 — Operational cost report (DRAFT, pending CI evidence)

**Branch:** `study/home-guard-004-reproducer-costs`
**Frozen base:** `44486057320e908ec091c327112d830f65e20caa` (PR #113 candidate)
**Method:** costs measured from CI run instrumentation (`cost-timeline.jsonl`,
`revocation-timings.json`), not estimated.

## 1. Cold first setup

| Item | Measured |
|---|---|
| Elapsed wall time (namespace creation → first policy applied) | TBD from `cost-timeline.jsonl` |
| Manual steps | TBD (count of operator commands) |

## 2. Marginal onboarding (per additional device)

| Item | Measured |
|---|---|
| Policy generation + signing (`make_policies.py`) | TBD |
| Policy apply: verify → kernel install → receipt | TBD |
| 2nd device | TBD — topology has 2 pairs; marginal unit = one policy-update cycle |
| 5th device | **NOT SUPPORTED without redesign** — policy schema fixes exactly two device pairs (`tv_to_nvr_tcp_8080`, `thermostat_to_hvac_tcp_9000`); `policy_gate.py` rejects any other scope. Adding a 3rd+ device requires a schema change. |

## 3. Revocation timeline (monotonic, microseconds)

| Phase | Measured |
|---|---|
| Submission → signature validated | TBD from `revocation-timings.json` |
| Validation → kernel rules applied | TBD |
| conntrack eviction (inside kernel apply) | TBD + exit code |
| Kernel applied → signed receipt issued | TBD |
| Submission → first confirmed blocked observation | TBD (barrier → probe) |

## 4. Recovery and verification

| Item | Measured |
|---|---|
| `verify_evidence.py` wall time | TBD from `cost-timeline.jsonl` |
| Steps to diagnose + restore | TBD |

## Environment blockers (local VM)

The leased VM cannot run the kernel experiment: no conntrack kernel module
(stateless matches only), no `conntrack` tool, no `tcpdump`, no host
`CAP_SYS_ADMIN` for named namespaces. PR #122 recorded the same. All
kernel evidence below comes from the GitHub Actions disposable runner
(ubuntu-latest, conntrack present), consistent with PR #113.
