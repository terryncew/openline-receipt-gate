# HOME-GUARD-004 — Operational cost report

**Branch:** `study/home-guard-004-reproducer-costs`
**Frozen base:** `44486057320e908ec091c327112d830f65e20caa` (PR #113 candidate)
**Evidence:** CI run 39152946810 (ubuntu-latest, disposable), artifact
`HOME-GUARD-004-measured-evidence` (30-day retention).
**Method:** all values measured from `cost-timeline.jsonl` (monotonic_ns) and
`revocation-timings.json` (monotonic_us). No estimates.

## 1. Cold first setup

| Item | Measured |
|---|---|
| Scripted setup: namespace creation → veth pairs → sysctl → policy generation → first policy applied | **1.36 s** (43803849425 → 45365771741 ns) |
| Manual operator steps | 3: (1) clone repo + checkout branch, (2) install deps (`pip install cryptography==50.0.1`; apt `iproute2 iptables conntrack tcpdump` if missing), (3) run `bash experiments/home-guard-003/run_measured.sh <evidence-dir>` |
| CI wall time for dependency prep | ~45 s (apt update + pip install, one-time per runner) |

The single documented command is `run_measured.sh`. Everything else is
prerequisite provisioning.

## 2. Marginal onboarding (per additional device)

| Item | Measured |
|---|---|
| Policy generation + signing (5 policies) | **568 ms** total → ~114 ms per policy |
| Policy apply: verify signature → install kernel rules → signed receipt | **348 ms** (initial v1 apply); **28.5 ms** (v2 revoke, submit→receipt) |
| Marginal cost per device *within schema* | ~0.5 s of machine time + 1 signed policy file; no shared state between devices, so cost is flat per device |
| 2nd device pair | Supported — same cost as 1st (schema has exactly 2 pairs) |
| 5th device | **NOT SUPPORTED without redesign.** `policy_gate.py` schema validation requires exactly `{"tv_to_nvr_tcp_8080", "thermostat_to_hvac_tcp_9000"}`; any other scope is rejected as `unrecognized_firewall_scope`. Adding a 3rd+ device pair requires a schema change, new rule templates, and re-verification. This is the binding constraint on scaling. |

## 3. Revocation timeline (monotonic)

| Phase | Measured |
|---|---|
| Policy submission → signature validated | **384 µs** |
| Validation → kernel rules applied (iptables-restore + kernel read-back) | **23.7 ms** |
| └─ conntrack eviction (`conntrack -D`, inside kernel apply) | **5.6 ms**, exit 0, evicted 1 ESTABLISHED flow |
| Kernel applied → signed receipt issued | **3.9 ms** |
| **Submission → signed receipt (total)** | **28.5 ms** |
| Submission → first confirmed blocked observation (probe) | **1.41 s** — dominated by the new-connection probe timeout, not enforcement; kernel was enforcing at ~28 ms |

Revocation is fast at the kernel (~28 ms submit-to-receipt). Confirmation via
active probing adds ~1.4 s due to TCP timeout semantics.

## 4. Recovery and verification

| Item | Measured |
|---|---|
| `verify_evidence.py` wall time (7 receipts, 4 PCAPs, kernel rules, sqlite ledger) | **156 ms** |
| Steps to diagnose failure | 1. Run verifier → 2. read `report.json` / falsifier line → 3. inspect `gate-log.txt`, `kernel-counters.txt` |
| Steps to restore authorization | 1. Owner signs new policy version (n+1) → 2. `policy_gate.py --policy` → 3. receipt confirms kernel hash |
| Hostile evidence tamper test | Verifier **rejected** tampered receipt (`bad signed receipt: signature_invalid`), exit nonzero |

## What was NOT measured (blockers)

- **Local VM execution:** the leased VM lacks conntrack kernel support, the
  `conntrack` and `tcpdump` tools, and host `CAP_SYS_ADMIN`. All kernel
  evidence comes from the disposable GitHub Actions runner, as in PR #113.
  (PR #122 recorded the same local blockers.)
- **5th-device onboarding:** blocked by fixed 2-pair schema (see §2).
- **Multi-receiver / distributed propagation:** single firewall namespace only;
  policy delivery to N receivers unmeasured.
- **Long-run stability:** single ~2-minute run; no soak test.

## Raw evidence locations

CI artifact `HOME-GUARD-004-measured-evidence` (run 39152946810):
`cost-timeline.jsonl`, `revocation-timings.json`, 4 PCAPs, `kernel-counters.*`,
`apply-receipts.jsonl` (7 signed), `report.json`, `SHA256SUMS`, `tamper-test.log`.
