# HOME-GUARD-003 Reproducer and Cost Study — corrected results

**Corrections applied 2026-10-18** per independent review of PR #123.
(Not to be confused with PR #114's HOME-GUARD-004 reboot/tamper study.)

**Question:** Can a fresh operator reproduce Home Guard's receiver-enforced
revocation in a disposable virtual network, independently verify the evidence,
and measure the additional work required to protect more devices?

**Answer: yes for the first two; the third is largely unmeasured.**

## What worked (CI run 39152946810, independently verified)

- **Reproduction:** the full PR #113 mechanism re-ran on a disposable runner
  from one documented command. Verdict:
  `PASS_SIGNED_POLICY_TO_KERNEL_REVOCATION_IN_VIRTUAL_NETWORK`.
- **Security observations:** 9 application-payload packets reached NVR before
  revoke, **0 after**. Established TV socket: 19 sends, **0 ACKs**. New TV
  connection + alternate port timed out. Forged source seen at TV ingress,
  **not** at HVAC egress. Thermostat → HVAC **2/2** before and after.
- Kernel counters: 8 revoked-flow DROPs, 3 spoof/alt-port DROPs, 6 legitimate
  ACCEPTs. **2** owner policies applied (v1→v2); **5** hostile updates rejected
  (forged signer, rollback ×2, expired, tampered); **7/7** receipts verify.
  `conntrack -D` exit 0, evicted the ESTABLISHED flow.
- **Hostile evidence tamper:** flipped signature byte → verifier rejected with
  the specific `signature_invalid` failure (not merely nonzero exit).
- **New runner, same mechanism:** the corrected orchestration reuses PR #113's
  six protected files byte-identical; it executes a copied orchestration
  script (`run_measured.sh`) and temporary wrappers (`measure_phases.py`)
  around `policy_gate` functions and `subprocess.run` for timing only.

## Corrected costs (boundaries in COST_REPORT.md)

- Cold scripted setup: **1.562 s** (3 manual operator steps; deps ~11.8 s separate).
- Revocation internal (validation → signed receipt): **28.467 ms**.
- Revocation outer (submit → process return): **179.131 ms**.
- Blocked-probe result: **1.610 s** — timeout-based observation, NOT enforcement latency.
- Evidence verification: **156.235 ms**.
- Policy generation: **568 ms for five fixture policies** (not device onboardings).

## Negative findings (retained, not softened)

- **PR #114 (HOME-GUARD-004):** startup ordering leak (6 packets before default
  DROP) and local-state rollback failure (restored kernel rejects current v2
  as stale). These failures stand and bound any recovery claim.
- **PR #115 (HOME-GUARD-005):** conventional nftables / signed-witness parity;
  **no unique OpenLine security advantage demonstrated**. Stop rule fired.
- **Marginal device onboarding: NOT MEASURED.** Fifth device: **UNSUPPORTED**
  by the fixed two-pair schema. No demonstrated device-onboarding advantage
  or commercial superiority is claimed.
- **Keys and trust:** public deterministic test fixtures; trusted privileged
  updater and root firewall; SQLite ledger not attacker-resistant.
- **Scope:** single receiver, single run, virtual interfaces only. No real-home
  or production safety proof. No repeated cold/warm measurements.
- A signed receipt timestamp is **not** independent proof of the exact instant
  packet enforcement began.

## Evidence integrity

Original artifact preserved (SHA256SUMS digest
`67f5f7e7f8fb821b0bfc00b5fdd884ed964f5716fdce1ecfa8ef1b417a011c1c`;
28/29 entries match — `cost-timeline.jsonl` fails as documented). A
post-review **derived** manifest covering all files is provided separately and
labeled as such; it is not presented as the original CI artifact.
