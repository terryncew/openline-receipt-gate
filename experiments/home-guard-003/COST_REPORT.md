# HOME-GUARD-003 Reproducer and Cost Study — corrected operational costs

**Corrections applied 2026-10-18** per independent review of PR #123.
All values recomputed from raw monotonic timestamps in the preserved original
CI artifact (run 39152946810). No values estimated.

**Provenance:**
- Frozen PR #113 mechanism: `44486057320e908ec091c327112d830f65e20caa`
- CI-tested execution: commit `708dc537` (run 39152946810, ubuntu-latest)
- Reviewed documentation: commit `2ce3bd05`
- Original artifact SHA256SUMS digest: `67f5f7e7f8fb821b0bfc00b5fdd884ed964f5716fdce1ecfa8ef1b417a011c1c`
  (29 entries; 28 match — see §7)

## 1. Cold scripted setup: 1.562 s

**Boundary:** `cold_setup_start` → `initial_apply_end` in `cost-timeline.jsonl`
(monotonic_ns 43803849425 → 45365771741).

Covers: tool presence checks, 5 namespace creations, 4 veth pairs + addressing,
sysctl, fail-closed FORWARD DROP, policy generation (5 fixtures), server
startup, first owner policy (v1) verified + applied + receipted.

**Not included:** dependency provisioning (see §2), repo checkout, operator
think time. Manual operator steps: 3 (clone+checkout; install deps; run one
command: `bash experiments/home-guard-003/run_measured.sh <evidence-dir>`).

## 2. Dependency provisioning: ~11.8 s (CI-observed, one-time per runner)

**Boundary:** CI step start 18:10:40.258Z → next step start 18:10:52.097Z.

Covers: `pip install cryptography==50.0.1` + `apt-get install iproute2
iptables conntrack tcpdump`. One-time per fresh runner; not part of the
experiment's own timing.

## 3. Revocation — two distinct boundaries, do not conflate

### 3a. Internal: validation through signed receipt — 28.467 ms

**Boundary:** `measure_phases.py` monotonic_us, inside the policy-gate process.

| Phase | Measured |
|---|---|
| Signature validation | 0.384 ms |
| Kernel rule application (iptables-restore + kernel read-back) | 23.722 ms |
| └─ conntrack eviction (`conntrack -D`) | 5.647 ms, exit 0, 1 ESTABLISHED flow evicted |
| Signed receipt issuance | 3.892 ms |
| **Internal total (submit → receipt)** | **28.467 ms** |

### 3b. Outer: submission through process return — 179.131 ms

**Boundary:** `revocation_submit` → `revocation_receipt_issued` in
`cost-timeline.jsonl` (monotonic_ns 48017853646 → 48196984275).

Covers the full `measure_phases.py` process invocation via
`sudo ip netns exec`: Python startup, imports, the 28.467 ms internal work,
and process teardown. The ~150 ms difference vs §3a is process + namespace
exec overhead, not enforcement latency.

### 3c. Blocked-probe result — 1.610 s (NOT enforcement latency)

**Boundary:** `revocation_submit` → `first_blocked_observation`
(48017853646 → 49628144973).

This measures a *new-connection probe timing out* (TCP SYN with no response),
which is dominated by the client's timeout semantics. **It must not be
reported as "first-packet enforcement latency" or "time until the kernel
blocked."** The kernel was enforcing at ~28 ms (§3a); the 1.610 s is
observation latency through a timeout-based probe. A signed receipt timestamp
is likewise not independent proof of the exact instant packet enforcement began.

## 4. Evidence verification: 156.235 ms

**Boundary:** `verification_start` → `verification_end`
(54832990997 → 54989226024).

Covers `verify_evidence.py`: 7 receipt Ed25519 verifications, 4 PCAP parses,
kernel-rule binding checks, sqlite ledger consistency, report generation.

## 5. Policy generation: 568 ms for five fixture policies

**Boundary:** `policy_generation_start` → `policy_generation_end`
(44429228236 → 44997569663).

This generated **five test fixture policies** (v1 allow, v2 revoke, forged,
rollback, expired). It is **not** "five device onboardings" and must not be
reported as such.

## 6. NOT MEASURED (explicit)

- **Marginal device onboarding:** NOT MEASURED. No per-device onboarding flow
  was executed; the §5 timing is fixture generation, not onboarding.
- **Fifth device:** UNSUPPORTED. The policy schema fixes exactly two device
  pairs (`tv_to_nvr_tcp_8080`, `thermostat_to_hvac_tcp_9000`);
  `policy_gate.py` rejects any other scope as `unrecognized_firewall_scope`.
  A third pair requires schema redesign (not authorized, not attempted).
- **Recovery time:** NOT MEASURED. No failure-recovery run was timed.
- **Repeated cold/warm performance:** NOT MEASURED. Single run only; no
  variance, no warm-cache comparison.

## 7. Evidence-integrity defect (original artifact)

The original `SHA256SUMS` (29 entries) has **28 matching, 1 failing**:
`cost-timeline.jsonl` fails because `run_measured.sh` appended the
`run_complete` marker **after** hashing. The manifest also omits
`revocation-timings.json`, `applied.sqlite`, and `tamper-test.log`.

The original artifact is preserved as-downloaded (digest above) and is **not
rewritten**. A post-review derived manifest is provided separately, labeled
as such. Future packaging finalizes all writes before hashing and requires
all declared hashes to match (see corrected `run_measured.sh`).
