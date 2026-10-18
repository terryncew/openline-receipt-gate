# Home Guard local reproducer: execution gate and factual handoff

**Date:** 2026-10-18 UTC / America/Los_Angeles. **Outcome: ENV_BLOCKED; NO NEW KERNEL EXPERIMENT.** This is a narrowly scoped *blocked-run receipt*, not a security proof, new framework, or a completed reproducibility/cost study. Owner's stop condition applied before any firewall mutation. No source security mechanism, frozen HOME-GUARD-003 scripts, or raw experiment evidence changed.

## Pinned sources, exact Git identity, and prior evidence

- Repository: `terryncew/openline-receipt-gate`.
- Frozen HOME-GUARD-003 candidate commit: `44486057320e908ec091c327112d830f65e20caa` (Draft PR #113, **unmerged**, base `study/home-guard-002-virtual-net@89a80d6736e38a0c6d59f821e72425e4ce808bd0`). This branch was forked from the exact candidate SHA and the new Draft PR is **stacked on PR #113's branch** to leave its base relationship intact. Candidate script and all frozen evidence remain byte-unchanged.
- Original source Git blob SHA-1 from pinned GitHub `fetch_file`:
  - `experiments/home-guard-003/README.md`: `863dc3f6c93767b1e2658f919c285dca918f3a64`
  - `run_virtual_network.sh`: `65528fa7a6b9313da7a08b1bb82c47b7dfd9d149`
  - `policy_gate.py`: `abc1c7f8fd9c436801c7d26687439f98379c5f33`
  - `make_policies.py`: `c824aa286551a77dccd93fa18efd298b34914157`
  - `active_flow.py`: `00b82984bd6b8836d0a22aae855a8a1e30218970`
  - `echo_endpoint.py`: `20933c7df6740bcd1a59e11b6c459cbb70bb81b7`
  - `verify_evidence.py`: `52f9c0901a7d0927967d511f4e2ffb1b9c23da67`
  - prior `experiments/home-guard-002/run_virtual_network.sh`: `2c784aac002cc937c2206db795b89d8984609a57`
  - prior `experiments/home-guard-002/client.py`: `02544a1b03f2ffef07ffaacc9b794187e2dd0027`
  - candidate CI `.github/workflows/home-guard-003.yml`: `07707073aaa9ff0b290b68d7bfa59c81dae9dab7`
- PR #113 historical reported kernel pass and raw evidence archive: `https://github.com/terryncew/openline-receipt-gate/actions/runs/38447378689` / artifact `11839625863` (retention 30 days). This is **prior evidence, not today's new run**. The GitHub PR body documents 4 PCAPs, 7 signed decisions, TCP attempt/ACK observations, packet counts, and rule counters. The binary historical artifact was not downloaded or rechecked in this run.
- Compared evidence-packaging patterns read from private `terryncew/openline-research-workspace`, Draft PR #10 `2ad2a98f27ebd4211986d65cd1cfebee497f48bb`: deterministic offline verification + pinned manifest + independent reviewer. Nothing from that PR was edited or imported. For a later runnable packet proof, anchor the manifest in a trusted frozen commit, verify bytes **before any code execution**, and independently sign trusted results; do not treat a checksum in the same writable bundle as external provenance.
- Applicable instructions: source candidate `experiments/home-guard-003/README.md` and script headers reviewed, HOME-GUARD-002 README/script inspected. `AGENTS.md`, root `HANDOFF.md`, HOME-GUARD-001/002/003 `HANDOFF.md`, `CLAUDE.md` and `CONTRIBUTING.md` returned NOT_FOUND at this SHA; no such instructions or handoffs were invented. New `reproducer-preflight/HANDOFF.md` records this additive task-specific handoff.

## Already-available local commands (NOT EXECUTED HERE)

On a disposable, explicitly authorized isolated Linux VM with `sudo` and namespace network capabilities; Python 3, `cryptography==50.0.1`, `iproute2`, `iptables`, `conntrack`, and `tcpdump`, from the pinned candidate checkout:

**Existing single-run demo command:**
```bash
bash experiments/home-guard-003/run_virtual_network.sh /tmp/hg3-evidence
```
**Existing separate independent verification command:**
```bash
python experiments/home-guard-003/verify_evidence.py /tmp/hg3-evidence
```

The original script creates `hg3-fw`, `hg3-tv`, `hg3-nvr`, `hg3-thermo`, `hg3-hvac` named namespaces, veth links only, applies signed test policies with receiver gate and records firewall snapshot, test client streams, pcaps, and `SHA256SUMS`. It installs/uses kernel firewall in `hg3-fw` (requires explicit isolation and privilege); it cleans its namespaces on exit. The original workflow attempts a dependency `pip install` and potentially `apt-get install`, both disallowed by this run's offline/no-install limits. **No remote CI rerun was triggered.**

## Actual preflight observations today

Read-only host check and one safely isolated disposable `unshare` user/network/mount process; **zero host firewall rules changed**, zero named namespaces added or deleted, zero package downloads/installation. Structured raw stdout, exit code, capability bits, installed tools and clock in `ENV_PREFLIGHT.json`. SHA-256 of local preflight JSON exactly **`36ab7b541056e6d290553dfdc1af5373827fb5fccd6347924379da0bfd2fc652`** before committing its UTF-8 bytes.

| Item | Observation |
|---|---|
| Host | Linux `6.18.55`, x86_64; Python `3.13.5`; cryptography `46.0.4` (candidate docs pin `50.0.1`) |
| Already installed | `ip` (iproute2 6.15), `sudo`, `unshare`, `git`, `sha256sum`, Python |
| Missing executables | **`iptables`, `iptables-restore`, `iptables-save`, `conntrack`, `tcpdump`** |
| Host capabilities | `CAP_NET_ADMIN=false`, `CAP_SYS_ADMIN=false` (effective hex `00000000800405fb`) |
| Safe namespace-only check | `unshare --user --map-root-user --net --mount --fork -- sh -c 'id; ip -V; ip link show lo'` **exit 0**; isolated loopback is DOWN, no firewall operations |
| Original integration script | **NOT RUN**. Its initial executable preflight would emit `ENV_BLOCKED: missing iptables` and exit 77 under these exact tool conditions, before any network creation. This is an implication from read source, **not observed script output**. |
| Safety decision | Stop, no apt/pip/network download, no imitation firewall, no synthetic substitute, no privileged host modification |

This environment can run a disposable network namespace, but it lacks the native kernel instruments needed to establish **actual packet forwarding rules, conntrack eviction and packet capture**. Success of the namespace probe is not evidence of packet enforcement. An isolated user namespace does not magically provide the absent executables. The correct classification is **BLOCKED**.

## Original implementation review: what matters to the next fair run

The original `policy_gate.py` pins owner public key outside the request, verifies Ed25519 signed policy, fixed schema and expiry, enforces increasing version in SQLite, writes narrow `iptables-restore` rules, reads `iptables -S FORWARD` from kernel and signs accepted/refused decision receipts. After revocation it installs dedicated TCP DROP in both directions before any generic established-flow allowance. Its `conntrack -D` is attempted and exit status printed; **the code does not require exit 0 or record its result in a signed receipt**, so do not upgrade an attempted eviction to an independently certified successful conntrack invalidation. The explicit DROP can still deny traffic without successful eviction; this requires real PCAP and counter evidence.

The existing `verify_evidence.py` checks the TCP established-flow application ACK trace, separate ingress/egress PCAPs, rule/counters, owner and receiver signatures, versions, file hashes, SQLite high-water, and thermostat before/after traffic. It **does not** prove physical packet-level identity, effect-free crash recovery, unbounded topology onboarding, an independently operated receiver, or that kernel reality cannot change after a snapshot. Preexisting PCAP observations are distinct from attempted sends and DROP counters; never claim the attempted sends equal packets dropped.

`active_flow.py` emits `time.time_ns()` wall-clock timestamps; the revocation barrier and receiver receipt likewise use epoch time. The original instrumentation does **not** collect the requested same-clock **monotonic** sequence of submission → validation → kernel apply → conntrack delete → confirmed first blocked packet → receipt issuance. Consequently **no trustworthy new measured revocation-enforcement latency is available today**, and the owner-signature timestamp is not enforcement latency. The script's fixed policy `rules` keys admit exactly two named flows, and hard-coded interfaces/topology do not natively support adding a fifth arbitrary protected device without changes. Don't report a measured marginal-device curve from these fixed fixtures.

## Real-cost report — only measured facts, no fabricated times

| Category requested | New observed measurement on this host | Outcome |
|---|---|---|
| A. First setup time / manual steps | Prerequisite inventory only; actual VM/network/policy setup **never began** | **BLOCKED / NOT MEASURED** |
| B. Second device and fifth device onboarding | Existing network topology includes TV, NVR, thermostat, HVAC with **two predeclared protected services**. No device added or timed. Fifth device is not supported under current hard-coded configuration without source/topology extension. | **BLOCKED / NOT MEASURED** |
| C. Revocation enforcement monotonic timing | No running firewall, TCP flow or signed revocation this turn; original recorded times are wall clock, not the requested monotonic chain | **BLOCKED / NOT MEASURED** |
| D. Recovery, receipt verification, restore policy | No new receipt, evidence package, replay or restoration | **BLOCKED / NOT MEASURED** |
| Cold/repeat comparison | **0** actual new cold runs, **0** warmed runs | **BLOCKED** |
| New signed receipts | **0** | **NONE** |
| New PCAPs, kernel counters, rule snapshots | **0** | **NONE** |
| Hostile evidence alteration rejection | **NOT RUN**; no new trustworthy evidence package was generated | **BLOCKED** |

### User-facing console summary (correctly derived from this run)

```text
HOME GUARD — VIRTUAL NETWORK TEST
Before revocation: NOT TESTED (ENV_BLOCKED)
Existing connection after revocation: NOT TESTED (ENV_BLOCKED)
New unauthorized connection: NOT TESTED (ENV_BLOCKED)
Legitimate device control: NOT TESTED (ENV_BLOCKED)
Enforcement latency: NOT MEASURED
Signed receipts: 0 (new run)
Independent evidence verification: NOT RUN
Verdict: BLOCKED — required kernel tools unavailable
```

The printed values are a **report of today**, not executable output of `run_virtual_network.sh`. No hardcoded successful field.

## Bottom line and next permitted step

**No new security result and no marginal-device operating-cost result were established today.** The frozen candidate and prior credible virtual-network proof were preserved. Do not install dependencies, trigger networked CI, weaken the kernel falsifier, claim fresh results from the old CI run, or create additional projects on this task's authority. A future independent actual demo requires **explicit owner-approved** offline, isolated Ubuntu/compatible Linux VM with the required native tools already installed, a *fresh cold run*, a separately pinned evidence manifest, tamper test and monotonic instrumentation before timing claims. Work stopped at the explicit environment gate; this task branch holds only read-only preflight receipts and handoff.
