# HOME-GUARD-004 — frozen recovery and tamper falsifiers

**Status:** PRE-IMPLEMENTATION FREEZE. This document is committed by itself before any HOME-GUARD-004 harness or execution. Later corrections to the apparatus must not alter the success criteria. Any uncovered weakness remains visible as FAIL; missing privileged environment or missing independent packet proof is INCONCLUSIVE, never PASS.

## Baseline / no new production code

Test the exact HOME-GUARD-003 source at `44486057320e908ec091c327112d830f65e20caa`, particularly `experiments/home-guard-003/policy_gate.py` and the cold-start ordering in `run_virtual_network.sh`. The frozen HOME-GUARD-003 result is a bounded PASS only for a live policy update, not recovery. Do not edit its code, signatures, original experiments or frozen evidence. This is a separate disposable Linux namespace test, not a patch to a product.

## One independent receiver and its trust boundaries

A simulated TV (`10.73.1.2`) tries to reach an NVR (`10.73.2.2:8080`) through a distinct Linux kernel firewall namespace. A thermostat (`10.73.3.2`) is authorized to reach HVAC (`10.73.4.2:9000`). Endpoints have no application-level deny policy. A fixed TEST owner key signs `v1 ALLOW(TV)` and `v2 REVOKE(TV)` using the unchanged HOME-GUARD-003 contract. The updater has a locally writable SQLite high-water ledger, a separately located signed-receipt audit witness captured from v2, and actual netfilter/conntrack. The attacker may control the TV, replay old valid signed policies, remove/replace SQLite and policy files; the attacker cannot forge the test owner signature or edit the separately archived witness in the **conditional witness** case. This is a limitation, not a production assumption of secure storage.

## Power-loss simulation and observation

After demonstrating that v1 allows TV and v2 drops TV while thermostat works, kill/delete the *firewall namespace* to destroy its kernel filter and conntrack state, retaining only expressly designated files. Recreate the namespace and its veth interfaces. This emulates complete loss of the kernel forwarding/filtering state and restart while device namespaces persist; **it is not an electrical power-cut or real router reboot**.

In every reboot case, arm real packet capture at the NVR endpoint interface and at the TV interface *before* enabling IP forwarding. Preserve the first observed SYN and response with packet timestamps. A reboot is not a success unless there is at least one post-reconnection TV attempt visible at ingress. Also capture `iptables -S FORWARD`, `iptables-save -c`, application replies and the signed policy/receiver receipts. Do not use a 200ms grace period for cold-start leakage; a single forwarded forbidden packet is a FAIL.

## Immutable case matrix and verdicts

| Case | Frozen requirement / falsifier | Class |
|---|---|---|
| HG4-0 valid live precondition | v1 permits TV, then v2 revokes it, while thermostat continues; v2 signed receipt archived independently | Sanity; INCONCLUSIVE if missing |
| HG4-1 existing startup ordering | After reset with veth links up, enable forwarding **before** DROP, as HOME-GUARD-003 orders it; actively send TV SYNs before DROP. Requirement is *zero* forbidden egress packets from the earliest observable ingress. One TV packet or successful NVR response before DROP = **FAIL**; no ingress attempts/capture = INCONCLUSIVE | Boot fail-closed |
| HG4-2 safe ordering comparison | Install `FORWARD DROP` while forwarding is off, arm captures, only then allow packet forwarding and later process signed recovery. Zero forbidden NVR egress packets from first ingress until legitimate recovery is permitted. Authorized control must succeed after a valid recovered policy, not by an unapproved default rule | Boot sequencing control |
| HG4-3 intact v2 ledger restart | After kernel state loss, unmodified `policy_gate.py` must reinstall the current signed v2 without granting TV and restore thermostat; rejecting same v2 and leaving thermostat down is **FAIL recovery availability**, although TV containment is a separate PASS if no egress packets cross | Durable recovery |
| HG4-4 missing ledger | With no local ledger and only previously issued valid signed v1 available, old v1 must **not** reopen the revoked TV permission. Any accepted v1 and forwarded TV packet is **FAIL** | Revocation rollback safety |
| HG4-5 stale ledger | With backed-up version-1 ledger and the old version-1 policy, refuse the replay and remain fail-closed. Accepting old version-1 and forwarding TV is FAIL. A receiver unaware of v2 cannot independently know that v2 exists without external evidence; do not conflate replay refusal with complete revocation freshness | Stale-state handling |
| HG4-6 attacker-replaced ledger | Replace the v2 SQLite ledger with an attacker-controlled valid SQLite row at version 0, then supply old genuinely owner-signed v1. It must not reopen the TV; any allowed TCP packet is **FAIL**. Attacker cannot edit firewall or signer key directly | Local-state tamper prevention |
| HG4-7 missing policy file | Boot with safe default DROP and intact v2 ledger but absent selected policy JSON. No TV packet may reach NVR; a raw exception without a signed, identifiable failure receipt is **FAIL** for auditable recovery (separate verdicts for containment and evidence) | Missing-policy behavior |
| HG4-8 external witness | Independent verifier with an *out-of-band pinned* v2 signed apply receipt and source-policy bytes must identify restored version/hash below v2 or TV-permitting kernel state as inconsistent. Missing or altered witness must be INCONCLUSIVE, never proof of no tampering. Distinguish passive detection with witness from **actual updater prevention**, and note fixture keys are publicly known | Conditional tamper detection |
| HG4-9 physical power loss | Without an actual power-loss device and persistent secure boot/update state, **INCONCLUSIVE**, regardless of namespace resets | Production boundary |

For each case report **PASS / FAIL / INCONCLUSIVE** with raw packet capture and kernel state supporting the assessment. Negative results are expected and must not be repaired by changing original HOME-GUARD-003 code in this experiment.

## Minimum trusted measurements

1. Source pin and unchanged existing test/evidence hashes; a separate GitHub-hosted ephemeral Ubuntu runner, sudo netns/iptables, no host NIC/firewall modifications, no outbound production destinations or real credentials.
2. Raw PCAP capture started before forwarding is enabled (both TV source and NVR sink), valid Ethernet packet records, exact packet and reply counts, no selective filtering of captures by result.
3. A signed v2 receiver receipt linked to original policy byte hash and prior observed firewall state, independent of attacker-mutated local ledger. If only a mutable local receipt is present, tamper detection is not established.
4. Per-case signed policy bytes, SQLite state before/after (only synthetic), kernel rules before/after, all failure outputs including exceptions, time ordering and SHA-256 manifest. Keep failed runs/artifacts; do not replace a failed result with an unsupported PASS.
5. Receiver-side packet logging is corroborated by traffic at the endpoint, not by the updater's own assertion. A failed TCP connection alone never proves firewall containment.

## STOP rule

Do not implement a new policy engine, secure-storage architecture, router software or product feature. Stop after the recorded results if recovery fails. Any repair requires a **separate** design with a new independent trust anchor and fresh preregistration; a test-only safe boot ordering control may be demonstrated but must not be mislabeled as shipped HOME-GUARD-003 enforcement. $0 paid API, no hardware or external sites, no merge/deployment.