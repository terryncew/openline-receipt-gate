# HOME-GUARD-003 — signed owner authority governs an actual virtual firewall

Pre-registered criterion: verify an OpenLine owner-signed policy, then prove
its revocation stops both a new TV-to-NVR connection AND an already-established
TCP stream while legitimate thermostat-to-HVAC traffic stays up. Reject
forged-owner, rollback/replayed, expired and tampered signed policy updates.

Five disposable Linux namespaces, actual kernel iptables-restore rules,
actual conntrack and TCP traffic, four independent PCAP captures. A
separate trusted updater verifies pinned owner Ed25519 public key (fixture
only), schema and time; accepts strictly increasing policy versions; installs
only hard-coded veth-specific rules; observes kernel configuration and signs
the applied decision receipt with the receiver key. No user-supplied shell
commands or root trust chosen by submitted policies.

Falsifiers: post-revocation TV-to-NVR packet crossing NVR egress, existing
socket receiving any post-barrier application ACK, failure to observe active
pre-revocation traffic and continuing post-revocation sending, a new TV
connection succeeding, spoofed TV traffic crossing to HVAC, legitimate
control stopping, any rejected policy changing kernel rules, wrong owner
signature, rollback or receipt/hash mismatch, or missing packet captures.

The DROP is before any established-flow matching. The test also attempts
conntrack deletion. A local TCP socket might remain open but packets must
stop traversing the firewall; a TCP RST is not required for success.

Reproduce on a disposable Ubuntu VM with sudo privilege, Python 3,
cryptography==50.0.1, iproute2, iptables, conntrack, tcpdump:

    bash experiments/home-guard-003/run_virtual_network.sh /tmp/hg3-evidence

Independent verifier:

    python experiments/home-guard-003/verify_evidence.py /tmp/hg3-evidence

CI uploads the signed test policy files, the signed apply/refusal receipts,
SQLite durable sequence ledger, actual kernel installed rules/counters,
persistent-flow attempts and all raw PCAPs, including dedicated post-revoke HVAC capture. If namespace capabilities are
missing this experiment is INCONCLUSIVE, never simulator PASS.

No real devices, real credentials, household or public network, paid API,
deployment or publication. Fixed fixture signing keys from HOME-GUARD-001
are intentionally public. Root/host compromise, rollback of the SQLite DB,
crash atomicity between kernel and ledger, real link-layer identity, multiple
firewall nodes, WiFi paths, router restarts, and safe key custody are NOT
proven. The updater assumes trusted code and privilege in this isolated VM.

Draft PR #111, frozen HOME-GUARD-001 evidence and HOME-GUARD-002 source
remain unchanged. This is a separate experimental branch, not a pilot release.
