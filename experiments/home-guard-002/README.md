# HOME-GUARD-002 — disposable kernel-firewall experiment

Independent of HOME-GUARD-001 frozen source/tests and separate from Draft PR #111.
This experiment provisions **six isolated Linux network namespaces inside a
single disposable GitHub-hosted Ubuntu runner**, connects them by virtual
Ethernet pairs, and uses actual Linux IPv4 forwarding + iptables DROP/ACCEPT.

Actors: TV (attacker), NVR (protected recorder), thermostat (authorized
sensor), HVAC gateway (authorized target), relay (attacker-reachable hop), and
firewall/router. No household NIC, customer traffic, real device, or cloud
firewall is configured. The simulated NVR/HVAC run deliberately simple TCP
listeners, but **the NVR has no application deny logic**: any reachable
connection to its ports would succeed. Blocking is at the router.

Threat cases: TV->NVR TCP/8080; alternate TCP/8443 and TCP/22; raw
spoofed source TCP SYN from TV using thermostat's IP toward HVAC; and a
reachable TV->relay hop that attempts relay->NVR. Control: thermostat->HVAC
TCP/9000 returns OK before and after attacks. A TV ingress interface drop
rule and a relay ingress drop rule make port and source-IP evasion ineffective
for the tested topology. A narrow TV->relay allow rule exists ONLY to
exercise whether the *second* hop can be blocked. Kernel packet filter
counters and captures on the firewall's ingress and egress interfaces are
independently inspected.

The passing firewall rules here are an **explicit test translation** of the
simulator's intent, not a general-purpose compiler of arbitrary signed
OpenLine decisions. HOME-GUARD-002 is a packet enforcement observation,
not a proof of an authenticated, signed-policy-to-kernel deployment chain.
Spoof resistance follows physical/veth ingress-interface distinction in
this model; no real hardware port security, Wi-Fi, VLAN isolation or
compromised-router claim is made.

## Reproduce
From this branch in a disposable Ubuntu VM with sudo network privileges,
Python 3, iproute2, iptables and tcpdump:

    bash experiments/home-guard-002/run_virtual_network.sh "$PWD/home-guard-002-evidence"

The script creates only hg2-* namespaces and deletes them on exit. The
resulting directory holds actual pcap files, decoded pcap text, firewall
rule counters, connection observations, and SHA256SUMS. CI uploads that
directory as a review artifact. The PCAPs and iptables counters, rather
than Home Guard simulator logs, establish kernel-level ingress, forwarding
and suppression. If namespace creation isn't permitted, the environment
is blocked and the result is **INCONCLUSIVE**, not simulation PASS.

Falsifiers: forbidden traffic appearing at NVR egress; spoof packet
passing TV ingress and reaching HVAC egress; relay reaching NVR; any
authorized thermostat control failing; no incrementing firewall DROP
counter; TCP connection refusals counted as packet denial; or no packet
capture from the attempted TV flow. No paid APIs or deployments.
