"""Independent checks over kernel TCP packet captures and iptables-save counters."""
import hashlib
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
decode = lambda name: (root / (name + ".txt")).read_text().splitlines()
tv = decode("tv-ingress")
nvr = decode("nvr-egress")
relay = decode("relay-ingress")
hvac = decode("hvac-egress")

attempts = [json.loads(line) for line in (root/"attempts.jsonl").read_text().splitlines()]
assert len(attempts) == 7, f"expected seven controlled attempts: {attempts}"
assert all(x.get("pass", x.get("status") == "RAW_SYN_SENT") for x in attempts), attempts
statuses = {x["label"]: x for x in attempts}
assert statuses["control-before"]["response"] == "OK:hvac"
assert statuses["control-after"]["response"] == "OK:hvac"
for label in ("tv-to-nvr-8080", "tv-alt-8443", "tv-alt-22"):
    assert statuses[label]["status"] == "TIMEOUT", statuses[label]
assert statuses["tv-relay"]["response"] == "RELAY_DOWNSTREAM_BLOCKED"

def found(lines, *needles):
    return any(all(term in line for term in needles) for line in lines)

assert found(tv, "10.73.1.2.", " > 10.73.2.2.8080:"), "TV attack SYN missing on ingress"
assert found(tv, "10.73.1.2.", " > 10.73.2.2.8443:"), "alternate-port SYN missing"
assert found(tv, "10.73.3.2.42424 > 10.73.4.2.9000:"), "raw spoofed packet missing at TV ingress"
assert not found(hvac, "10.73.3.2.42424 > 10.73.4.2.9000:"), "spoofed TV packet reached HVAC!"
assert found(relay, "10.73.5.2.", " > 10.73.2.2.8080:"), "relay's downstream SYN not seen"
assert found(hvac, "10.73.3.2.", " > 10.73.4.2.9000:"), "authorized flow missing on HVAC egress"
assert len(nvr) == 0, f"FALSIFIER: {len(nvr)} IP packets forwarded to protected NVR: {nvr[:6]}"

counters = {}
for line in (root/"firewall_counters.rules").read_text().splitlines():
    m = re.match(r"^\[(\d+):(\d+)\] -A FORWARD (.*)$", line)
    if not m:
        continue
    packets, _, spec = m.groups()
    packets = int(packets)
    if "-i fwtv" in spec and "-j DROP" in spec:
        counters["tv_ingress_drop"] = packets
    if "-i fwrelay" in spec and "-j DROP" in spec:
        counters["relay_ingress_drop"] = packets
    if "-i fwthermo" in spec and "-j ACCEPT" in spec:
        counters["thermostat_allow"] = packets
    if "-i fwtv" in spec and "-j ACCEPT" in spec and "-d 10.73.5.2" in spec:
        counters["tv_relay_allow"] = packets
for name in ("tv_ingress_drop", "relay_ingress_drop", "thermostat_allow", "tv_relay_allow"):
    assert counters.get(name, 0) > 0, f"kernel filter rule {name} did not count packets: {counters}"

pcaps = {}
for file in sorted(root.glob("*.pcap")):
    pcaps[file.name] = {
        "sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
        "bytes": file.stat().st_size,
    }
assert len(pcaps) == 4 and all(p["bytes"] >= 24 for p in pcaps.values()), pcaps
report = {
    "experiment": "HOME-GUARD-002",
    "environment": "disposable Linux netns, veth, kernel iptables FORWARD",
    "verdict": "PASS_PACKET_CONTAINMENT_IN_TESTED_TOPOLOGY",
    "tests": {
        "tv_direct_port_8080": "DROP_OBSERVED",
        "tv_alternate_ports_8443_22": "DROP_OBSERVED",
        "tv_forged_thermostat_source": "DROP_ON_TV_INGRESS",
        "tv_relay_to_nvr": "RELAY_REACHED_DOWNSTREAM_DROP",
        "thermostat_to_hvac_before_after": "2_OF_2_ALLOWED",
        "protected_nvr_egress_ip_packets": len(nvr),
    },
    "kernel_firewall_counters": counters,
    "pcap_sha256": pcaps,
    "limitation": "No real devices/home; static receiver-policy translation, not signed-policy-to-firewall deployment.",
}
(root/"report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps(report, indent=2, sort_keys=True))
