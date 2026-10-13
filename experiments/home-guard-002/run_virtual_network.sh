#!/usr/bin/env bash
# HOME-GUARD-002 -- disposable Linux network namespaces and actual kernel firewall.
# Does not touch any host/household interface. No cloud or public network target.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EXP="$ROOT/experiments/home-guard-002"
E="$1"
mkdir -p "$E"
E="$(cd "$E" && pwd)"
PIDS=""
NAMES="hg2-fw hg2-tv hg2-nvr hg2-thermo hg2-hvac hg2-relay"

cleanup() {
  set +e
  for ns in $NAMES; do
    sudo ip netns pids "$ns" 2>/dev/null | xargs -r sudo kill -TERM 2>/dev/null
  done
  sleep 0.25
  for ns in $NAMES; do sudo ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT

for cmd in ip iptables iptables-save tcpdump python3; do
  if ! command -v "$cmd" >/dev/null; then
    echo "ENV_BLOCKED: missing $cmd" | tee "$E/environment-blocker.txt"
    exit 77
  fi
done

printf 'HOME-GUARD-002 disposable Linux namespace packet test\n' > "$E/metadata.txt"
uname -a >> "$E/metadata.txt"
for ns in $NAMES; do
  if ! sudo ip netns add "$ns"; then
    echo "ENV_BLOCKED: cannot create Linux network namespace" | tee "$E/environment-blocker.txt"
    exit 77
  fi
  sudo ip -n "$ns" link set lo up
done

# Physical port identity in this *virtual* topology is ingress veth interface,
# not a user-supplied packet source IP.
link_pair() {
  num="$1"; host="$2"; fwif="$3"; hostif="$4"
  sudo ip link add "$fwif" type veth peer name "$hostif"
  sudo ip link set "$fwif" netns hg2-fw
  sudo ip link set "$hostif" netns "$host"
  sudo ip -n hg2-fw addr add "10.73.$num.1/24" dev "$fwif"
  sudo ip -n hg2-fw link set "$fwif" up
  sudo ip -n "$host" addr add "10.73.$num.2/24" dev "$hostif"
  sudo ip -n "$host" link set "$hostif" up
  sudo ip -n "$host" route add default via "10.73.$num.1"
}
link_pair 1 hg2-tv fwtv tveth
link_pair 2 hg2-nvr fwnvr nvreth
link_pair 3 hg2-thermo fwthermo tmeth
link_pair 4 hg2-hvac fwhvac hveth
link_pair 5 hg2-relay fwrelay releth

sudo ip netns exec hg2-fw sysctl -qw net.ipv4.ip_forward=1
sudo ip netns exec hg2-fw sysctl -qw net.ipv4.conf.all.rp_filter=0
sudo ip netns exec hg2-fw sysctl -qw net.ipv4.conf.fwtv.rp_filter=0
sudo ip netns exec hg2-fw iptables -w -P FORWARD DROP
sudo ip netns exec hg2-fw iptables -w -F FORWARD
# Return packets for the explicitly permitted flows.
sudo ip netns exec hg2-fw iptables -w -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# One deliberately narrow exception permits TV to reach a relay so the second
# hop, relay -> protected NVR, can be independently tested.
sudo ip netns exec hg2-fw iptables -w -A FORWARD -i fwtv -o fwrelay -s 10.73.1.2 -d 10.73.5.2 -p tcp --dport 7070 -j ACCEPT
# Authorized control is interface + exact source/destination + exact port.
sudo ip netns exec hg2-fw iptables -w -A FORWARD -i fwthermo -o fwhvac -s 10.73.3.2 -d 10.73.4.2 -p tcp --dport 9000 -j ACCEPT
# The TV's physical virtual ingress interface always drops, even forged source IP.
sudo ip netns exec hg2-fw iptables -w -A FORWARD -i fwtv -j DROP
# Relays are not entitled to reach the protected recorder.
sudo ip netns exec hg2-fw iptables -w -A FORWARD -i fwrelay -j DROP
sudo ip netns exec hg2-fw iptables -w -A FORWARD -j DROP

sudo ip netns exec hg2-fw iptables-save > "$E/firewall_rules.v4"
sudo ip netns exec hg2-fw ip -br addr > "$E/fw_interfaces.txt"
for ns in $NAMES; do
  sudo ip -n "$ns" route show >> "$E/routes.txt"
done

capture() {
  iface="$1"; label="$2"
  sudo ip netns exec hg2-fw tcpdump -nn -U -s 0 -i "$iface" -w "$E/$label.pcap" ip > "$E/$label-capture.log" 2>&1 &
  PIDS="$PIDS $!"
}
capture fwtv tv-ingress
capture fwnvr nvr-egress
capture fwrelay relay-ingress
capture fwhvac hvac-egress

sudo ip netns exec hg2-nvr python3 -u "$EXP/endpoint.py" --role nvr --bind 10.73.2.2 --port 8080 --port 8443 > "$E/nvr-server.log" 2>&1 &
PIDS="$PIDS $!"
sudo ip netns exec hg2-hvac python3 -u "$EXP/endpoint.py" --role hvac --bind 10.73.4.2 --port 9000 > "$E/hvac-server.log" 2>&1 &
PIDS="$PIDS $!"
sudo ip netns exec hg2-relay python3 -u "$EXP/endpoint.py" --role relay --bind 10.73.5.2 --port 7070 > "$E/relay-server.log" 2>&1 &
PIDS="$PIDS $!"
sleep 2
grep -q "READY role=nvr" "$E/nvr-server.log"
grep -q "READY role=hvac" "$E/hvac-server.log"
grep -q "READY role=relay" "$E/relay-server.log"

probe() {
  ns="$1"
  shift
  sudo ip netns exec "$ns" python3 "$EXP/client.py" "$@" | tee -a "$E/attempts.jsonl"
}
# Control is tested before attacks to establish the endpoint is really reachable.
probe hg2-thermo --label control-before --host 10.73.4.2 --port 9000 --expect ok-hvac
# A compromised TV directly sends packets, ignoring any agent/API refusal.
probe hg2-tv --label tv-to-nvr-8080 --host 10.73.2.2 --port 8080 --expect drop
probe hg2-tv --label tv-alt-8443 --host 10.73.2.2 --port 8443 --expect drop
probe hg2-tv --label tv-alt-22 --host 10.73.2.2 --port 22 --expect drop
# Raw TCP SYN forges the allowed thermostat IP but enters on the TV veth port.
probe hg2-tv --label tv-spoofed-thermostat --host 10.73.4.2 --port 9000 --expect raw-spoof
# TV may talk to relay on 7070. The relay attempts NVR and must time out.
probe hg2-tv --label tv-relay --host 10.73.5.2 --port 7070 --expect relay-blocked
probe hg2-thermo --label control-after --host 10.73.4.2 --port 9000 --expect ok-hvac

sleep 1
sudo ip netns exec hg2-fw iptables-save -c > "$E/firewall_counters.rules"
sudo ip netns exec hg2-fw iptables -L FORWARD -v -n -x > "$E/firewall_counters.txt"
# Finish the packet capture independently of the synthetic endpoint processes.
sudo ip netns pids hg2-fw | xargs -r sudo kill -INT || true
sleep 1
sudo chown -R "$(id -u):$(id -g)" "$E"
for label in tv-ingress nvr-egress relay-ingress hvac-egress; do
  tcpdump -nn -tt -r "$E/$label.pcap" > "$E/$label.txt" 2> "$E/$label-decode.log"
done
python3 "$EXP/verify_packets.py" "$E"
( cd "$E"; sha256sum *.pcap *.txt *.jsonl *.rules report.json > SHA256SUMS )
echo "EVIDENCE READY: $E"
