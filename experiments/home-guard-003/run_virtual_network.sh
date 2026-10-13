#!/usr/bin/env bash
# HOME-GUARD-003: owner-signed update controls real kernel firewall in a
# disposable GitHub-hosted VM. NEVER invoke on any home network or host NIC.
set -Eeuo pipefail

EXP="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$EXP/../.." && pwd)"
EX2="$REPO/experiments/home-guard-002"
PY="$(command -v python)"
E="${1:?evidence path required}"
mkdir -p "$E"
E="$(cd "$E" && pwd)"
NAMES=(hg3-fw hg3-tv hg3-nvr hg3-thermo hg3-hvac)
CREATED=()
cleanup() {
  set +e
  for ns in "${CREATED[@]}"; do
    sudo ip netns pids "$ns" 2>/dev/null | xargs -r sudo kill -TERM 2>/dev/null
  done
  sleep 0.3
  for ns in "${CREATED[@]}"; do sudo ip netns del "$ns" 2>/dev/null; done
  sudo chown -R "$(id -u):$(id -g)" "$E" 2>/dev/null
}
trap cleanup EXIT

for cmd in ip iptables iptables-restore conntrack tcpdump; do
  if ! command -v "$cmd" >/dev/null; then
    echo "ENV_BLOCKED: missing $cmd" | tee "$E/environment-blocker.txt"
    exit 77
  fi
done
sudo ip netns list > "$E/initial-namespaces.txt"
for ns in "${NAMES[@]}"; do
  if grep -Eq "^$ns( |$)" "$E/initial-namespaces.txt"; then
    echo "ENV_BLOCKED: namespace $ns already exists; will not touch it" | tee "$E/environment-blocker.txt"
    exit 77
  fi
done
{
  echo "HOME-GUARD-003 disposable namespace security test"
  uname -a
  ip -V
  iptables --version
  conntrack -V
  "$PY" --version
  git -C "$REPO" rev-parse HEAD
} > "$E/environment.txt"

for ns in "${NAMES[@]}"; do
  if ! sudo ip netns add "$ns"; then
    echo "ENV_BLOCKED: cannot create $ns" | tee "$E/environment-blocker.txt"
    exit 77
  fi
  CREATED+=("$ns")
  sudo ip -n "$ns" link set lo up
done

link_pair() {
  num="$1"; ns="$2"; fwif="$3"; hostif="$4"
  sudo ip link add "$fwif" type veth peer name "$hostif"
  sudo ip link set "$fwif" netns hg3-fw
  sudo ip link set "$hostif" netns "$ns"
  sudo ip -n hg3-fw addr add "10.73.$num.1/24" dev "$fwif"
  sudo ip -n hg3-fw link set "$fwif" up
  sudo ip -n "$ns" addr add "10.73.$num.2/24" dev "$hostif"
  sudo ip -n "$ns" link set "$hostif" up
  sudo ip -n "$ns" route add default via "10.73.$num.1"
}
link_pair 1 hg3-tv fwtv tveth
link_pair 2 hg3-nvr fwnvr nvreth
link_pair 3 hg3-thermo fwthermo tmeth
link_pair 4 hg3-hvac fwhvac hveth
sudo ip netns exec hg3-fw sysctl -qw net.ipv4.ip_forward=1
sudo ip netns exec hg3-fw sysctl -qw net.ipv4.conf.all.rp_filter=0
# Fail CLOSED before loading the very first owner policy.
sudo ip netns exec hg3-fw iptables -w -P FORWARD DROP
sudo ip netns exec hg3-fw iptables -w -F FORWARD

"$PY" "$EXP/make_policies.py" "$E/policies" > "$E/test-key-disclosure.txt"
GATE_ARGS=(--ledger "$E/applied.sqlite" --receipts "$E/apply-receipts.jsonl")
run_policy() {
  stage="$1"; filename="$2"
  echo "APPLY $stage $filename" | tee -a "$E/policy-events.txt"
  sudo ip netns exec hg3-fw "$PY" "$EXP/policy_gate.py" \
    --policy "$E/policies/$filename" "${GATE_ARGS[@]}" \
    --snapshot "$E/installed-$stage.rules" | tee -a "$E/gate-log.txt"
}
reject_policy() {
  stage="$1"; filename="$2"
  echo "REJECT_PROBE $stage $filename" | tee -a "$E/policy-events.txt"
  before="$(sudo ip netns exec hg3-fw iptables -S FORWARD | sha256sum | cut -d' ' -f1)"
  set +e
  sudo ip netns exec hg3-fw "$PY" "$EXP/policy_gate.py" \
    --policy "$E/policies/$filename" "${GATE_ARGS[@]}" \
    --snapshot "$E/should-not-exist-$stage.rules" >> "$E/gate-log.txt" 2>&1
  status=$?
  set -e
  after="$(sudo ip netns exec hg3-fw iptables -S FORWARD | sha256sum | cut -d' ' -f1)"
  if [[ "$status" -ne 10 || "$before" != "$after" ]]; then
    echo "FALSIFIER: rejected policy $stage changed rules or returned $status" >&2
    exit 1
  fi
  echo "REJECTED_WITHOUT_MUTATION $stage status=$status kernel_sha256=$after" |
    tee -a "$E/policy-events.txt"
}
probe() {
  namespace="$1"
  shift
  sudo ip netns exec "$namespace" "$PY" "$EX2/client.py" "$@" |
    tee -a "$E/client-probes.jsonl"
}

run_policy initial v1-owner-allow.json
# The two endpoints contain NO policy decisions. If reachable they respond.
sudo ip netns exec hg3-nvr "$PY" -u "$EXP/echo_endpoint.py" \
  --role nvr --bind 10.73.2.2 --port 8080 > "$E/nvr-server.log" 2>&1 &
sudo ip netns exec hg3-hvac "$PY" -u "$EXP/echo_endpoint.py" \
  --role hvac --bind 10.73.4.2 --port 9000 > "$E/hvac-server.log" 2>&1 &
sleep 1
grep -q "READY role=nvr" "$E/nvr-server.log"
grep -q "READY role=hvac" "$E/hvac-server.log"

capture() {
  iface="$1"; label="$2"
  sudo ip netns exec hg3-fw tcpdump -nn -U -s 0 -i "$iface" \
    -w "$E/$label.pcap" ip > "$E/$label-capture.log" 2>&1 &
}
capture fwtv tv-ingress
capture fwnvr nvr-egress
capture fwhvac hvac-egress
sleep 0.7

probe hg3-thermo --label control-before --host 10.73.4.2 --port 9000 --expect ok-hvac
# Real TV TCP stream keeps sending on the already ESTABLISHED socket, even
# after the receiver revokes authorization and installs DROP in the kernel.
sudo ip netns exec hg3-tv "$PY" -u "$EXP/active_flow.py" \
  --ready "$E/tv-flow-ready.txt" --stop "$E/tv-flow-stop.flag" \
  > "$E/tv-active-flow.jsonl" 2> "$E/tv-flow-stderr.txt" &
FLOW_PID=$!
ready=0
for i in $(seq 1 80); do
  if [[ -f "$E/tv-flow-ready.txt" ]]; then ready=1; break; fi
  if ! kill -0 "$FLOW_PID" 2>/dev/null; then
    echo "FALSIFIER: TV connection exited before establishing" >&2
    exit 1
  fi
  sleep 0.10
done
if [[ "$ready" -ne 1 ]]; then
  echo "FALSIFIER: initial owner-authorized TV connection never received 5 ACKs" >&2
  exit 1
fi
sudo ip netns exec hg3-fw conntrack -L -p tcp -s 10.73.1.2 -d 10.73.2.2 \
  > "$E/conntrack-before-revoke.txt" 2>&1 || true
sleep 0.25

run_policy revoked v2-owner-revoke.json
# Barrier is only AFTER kernel accepted DROP rules, not time of DENY receipt.
"$PY" -c 'import time; print(time.time_ns()//1000)' > "$E/revocation-barrier-us.txt"
sudo ip netns exec hg3-fw iptables -L FORWARD -v -n -x \
  > "$E/revoked-firewall-rules.txt"
# Test a NEW attempted connection while original TV flow continues sending.
probe hg3-tv --label new-TV-connection-after-revoke \
  --host 10.73.2.2 --port 8080 --expect drop
probe hg3-tv --label TV-alternative-port-after-revoke \
  --host 10.73.2.2 --port 8443 --expect drop
probe hg3-tv --label TV-forged-thermostat-after-revoke \
  --host 10.73.4.2 --port 9000 --expect raw-spoof

# Hostile policy files cannot install rules or advance version.
reject_policy forged v999-attacker-forged-allow.json
reject_policy rollback v1-owner-rollback.json
reject_policy expired v3-owner-expired.json
reject_policy tampered v3-tampered-unsigned.json
reject_policy duplicate v2-owner-revoke.json

# Unrelated *authorized* control remains usable.
probe hg3-thermo --label control-after --host 10.73.4.2 --port 9000 --expect ok-hvac
sleep 0.55
touch "$E/tv-flow-stop.flag"
wait "$FLOW_PID"
sudo ip netns exec hg3-fw iptables-save -c > "$E/kernel-counters.rules"
sudo ip netns exec hg3-fw iptables -L FORWARD -v -n -x > "$E/kernel-counters.txt"
sudo ip netns exec hg3-fw iptables -S FORWARD > "$E/kernel-final.rules"
sudo ip netns exec hg3-fw conntrack -L -p tcp -s 10.73.1.2 -d 10.73.2.2 \
  > "$E/conntrack-after-revoke.txt" 2>&1 || true
sudo ip netns exec hg3-fw ip -br addr > "$E/fw-interfaces.txt"

# Finish tcpdump while namespaces remain alive.
sudo ip netns pids hg3-fw | xargs -r sudo kill -INT || true
sleep 1
sudo chown -R "$(id -u):$(id -g)" "$E"
for label in tv-ingress nvr-egress hvac-egress; do
  tcpdump -nn -tt -r "$E/$label.pcap" > "$E/$label.txt" 2> "$E/$label-decode.log"
done
"$PY" "$EXP/verify_evidence.py" "$E"
(cd "$E" && sha256sum *.pcap *.rules *.txt *.jsonl report.json > SHA256SUMS)
echo "HOME-GUARD-003 PACKET_AND_SIGNATURE_EVIDENCE_READY $E"
