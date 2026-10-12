#!/bin/bash
# GATEWAY-SUBSCRIPTION-001: one-command subscription-cancellation demo.
#
#   ./subscription001/run_demo.sh
#
# Starts a local gateway stack (authz service + mock payment API with and
# without the final standing check + Envoy), runs the demo, prints the
# narrative, tears everything down, and leaves evidence in
# subscription001/run/evidence/.
#
# Fictional parties and funds only. No real payment processing.
# Requires: Python 3.12, pip deps (gateway/requirements.txt), Envoy binary
# at $ENVOY_BIN (default $HOME/workspace/.envoy-binary).
set -euo pipefail

GWROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNDIR="$GWROOT/subscription001/run"
ENVOY_BIN="${ENVOY_BIN:-$HOME/workspace/.envoy-binary}"

export GATEWAY_CONFIG="$RUNDIR/config"
export GATEWAY_DB="$RUNDIR/state/demo.db"
export RUNDIR
export EVIDIR="$RUNDIR/evidence/$(date +%Y%m%d-%H%M%S)"
export PYTHONPATH="$GWROOT:${PYTHONPATH:-}"

# Deterministic run: fresh key, policy, and empty DB every time.
# Evidence from prior runs is kept (timestamped); config/state/logs reset.
rm -rf "$RUNDIR/config" "$RUNDIR/state" "$RUNDIR/logs"
mkdir -p "$EVIDIR" "$RUNDIR/logs"

for p in 8080 9000 9001 50051 50053 9901; do
  if (echo >/dev/tcp/127.0.0.1/$p) 2>/dev/null; then
    echo "port $p is occupied — stop the other stack first" >&2
    exit 2
  fi
done

[ -x "$ENVOY_BIN" ] || { echo "Envoy binary not found: $ENVOY_BIN" >&2; exit 2; }

echo "== init: receiver key + policy + empty demo DB"
python3 "$GWROOT/gateway_admin.py" init >/dev/null

PIDS=()
teardown() {
  echo "== teardown"
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap teardown EXIT

echo "== start: authz :50051 (+standing :50053)"
GATEWAY_STANDING_PORT=50053 \
  setsid python3 "$GWROOT/authz_server.py" 50051 \
  >"$RUNDIR/logs/authz.log" 2>&1 < /dev/null & PIDS+=($!)

echo "== start: payment API :9000 (standing check ON — demo configuration)"
GATEWAY_STANDING_CHECK=1 MOCK_API_PORT=9000 \
  setsid python3 "$GWROOT/mock_api.py" \
  >"$RUNDIR/logs/api.log" 2>&1 < /dev/null & PIDS+=($!)

echo "== start: payment API :9001 (standing check OFF — honest contrast)"
MOCK_API_PORT=9001 \
  setsid python3 "$GWROOT/mock_api.py" \
  >"$RUNDIR/logs/api-nocheck.log" 2>&1 < /dev/null & PIDS+=($!)

sleep 2
echo "== start: Envoy :8080"
setsid "$ENVOY_BIN" -c "$GWROOT/envoy/envoy-openline.yaml" \
  >"$RUNDIR/logs/envoy.log" 2>&1 < /dev/null & PIDS+=($!)

echo "== wait for health"
for i in $(seq 1 30); do
  if curl -s -m 2 http://127.0.0.1:8080/health >/dev/null \
     && curl -s -m 2 http://127.0.0.1:9000/health >/dev/null \
     && curl -s -m 2 http://127.0.0.1:9001/health >/dev/null; then
    break
  fi
  sleep 1
  [ "$i" = 30 ] && { echo "stack failed to come up; see $RUNDIR/logs" >&2; exit 3; }
done

echo "== run the demonstration"
python3 "$GWROOT/subscription001/demo.py"
rc=$?

echo
echo "== evidence: $EVIDIR"
ls "$EVIDIR"
exit $rc
