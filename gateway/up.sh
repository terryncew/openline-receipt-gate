#!/bin/bash
# Start the full gateway stack: authz service, mock API, Envoy.
# Usage: ./up.sh  (from the gateway/ directory)
set -e
cd "$(dirname "$0")"
export GATEWAY_CONFIG="${GATEWAY_CONFIG:-$PWD/config}"
export GATEWAY_DB="${GATEWAY_DB:-$PWD/state/gateway.db}"
export PYTHONPATH="$PWD:${PYTHONPATH:-}"
ENVOY_BIN="${ENVOY_BIN:-$HOME/workspace/.envoy-binary}"

./down.sh 2>/dev/null || true
sleep 1

[ -f "$GATEWAY_CONFIG/receiver.key" ] || python3 gateway_admin.py init

(setsid python3 authz_server.py 50051 > /tmp/gw-authz.log 2>&1 < /dev/null & echo $! > /tmp/gw-authz.pid)
(setsid python3 mock_api.py > /tmp/gw-api.log 2>&1 < /dev/null & echo $! > /tmp/gw-api.pid)
sleep 2
(setsid "$ENVOY_BIN" -c "$PWD/envoy/envoy-openline.yaml" > /tmp/gw-envoy.log 2>&1 < /dev/null & echo $! > /tmp/gw-envoy.pid)
sleep 3

echo "authz: $(cat /tmp/gw-authz.pid)  api: $(cat /tmp/gw-api.pid)  envoy: $(cat /tmp/gw-envoy.pid)"
curl -s -m 5 http://127.0.0.1:8080/health && echo " <- envoy ok"
