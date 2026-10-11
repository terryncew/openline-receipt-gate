#!/bin/sh
# Gateway service entrypoint (Docker Compose).
#
# Problem: the `gateway-config` named volume starts EMPTY, but
# authz_server.py and mock_api.py require receiver.key + policy.json in
# GATEWAY_CONFIG at startup and crash with FileNotFoundError otherwise.
#
# Fix: on container start, if the receiver config is absent, run
# `gateway_admin.py init` (idempotent) before exec'ing the service.
# A mkdir-based lock makes init atomic when authz and mockapi boot
# concurrently against the same fresh volume; the loser waits for the
# key/policy files to appear instead of racing init.
set -e
CFG="${GATEWAY_CONFIG:-/config}"
ADMIN="${GATEWAY_ADMIN_PY:-/app/gateway/gateway_admin.py}"
mkdir -p "$CFG"

if [ -f "$CFG/receiver.key" ] && [ -f "$CFG/policy.json" ]; then
  echo "[entrypoint] receiver config present in $CFG, skipping init"
else
  if mkdir "$CFG/.init-lock" 2>/dev/null; then
    echo "[entrypoint] initializing receiver config in $CFG"
    python3 "$ADMIN" init
    rmdir "$CFG/.init-lock"
  else
    echo "[entrypoint] init in progress by peer; waiting for config"
    for i in $(seq 1 60); do
      if [ -f "$CFG/receiver.key" ] && [ -f "$CFG/policy.json" ]; then
        break
      fi
      sleep 1
    done
  fi
fi

echo "[entrypoint] exec: $*"
if [ $# -eq 0 ]; then
  echo "[entrypoint] ERROR: no command to exec (empty CMD)" >&2
  exit 1
fi
exec "$@"
