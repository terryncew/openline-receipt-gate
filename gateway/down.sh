#!/bin/bash
# Stop the gateway stack.
for f in /tmp/gw-authz.pid /tmp/gw-api.pid /tmp/gw-envoy.pid; do
  [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true
done
# fallback: kill by port owner
for port in 50051 9000; do
  pid=$(ss -tlnp 2>/dev/null | grep ":$port " | grep -oP 'pid=\K[0-9]+' | head -1)
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
done
echo "stack stopped"
