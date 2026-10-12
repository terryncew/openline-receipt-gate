#!/bin/bash
# TEMPORARY: Upstream stall isolation trigger
# Branch: temp/stall-isolation-001 (DO NOT MERGE)
# Purpose: Reproduce the post-full-restart Envoy upstream stall
#          for balance reads. Root cause unisolated.
#
# This script is BOUNDED:
# - Runs only on this temp branch
# - Does not modify the frozen baseline (experiment/gateway-subscription-001)
# - Will be deleted after the isolation run
#
# To run (requires Docker, GHA recommended):
#   bash ./trigger-stall-isolation.sh
#
# Expected: Balance reads via Envoy timeout after `docker compose restart`.
# The script captures logs, timing, and Envoy config for analysis.

set -e

echo "=== Upstream Stall Isolation Trigger ==="
echo "Branch: $(git branch --show-current)"
echo "This is a TEMPORARY branch. Do not merge."
echo ""

# Verify we're on the temp branch
if [ "$(git branch --show-current)" != "temp/stall-isolation-001" ]; then
    echo "ERROR: Must run on temp/stall-isolation-001"
    exit 1
fi

# Verify Docker is available
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker not available. Run on GHA."
    exit 1
fi

echo "[1/4] Starting full stack..."
docker compose up -d
sleep 10

echo "[2/4] Baseline: balance read via Envoy (should work)..."
curl -s -m 5 http://localhost:8080/balance || echo "BASELINE FAILED"

echo "[3/4] Full-stack restart..."
docker compose restart
sleep 15

echo "[4/4] Post-restart: balance read via Envoy (stall reproduces here)..."
echo "Timing the request (timeout 10s)..."
time curl -s -m 10 http://localhost:8080/balance || echo "STALL REPRODUCED (timeout)"

echo ""
echo "=== Capturing diagnostics ==="
docker compose logs envoy > /tmp/stall-envoy.log 2>&1 || true
docker compose logs authz > /tmp/stall-authz.log 2>&1 || true
echo "Logs saved to /tmp/stall-*.log"

echo ""
echo "=== Done ==="
echo "Analyze /tmp/stall-envoy.log for upstream connection errors."
echo "Delete this branch after analysis: git branch -D temp/stall-isolation-001"
