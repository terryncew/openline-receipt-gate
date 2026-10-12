#!/bin/bash
# TEMPORARY: Upstream stall isolation diagnostic
# Branch: temp/stall-isolation-001 (DO NOT MERGE)
#
# Reproduces the post-full-restart Envoy upstream stall for balance reads.
# Requires a HEALTHY baseline before restart. Distinguishes:
#   - Timeout (stall reproduced)
#   - Connection refused (Envoy not listening)
#   - HTTP error (5xx, 4xx)
#   - Malformed response (not JSON, missing fields)
#
# Usage: bash ./trigger-stall-isolation.sh
# Output: /tmp/stall-*.log, /tmp/stall-results.json

set -e

COMPOSE_DIR="gateway/compose"
RESULTS="/tmp/stall-results.json"

echo "=== Upstream Stall Isolation Diagnostic ==="
echo "Branch: $(git branch --show-current)"
echo "Compose: $COMPOSE_DIR/docker-compose.yml"
echo ""

if [ "$(git branch --show-current)" != "temp/stall-isolation-001" ]; then
    echo "ERROR: Must run on temp/stall-isolation-001"
    exit 1
fi

cd "$COMPOSE_DIR"

# Helper: test balance endpoint, classify the result
test_balance() {
    local label="$1"
    local url="http://localhost:8080/balance/treasury"
    local start=$(date +%s.%N)
    
    # Use curl with explicit timeout, capture HTTP code and body
    local output
    output=$(curl -s -m 10 -w "\n%{http_code}\n%{time_total}" "$url" 2>&1 || echo "CURL_FAILED")
    
    local end=$(date +%s.%N)
    local elapsed=$(echo "$end - $start" | bc -l 2>/dev/null || echo "unknown")
    
    # Parse output
    local http_code=$(echo "$output" | tail -2 | head -1)
    local time_total=$(echo "$output" | tail -1)
    local body=$(echo "$output" | head -n -2)
    
    # Classify
    local classification="UNKNOWN"
    if [ "$output" = "CURL_FAILED" ]; then
        classification="CONNECTION_REFUSED"
    elif [ "$http_code" = "000" ]; then
        classification="TIMEOUT"
    elif [ "$http_code" -ge 500 ] 2>/dev/null; then
        classification="HTTP_5XX"
    elif [ "$http_code" -ge 400 ] 2>/dev/null; then
        classification="HTTP_4XX"
    elif [ "$http_code" = "200" ]; then
        # Check if body is valid JSON with expected fields
        if echo "$body" | python3 -c "import json,sys; d=json.load(sys.stdin); assert 'treasury' in str(d) or 'balance' in str(d)" 2>/dev/null; then
            classification="HEALTHY"
        else
            classification="MALFORMED_RESPONSE"
        fi
    fi
    
    echo "{\"label\": \"$label\", \"classification\": \"$classification\", \"http_code\": \"$http_code\", \"time_total\": \"$time_total\", \"elapsed\": \"$elapsed\"}"
}

echo "[1/5] Starting full stack (openline profile)..."
docker compose --profile openline up -d --build
sleep 15

echo "[2/5] Baseline: balance read via Envoy..."
BASELINE=$(test_balance "baseline")
echo "$BASELINE"
BASELINE_CLASS=$(echo "$BASELINE" | python3 -c "import json,sys; print(json.load(sys.stdin)['classification'])")

if [ "$BASELINE_CLASS" != "HEALTHY" ]; then
    echo ""
    echo "FAIL: Baseline is not healthy ($BASELINE_CLASS). Cannot proceed."
    echo "The stall test requires a working baseline. Aborting."
    echo "$BASELINE" > "$RESULTS"
    exit 1
fi
echo "Baseline HEALTHY. Proceeding."

echo "[3/5] Full-stack restart..."
docker compose --profile openline restart
sleep 20

echo "[4/5] Post-restart: balance read via Envoy..."
POST=$(test_balance "post_restart")
echo "$POST"
POST_CLASS=$(echo "$POST" | python3 -c "import json,sys; print(json.load(sys.stdin)['classification'])")

echo "[5/5] Capturing diagnostics..."
docker compose --profile openline ps > /tmp/stall-ps.log 2>&1 || true
docker compose --profile openline logs envoy > /tmp/stall-envoy.log 2>&1 || true
docker compose --profile openline logs authz > /tmp/stall-authz.log 2>&1 || true
docker compose --profile openline logs mockapi > /tmp/stall-mockapi.log 2>&1 || true
cp envoy-openline-compose.yaml /tmp/stall-envoy-config.yaml 2>/dev/null || true

# Write results
cat > "$RESULTS" <<EOF
{
  "baseline": $BASELINE,
  "post_restart": $POST,
  "verdict": "$([ "$POST_CLASS" = "TIMEOUT" ] && echo "STALL_REPRODUCED" || echo "NO_STALL")",
  "post_classification": "$POST_CLASS"
}
EOF

echo ""
echo "=== Results ==="
cat "$RESULTS"
echo ""
echo "Diagnostics: /tmp/stall-*.log, /tmp/stall-envoy-config.yaml"

if [ "$POST_CLASS" = "TIMEOUT" ]; then
    echo "VERDICT: STALL REPRODUCED (timeout with healthy baseline)"
    exit 0
else
    echo "VERDICT: NO STALL (post-restart: $POST_CLASS)"
    exit 0
fi
