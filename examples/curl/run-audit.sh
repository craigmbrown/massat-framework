#!/bin/bash
# MASSAT Audit API - curl examples
# Usage: bash examples/curl/run-audit.sh

API="https://craigmbrown.com/api"

echo "=== 1. Health Check ==="
curl -s "$API/audit/health" | python3 -m json.tool
echo ""

echo "=== 2. Run Audit (GitHub repo) ==="
curl -s -X POST "$API/audit" \
  -H "Content-Type: application/json" \
  -d '{"repo": "https://github.com/octocat/Hello-World"}' | python3 -m json.tool
echo ""

echo "=== 3. Subscribe for Updates ==="
curl -s -X POST "$API/subscribe" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "company": "Test Corp"}' | python3 -m json.tool
echo ""

echo "=== Done ==="
