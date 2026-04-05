#!/bin/bash
# MASSAT Full Flow: Audit -> Subscribe -> Onboard -> Passport
# Usage: bash examples/curl/full-flow.sh https://github.com/your-org/your-repo

REPO=${1:-"https://github.com/octocat/Hello-World"}
API="https://craigmbrown.com/api"

echo "=== MASSAT Full Onboarding Flow ==="
echo "Repo: $REPO"
echo ""

# Step 1: Run audit
echo "--- Step 1: Security Audit ---"
AUDIT_RESULT=$(curl -s -X POST "$API/audit" \
  -H "Content-Type: application/json" \
  -d "{\"repo\": \"$REPO\"}")

AUDIT_ID=$(echo "$AUDIT_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['audit_id'])" 2>/dev/null)
RISK_SCORE=$(echo "$AUDIT_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['risk_score'])" 2>/dev/null)
REPORT_URL=$(echo "$AUDIT_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['report_url'])" 2>/dev/null)

echo "Audit ID: $AUDIT_ID"
echo "Risk Score: $RISK_SCORE"
echo "Report: $REPORT_URL"
echo ""

# Step 2: Subscribe for updates
echo "--- Step 2: Subscribe ---"
curl -s -X POST "$API/subscribe" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "company": "Test Corp", "source": "curl_example"}' | python3 -m json.tool
echo ""

# Step 3: Get full report
echo "--- Step 3: Full Report ---"
curl -s "$API/audit/$AUDIT_ID" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'Categories: {len(d.get(\"categories_assessed\", []))}')
for f in d.get('findings', [])[:5]:
    print(f'  [{f[\"severity\"]}] {f[\"category\"]}: {f.get(\"title\", \"\")}')
total = len(d.get('findings', []))
if total > 5: print(f'  ... +{total-5} more')
"
echo ""

# Step 4: Onboard for passport
echo "--- Step 4: Request Passport ---"
curl -s "$API/onboard?audit_id=$AUDIT_ID&agent_name=my-agent&operator_email=test@example.com" | python3 -m json.tool
echo ""

echo "=== Flow Complete ==="
