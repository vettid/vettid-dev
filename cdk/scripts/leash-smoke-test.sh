#!/usr/bin/env bash
# Smoke test for the public LEASH endpoints. Runs after a deploy lands.
#
# - GET /v1/public/leash/keys/{user_guid} — expect 404 for an unknown user
# - GET /v1/public/leash/status/{jti}     — expect 404 (treated as revoked) for unknown jti
# - POST /v1/public/leash/verify          — expect a 200 with rejection_reason "malformed"
#                                           when given garbage (proves the route is wired).
#
# A full mint→verify round-trip needs Sprint 4's agent CLI (issues a real
# leash from the vault). This script only proves the public routes are
# alive and shaped correctly.

set -euo pipefail

API="${API_URL:-https://api.vettid.dev}"
FAKE_USER="smoke-test-nobody-$(date +%s)"
FAKE_JTI="leash-smoke-$(date +%s)"

echo "API base: $API"
echo

echo "1. GET /v1/public/leash/keys/{user_guid}  (expect 404)"
RESP=$(curl -sS -w "\n%{http_code}" "$API/v1/public/leash/keys/$FAKE_USER")
CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | head -n -1)
echo "  → HTTP $CODE: $BODY"
[ "$CODE" = "404" ] || { echo "  FAIL: expected 404"; exit 1; }
echo

echo "2. GET /v1/public/leash/status/{jti}  (expect 404 with revoked=true)"
RESP=$(curl -sS -w "\n%{http_code}" "$API/v1/public/leash/status/$FAKE_JTI")
CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | head -n -1)
echo "  → HTTP $CODE: $BODY"
[ "$CODE" = "404" ] || { echo "  FAIL: expected 404"; exit 1; }
echo "$BODY" | grep -q '"revoked":true' || { echo "  FAIL: body must contain revoked:true"; exit 1; }
echo

echo "3. POST /v1/public/leash/verify  (garbage input → 200 with rejection)"
RESP=$(curl -sS -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d '{"leash":"not.a.real.jwt","request":{"action":"x:y"},"nonce":"abcd","timestamp":1,"agent_sig":"e30="}' \
  "$API/v1/public/leash/verify")
CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | head -n -1)
echo "  → HTTP $CODE: $BODY"
[ "$CODE" = "200" ] || { echo "  FAIL: expected 200"; exit 1; }
echo "$BODY" | grep -q '"verified":false' || { echo "  FAIL: body must contain verified:false"; exit 1; }
echo

echo "All three public LEASH routes are alive."
echo
echo "Full mint→verify round-trip needs Sprint 4 (agent CLI). Until then,"
echo "an end-to-end test requires running the vault op directly, e.g."
echo "via tests/integration/leash or an exec inside the enclave."
