#!/bin/bash
set -euo pipefail

# verify-migration-complete.sh
# Verifies that all users have been successfully migrated.
# Checks both migration status and warmup verification status.
#
# Usage:
#   ./verify-migration-complete.sh --environment staging

ENVIRONMENT=""
FAIL_THRESHOLD=0  # Maximum acceptable failures

# Lambda function names by environment
declare -A STATUS_LAMBDA=(
    ["staging"]="vettid-enclave-migration-staging"
    ["production"]="vettid-enclave-migration-prod"
)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --fail-threshold)
            FAIL_THRESHOLD="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 --environment <staging|production> [--fail-threshold <n>]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validation
if [[ -z "$ENVIRONMENT" ]]; then
    echo "Error: --environment is required"
    exit 1
fi

if [[ ! -v "STATUS_LAMBDA[$ENVIRONMENT]" ]]; then
    echo "Error: Unknown environment: $ENVIRONMENT"
    exit 1
fi

LAMBDA_NAME="${STATUS_LAMBDA[$ENVIRONMENT]}"

echo "=== Verifying Migration Complete ==="
echo "Environment: $ENVIRONMENT"
echo "Fail threshold: $FAIL_THRESHOLD"
echo ""

# Get migration status
PAYLOAD='{"action": "get_status"}'

RESPONSE=$(aws lambda invoke \
    --function-name "$LAMBDA_NAME" \
    --payload "$(echo "$PAYLOAD" | base64)" \
    --cli-binary-format raw-in-base64-out \
    /tmp/final-status.json \
    --query 'StatusCode' \
    --output text)

if [[ "$RESPONSE" != "200" ]]; then
    echo "Error: Status check failed with status $RESPONSE"
    cat /tmp/final-status.json
    exit 1
fi

RESULT=$(cat /tmp/final-status.json)

# Extract metrics
STATUS=$(echo "$RESULT" | jq -r '.status // "unknown"')
TOTAL=$(echo "$RESULT" | jq -r '.total_users // 0')
MIGRATED=$(echo "$RESULT" | jq -r '.migrated_users // 0')
VERIFIED=$(echo "$RESULT" | jq -r '.verified_users // 0')
FAILED=$(echo "$RESULT" | jq -r '.failed_users // 0')

echo "=== Migration Status ==="
echo "Status: $STATUS"
echo "Total users: $TOTAL"
echo "Migrated: $MIGRATED"
echo "Verified: $VERIFIED"
echo "Failed: $FAILED"
echo ""

# Validate status
if [[ "$STATUS" != "complete" ]]; then
    echo "Error: Migration status is '$STATUS', expected 'complete'"
    exit 1
fi

# Check migration count
if [[ "$MIGRATED" -ne "$TOTAL" ]] && [[ "$FAILED" -gt "$FAIL_THRESHOLD" ]]; then
    echo "Error: Not all users migrated and failures exceed threshold"
    echo "Missing: $((TOTAL - MIGRATED - FAILED)) users"
    exit 1
fi

# Check verification count
if [[ "$VERIFIED" -ne "$MIGRATED" ]]; then
    UNVERIFIED=$((MIGRATED - VERIFIED))
    echo "Warning: $UNVERIFIED users migrated but not verified"

    if [[ "$UNVERIFIED" -gt "$FAIL_THRESHOLD" ]]; then
        echo "Error: Unverified count exceeds threshold"
        exit 1
    fi
fi

# Check failures
if [[ "$FAILED" -gt "$FAIL_THRESHOLD" ]]; then
    echo "Error: $FAILED failed users exceeds threshold of $FAIL_THRESHOLD"
    echo ""
    echo "Failed users:"
    echo "$RESULT" | jq -r '.failed_details[]? | "  - \(.user_id): \(.error)"' 2>/dev/null || true
    exit 1
fi

# Calculate success rate
if [[ "$TOTAL" -gt 0 ]]; then
    SUCCESS_RATE=$(echo "scale=2; ($VERIFIED * 100) / $TOTAL" | bc)
    echo "Success rate: ${SUCCESS_RATE}%"
else
    echo "No users to migrate"
fi

echo ""
echo "=== Migration Verification Passed ==="
echo "Ready for traffic cutover"
