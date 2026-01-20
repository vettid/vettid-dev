#!/bin/bash
set -euo pipefail

# trigger-warmup-verification.sh
# Triggers warmup verification in the NEW enclave fleet.
# This verifies that migrated sealed material can be unsealed.
#
# Usage:
#   ./trigger-warmup-verification.sh --environment staging

ENVIRONMENT=""

# Lambda function names by environment
declare -A VERIFICATION_LAMBDA=(
    ["staging"]="vettid-enclave-verification-staging"
    ["production"]="vettid-enclave-verification-prod"
)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 --environment <staging|production>"
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

if [[ ! -v "VERIFICATION_LAMBDA[$ENVIRONMENT]" ]]; then
    echo "Error: Unknown environment: $ENVIRONMENT"
    exit 1
fi

LAMBDA_NAME="${VERIFICATION_LAMBDA[$ENVIRONMENT]}"

echo "=== Triggering Warmup Verification ==="
echo "Environment: $ENVIRONMENT"
echo "Lambda: $LAMBDA_NAME"
echo ""

# Create payload
PAYLOAD='{"action": "verify_all"}'

echo "Invoking verification Lambda..."

# Invoke Lambda
RESPONSE=$(aws lambda invoke \
    --function-name "$LAMBDA_NAME" \
    --payload "$(echo "$PAYLOAD" | base64)" \
    --cli-binary-format raw-in-base64-out \
    /tmp/verification-response.json \
    --query 'StatusCode' \
    --output text)

if [[ "$RESPONSE" != "200" ]]; then
    echo "Error: Lambda invocation failed with status $RESPONSE"
    cat /tmp/verification-response.json
    exit 1
fi

# Parse response
RESULT=$(cat /tmp/verification-response.json)
echo "Response: $RESULT"

# Check results
STATUS=$(echo "$RESULT" | jq -r '.status // "unknown"')
VERIFIED=$(echo "$RESULT" | jq -r '.verified // 0')
FAILED=$(echo "$RESULT" | jq -r '.failed // 0')
TOTAL=$(echo "$RESULT" | jq -r '.total // 0')

echo ""
echo "=== Verification Results ==="
echo "Status: $STATUS"
echo "Total users: $TOTAL"
echo "Verified: $VERIFIED"
echo "Failed: $FAILED"

if [[ "$STATUS" != "complete" ]] || [[ "$FAILED" -gt 0 ]]; then
    echo ""
    echo "Warning: Verification had issues"
    if [[ "$FAILED" -gt 0 ]]; then
        echo "Failed users:"
        echo "$RESULT" | jq -r '.failed_users[]? // empty'
    fi
    exit 1
fi

echo ""
echo "=== Warmup Verification Successful ==="
