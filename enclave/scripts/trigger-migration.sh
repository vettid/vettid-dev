#!/bin/bash
set -euo pipefail

# trigger-migration.sh
# Triggers sealed material migration in the OLD enclave fleet.
# This causes the old enclave to re-seal user DEKs for the new PCR values.
#
# Usage:
#   ./trigger-migration.sh --environment staging --target-pcrs "pcr0,pcr1,pcr2"

ENVIRONMENT=""
TARGET_PCRS=""

# Lambda function names by environment
declare -A MIGRATION_LAMBDA=(
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
        --target-pcrs)
            TARGET_PCRS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 --environment <staging|production> --target-pcrs <pcr0,pcr1,pcr2>"
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

if [[ -z "$TARGET_PCRS" ]]; then
    echo "Error: --target-pcrs is required"
    exit 1
fi

if [[ ! -v "MIGRATION_LAMBDA[$ENVIRONMENT]" ]]; then
    echo "Error: Unknown environment: $ENVIRONMENT"
    exit 1
fi

LAMBDA_NAME="${MIGRATION_LAMBDA[$ENVIRONMENT]}"

echo "=== Triggering Migration ==="
echo "Environment: $ENVIRONMENT"
echo "Lambda: $LAMBDA_NAME"
echo "Target PCRs: ${TARGET_PCRS:0:50}..."

# Parse PCRs
IFS=',' read -ra PCR_ARRAY <<< "$TARGET_PCRS"
if [[ ${#PCR_ARRAY[@]} -ne 3 ]]; then
    echo "Error: Expected exactly 3 PCR values"
    exit 1
fi

# Create payload
PAYLOAD=$(cat <<EOF
{
    "action": "start_migration",
    "target_pcrs": {
        "pcr0": "${PCR_ARRAY[0]}",
        "pcr1": "${PCR_ARRAY[1]}",
        "pcr2": "${PCR_ARRAY[2]}"
    }
}
EOF
)

echo ""
echo "Invoking migration Lambda..."

# Invoke Lambda
RESPONSE=$(aws lambda invoke \
    --function-name "$LAMBDA_NAME" \
    --payload "$(echo "$PAYLOAD" | base64)" \
    --cli-binary-format raw-in-base64-out \
    /tmp/migration-response.json \
    --query 'StatusCode' \
    --output text)

if [[ "$RESPONSE" != "200" ]]; then
    echo "Error: Lambda invocation failed with status $RESPONSE"
    cat /tmp/migration-response.json
    exit 1
fi

# Parse response
RESULT=$(cat /tmp/migration-response.json)
echo "Response: $RESULT"

# Check for errors in response
if echo "$RESULT" | jq -e '.error' > /dev/null 2>&1; then
    echo "Error: $(echo "$RESULT" | jq -r '.error')"
    exit 1
fi

MIGRATION_ID=$(echo "$RESULT" | jq -r '.migration_id // "unknown"')
echo ""
echo "Migration started successfully"
echo "Migration ID: $MIGRATION_ID"
echo ""
echo "=== Migration Triggered ==="
