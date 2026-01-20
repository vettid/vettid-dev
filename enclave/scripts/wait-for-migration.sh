#!/bin/bash
set -euo pipefail

# wait-for-migration.sh
# Polls migration status until completion or timeout.
#
# Usage:
#   ./wait-for-migration.sh --environment staging --timeout 3600

ENVIRONMENT=""
TIMEOUT=3600  # Default 1 hour
POLL_INTERVAL=30  # Check every 30 seconds

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
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 --environment <staging|production> [--timeout <seconds>]"
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

echo "=== Waiting for Migration ==="
echo "Environment: $ENVIRONMENT"
echo "Timeout: ${TIMEOUT}s"
echo "Poll interval: ${POLL_INTERVAL}s"
echo ""

START_TIME=$(date +%s)
LAST_STATUS=""

while true; do
    # Check timeout
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))

    if [[ $ELAPSED -ge $TIMEOUT ]]; then
        echo ""
        echo "Error: Migration timed out after ${ELAPSED}s"
        exit 1
    fi

    # Query status
    PAYLOAD='{"action": "get_status"}'

    RESPONSE=$(aws lambda invoke \
        --function-name "$LAMBDA_NAME" \
        --payload "$(echo "$PAYLOAD" | base64)" \
        --cli-binary-format raw-in-base64-out \
        /tmp/migration-status.json \
        --query 'StatusCode' \
        --output text 2>/dev/null) || true

    if [[ "$RESPONSE" != "200" ]]; then
        echo "Warning: Status check failed, retrying..."
        sleep "$POLL_INTERVAL"
        continue
    fi

    RESULT=$(cat /tmp/migration-status.json)
    STATUS=$(echo "$RESULT" | jq -r '.status // "unknown"')
    MIGRATED=$(echo "$RESULT" | jq -r '.migrated_users // 0')
    TOTAL=$(echo "$RESULT" | jq -r '.total_users // 0')
    FAILED=$(echo "$RESULT" | jq -r '.failed_users // 0')

    # Only print if status changed
    if [[ "$STATUS" != "$LAST_STATUS" ]]; then
        echo ""
        echo "Status: $STATUS"
        echo "Progress: $MIGRATED / $TOTAL users (${FAILED} failed)"
        LAST_STATUS="$STATUS"
    else
        echo -n "."
    fi

    case "$STATUS" in
        "complete")
            echo ""
            echo ""
            echo "=== Migration Complete ==="
            echo "Total users: $TOTAL"
            echo "Migrated: $MIGRATED"
            echo "Failed: $FAILED"
            echo "Duration: ${ELAPSED}s"

            if [[ "$FAILED" -gt 0 ]]; then
                echo ""
                echo "Warning: $FAILED users failed migration"
                echo "Check logs for details"
            fi

            exit 0
            ;;
        "failed")
            echo ""
            echo ""
            echo "=== Migration Failed ==="
            ERROR=$(echo "$RESULT" | jq -r '.error // "Unknown error"')
            echo "Error: $ERROR"
            exit 1
            ;;
        "pending"|"in_progress")
            # Continue polling
            sleep "$POLL_INTERVAL"
            ;;
        *)
            echo ""
            echo "Warning: Unknown status: $STATUS"
            sleep "$POLL_INTERVAL"
            ;;
    esac
done
