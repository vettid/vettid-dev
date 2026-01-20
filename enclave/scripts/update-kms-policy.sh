#!/bin/bash
set -euo pipefail

# update-kms-policy.sh
# Add or remove PCR values from KMS key policy for enclave attestation.
#
# Usage:
#   ./update-kms-policy.sh --environment staging --add-pcrs "pcr0,pcr1,pcr2"
#   ./update-kms-policy.sh --environment production --remove-old-pcrs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVIRONMENT=""
ADD_PCRS=""
REMOVE_OLD=false

# KMS key aliases by environment
declare -A KMS_KEY_ALIAS=(
    ["staging"]="alias/vettid-enclave-staging"
    ["production"]="alias/vettid-enclave-prod"
)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --add-pcrs)
            ADD_PCRS="$2"
            shift 2
            ;;
        --remove-old-pcrs)
            REMOVE_OLD=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 --environment <staging|production> [--add-pcrs <pcrs>] [--remove-old-pcrs]"
            echo ""
            echo "Options:"
            echo "  --environment     Target environment (staging or production)"
            echo "  --add-pcrs        Comma-separated PCR values to add (pcr0,pcr1,pcr2)"
            echo "  --remove-old-pcrs Remove PCRs that are no longer in use"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate environment
if [[ -z "$ENVIRONMENT" ]]; then
    echo "Error: --environment is required"
    exit 1
fi

if [[ ! -v "KMS_KEY_ALIAS[$ENVIRONMENT]" ]]; then
    echo "Error: Unknown environment: $ENVIRONMENT"
    exit 1
fi

KEY_ALIAS="${KMS_KEY_ALIAS[$ENVIRONMENT]}"

echo "=== KMS Policy Update ==="
echo "Environment: $ENVIRONMENT"
echo "KMS Key: $KEY_ALIAS"

# Get current key ID from alias
KEY_ID=$(aws kms describe-key --key-id "$KEY_ALIAS" --query 'KeyMetadata.KeyId' --output text)
if [[ -z "$KEY_ID" ]]; then
    echo "Error: Could not find KMS key for alias: $KEY_ALIAS"
    exit 1
fi
echo "Key ID: $KEY_ID"

# Get current policy
echo "Fetching current policy..."
CURRENT_POLICY=$(aws kms get-key-policy --key-id "$KEY_ID" --policy-name default --query Policy --output text)

# Function to add PCRs to policy
add_pcrs_to_policy() {
    local pcrs="$1"
    local policy="$2"

    # Parse PCRs
    IFS=',' read -ra PCR_ARRAY <<< "$pcrs"
    if [[ ${#PCR_ARRAY[@]} -ne 3 ]]; then
        echo "Error: Expected exactly 3 PCR values (pcr0,pcr1,pcr2)"
        exit 1
    fi

    local pcr0="${PCR_ARRAY[0]}"
    local pcr1="${PCR_ARRAY[1]}"
    local pcr2="${PCR_ARRAY[2]}"

    echo "Adding PCRs:"
    echo "  PCR0: ${pcr0:0:16}..."
    echo "  PCR1: ${pcr1:0:16}..."
    echo "  PCR2: ${pcr2:0:16}..."

    # Create new attestation condition
    local new_condition=$(cat <<EOF
{
    "StringEqualsIgnoreCase": {
        "kms:RecipientAttestation:PCR0": "$pcr0",
        "kms:RecipientAttestation:PCR1": "$pcr1",
        "kms:RecipientAttestation:PCR2": "$pcr2"
    }
}
EOF
)

    # Add the new condition to existing conditions using jq
    # The policy allows attestation if ANY of the condition sets match (AnyOf pattern)
    echo "$policy" | jq --argjson new_cond "$new_condition" '
        .Statement |= map(
            if .Sid == "AllowEnclaveDecrypt" then
                .Condition.AnyOf += [$new_cond]
            else
                .
            end
        )
    '
}

# Function to remove old PCRs (keep only the latest)
remove_old_pcrs_from_policy() {
    local policy="$1"

    # Keep only the last (most recent) condition set
    echo "$policy" | jq '
        .Statement |= map(
            if .Sid == "AllowEnclaveDecrypt" and (.Condition.AnyOf | length) > 1 then
                .Condition.AnyOf = [.Condition.AnyOf[-1]]
            else
                .
            end
        )
    '
}

# Apply changes
if [[ -n "$ADD_PCRS" ]]; then
    echo ""
    echo "Adding new PCRs to policy..."
    UPDATED_POLICY=$(add_pcrs_to_policy "$ADD_PCRS" "$CURRENT_POLICY")

    # Apply the updated policy
    aws kms put-key-policy \
        --key-id "$KEY_ID" \
        --policy-name default \
        --policy "$UPDATED_POLICY"

    echo "Policy updated successfully with new PCRs"
fi

if [[ "$REMOVE_OLD" == true ]]; then
    echo ""
    echo "Removing old PCRs from policy..."

    # Re-fetch policy in case it was just updated
    CURRENT_POLICY=$(aws kms get-key-policy --key-id "$KEY_ID" --policy-name default --query Policy --output text)
    UPDATED_POLICY=$(remove_old_pcrs_from_policy "$CURRENT_POLICY")

    # Count conditions before and after
    BEFORE=$(echo "$CURRENT_POLICY" | jq '[.Statement[] | select(.Sid == "AllowEnclaveDecrypt")] | .[0].Condition.AnyOf | length')
    AFTER=$(echo "$UPDATED_POLICY" | jq '[.Statement[] | select(.Sid == "AllowEnclaveDecrypt")] | .[0].Condition.AnyOf | length')

    if [[ "$BEFORE" != "$AFTER" ]]; then
        aws kms put-key-policy \
            --key-id "$KEY_ID" \
            --policy-name default \
            --policy "$UPDATED_POLICY"

        echo "Removed $((BEFORE - AFTER)) old PCR condition(s)"
    else
        echo "No old PCRs to remove (only 1 condition exists)"
    fi
fi

echo ""
echo "=== KMS Policy Update Complete ==="
