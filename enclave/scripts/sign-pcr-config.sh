#!/bin/bash
set -euo pipefail

# sign-pcr-config.sh
# Signs a PCR migration config using AWS KMS (ECDSA P-256).
# Uses the same PCR signing key as the PCR manifest (vettid-pcr-signing).
#
# Usage:
#   ./sign-pcr-config.sh pcr-config.json > signed-config.json
#
# The signing key ID is fetched from CDK stack outputs automatically.

REGION="${AWS_REGION:-us-east-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <config.json>" >&2
    exit 1
fi

CONFIG_FILE="$1"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Config file not found: $CONFIG_FILE" >&2
    exit 1
fi

# Get signing key ID from CDK stack outputs or SSM
KEY_ID=$(aws ssm get-parameter --name "/vettid/attestation/pcr-signing-key-id" \
    --query 'Parameter.Value' --output text --region "$REGION" 2>/dev/null || echo "")

if [[ -z "$KEY_ID" ]]; then
    # Fallback: try CDK stack outputs
    KEY_ID=$(aws cloudformation describe-stacks --stack-name VettID-Nitro \
        --query 'Stacks[0].Outputs[?OutputKey==`PcrSigningKeyId`].OutputValue' \
        --output text --region "$REGION" 2>/dev/null || echo "")
fi

if [[ -z "$KEY_ID" ]]; then
    echo "Error: Could not find PCR signing key ID from SSM or CDK outputs" >&2
    exit 1
fi

echo "Using KMS key: $KEY_ID" >&2

# Read the config
CONFIG=$(cat "$CONFIG_FILE")

# Validate config has required fields
for field in new_pcrs valid_from version; do
    if ! echo "$CONFIG" | jq -e ".$field" > /dev/null 2>&1; then
        echo "Error: Config missing required field: $field" >&2
        exit 1
    fi
done

# Create canonical JSON for signing.
#
# CRITICAL: must produce byte-for-byte the same output as the
# verifier's signedPayload() in enclave/migration/pcr_config.go. The
# verifier:
#   1. Sorts keys (we use jq -cS).
#   2. Drops the signature field (`del(.signature)`).
#   3. OMITS optional fields when their value is empty/zero — summary,
#      details_url, expires_at, published_at, mandatory_after.
#
# Step 3 is the subtle one. If the input JSON has `"details_url": ""`,
# the signer's canonical bytes contain that empty key but the
# verifier's don't — every signature fails ECDSA verify and migration
# silently no-ops. Surfaced 2026-05-26 deploying the security-review
# fixes (operator-generated config with `details_url: ""` produced an
# unverifiable signature).
#
# Fix: drop top-level keys whose value is `""` before sorting. We use
# `with_entries(select(.value != ""))` to skip empty-string fields;
# non-string values (objects, arrays) are kept as-is.
CANONICAL=$(echo "$CONFIG" | jq -cS 'del(.signature) | with_entries(select(.value != ""))')

# Hash the canonical JSON with SHA-256
HASH=$(echo -n "$CANONICAL" | openssl dgst -sha256 -binary | base64 -w 0)

# Sign with KMS ECDSA P-256 (same algorithm as PCR manifest signing)
SIGNATURE=$(aws kms sign \
    --key-id "$KEY_ID" \
    --message "$HASH" \
    --message-type DIGEST \
    --signing-algorithm ECDSA_SHA_256 \
    --query 'Signature' \
    --output text \
    --region "$REGION")

if [[ -z "$SIGNATURE" ]]; then
    echo "Error: KMS signing failed" >&2
    exit 1
fi

echo "Config signed successfully with KMS ECDSA P-256" >&2

# Add signature to config and output
echo "$CONFIG" | jq --arg sig "$SIGNATURE" '. + {signature: $sig}'
