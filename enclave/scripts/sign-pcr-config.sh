#!/bin/bash
set -euo pipefail

# sign-pcr-config.sh
# Signs a PCR configuration with an Ed25519 deployment key.
# The signature allows enclaves to verify the config is from a trusted source.
#
# Usage:
#   ./sign-pcr-config.sh pcr-config.json deploy-key.pem > signed-config.json
#
# Input format:
#   {
#     "new_pcrs": { "pcr0": "...", "pcr1": "...", "pcr2": "..." },
#     "old_pcrs": { "pcr0": "...", "pcr1": "...", "pcr2": "..." },
#     "valid_from": "2024-01-15T10:00:00Z",
#     "version": "20240115120000-abc1234"
#   }
#
# Output format adds "signature" field.

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <config.json> <private-key.pem>" >&2
    exit 1
fi

CONFIG_FILE="$1"
KEY_FILE="$2"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Config file not found: $CONFIG_FILE" >&2
    exit 1
fi

if [[ ! -f "$KEY_FILE" ]]; then
    echo "Error: Key file not found: $KEY_FILE" >&2
    exit 1
fi

# Read the config
CONFIG=$(cat "$CONFIG_FILE")

# Validate config has required fields
for field in new_pcrs valid_from version; do
    if ! echo "$CONFIG" | jq -e ".$field" > /dev/null 2>&1; then
        echo "Error: Config missing required field: $field" >&2
        exit 1
    fi
done

# Create canonical JSON for signing (sorted keys, no extra whitespace)
CANONICAL=$(echo "$CONFIG" | jq -cS 'del(.signature)')

# Sign with Ed25519
# Note: OpenSSL ed25519 signing requires the private key in PEM format
SIGNATURE=$(echo -n "$CANONICAL" | openssl pkeyutl -sign -inkey "$KEY_FILE" | base64 -w 0)

if [[ -z "$SIGNATURE" ]]; then
    echo "Error: Failed to generate signature" >&2
    exit 1
fi

# Add signature to config and output
echo "$CONFIG" | jq --arg sig "$SIGNATURE" '. + {signature: $sig}'
