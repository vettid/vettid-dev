#!/bin/bash
# Validate PCR values match expected values
# Used to verify enclave image hasn't been tampered with

set -euo pipefail

EIF_FILE="${1:-vettid-vault-enclave.eif}"
EXPECTED_PCRS="${2:-expected-pcrs.json}"

if [[ ! -f "$EIF_FILE" ]]; then
    echo "Error: EIF file not found: $EIF_FILE"
    exit 1
fi

if [[ ! -f "$EXPECTED_PCRS" ]]; then
    echo "Warning: No expected PCRs file found at $EXPECTED_PCRS"
    echo "Extracting PCRs from EIF..."
    nitro-cli describe-eif --eif-path "$EIF_FILE"
    exit 0
fi

echo "=== Validating PCR Values ==="
echo "EIF: $EIF_FILE"
echo "Expected: $EXPECTED_PCRS"
echo ""

# Extract actual PCRs
ACTUAL_PCRS=$(nitro-cli describe-eif --eif-path "$EIF_FILE")

# Compare PCR0 (enclave image)
ACTUAL_PCR0=$(echo "$ACTUAL_PCRS" | jq -r '.PCR0')
EXPECTED_PCR0=$(jq -r '.pcr0' "$EXPECTED_PCRS")

echo "PCR0 (Enclave Image):"
echo "  Expected: $EXPECTED_PCR0"
echo "  Actual:   $ACTUAL_PCR0"

if [[ "$ACTUAL_PCR0" != "$EXPECTED_PCR0" ]]; then
    echo "  MISMATCH!"
    MISMATCH=true
else
    echo "  OK"
fi

# Compare PCR1 (kernel)
ACTUAL_PCR1=$(echo "$ACTUAL_PCRS" | jq -r '.PCR1')
EXPECTED_PCR1=$(jq -r '.pcr1' "$EXPECTED_PCRS")

echo ""
echo "PCR1 (Kernel):"
echo "  Expected: $EXPECTED_PCR1"
echo "  Actual:   $ACTUAL_PCR1"

if [[ "$ACTUAL_PCR1" != "$EXPECTED_PCR1" ]]; then
    echo "  MISMATCH!"
    MISMATCH=true
else
    echo "  OK"
fi

# Compare PCR2 (application)
ACTUAL_PCR2=$(echo "$ACTUAL_PCRS" | jq -r '.PCR2')
EXPECTED_PCR2=$(jq -r '.pcr2' "$EXPECTED_PCRS")

echo ""
echo "PCR2 (Application):"
echo "  Expected: $EXPECTED_PCR2"
echo "  Actual:   $ACTUAL_PCR2"

if [[ "$ACTUAL_PCR2" != "$EXPECTED_PCR2" ]]; then
    echo "  MISMATCH!"
    MISMATCH=true
else
    echo "  OK"
fi

echo ""
if [[ "${MISMATCH:-false}" == "true" ]]; then
    echo "VALIDATION FAILED: PCR values do not match expected values"
    echo "This could indicate:"
    echo "  - Code changes since PCRs were generated"
    echo "  - Build environment differences"
    echo "  - Potential tampering"
    exit 1
else
    echo "VALIDATION PASSED: All PCR values match"
fi
