#!/bin/bash
# Verify PCR deployment across all sources:
# - AWS SSM Parameter Store (source of truth for production)
# - CloudFront PCR manifest (what mobile apps fetch)
# - Mobile app bundled fallbacks (offline/first-install fallback)
#
# Usage: ./verify-pcr-deployment.sh [options]
#
# Options:
#   --update-mobile    Show commands to update mobile bundled PCRs
#   --apply            Automatically update mobile bundled PCRs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# VETTID_ROOT is parent of vettid-dev (where vettid-android, vettid-ios etc. live)
# Script is at: vettid-dev/enclave/scripts/ so go up 3 levels to get to VettID/
VETTID_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

UPDATE_MOBILE=false
APPLY_UPDATES=false

for arg in "$@"; do
    case $arg in
        --update-mobile)
            UPDATE_MOBILE=true
            ;;
        --apply)
            APPLY_UPDATES=true
            ;;
    esac
done

echo "=== PCR Deployment Verification ==="
echo ""

# Get SSM values (source of truth)
echo "Fetching SSM Parameter Store values..."
SSM_PCR0=$(aws ssm get-parameter --name "/vettid/enclave/pcr/pcr0" --query "Parameter.Value" --output text 2>/dev/null || echo "NOT_FOUND")
SSM_PCR1=$(aws ssm get-parameter --name "/vettid/enclave/pcr/pcr1" --query "Parameter.Value" --output text 2>/dev/null || echo "NOT_FOUND")
SSM_PCR2=$(aws ssm get-parameter --name "/vettid/enclave/pcr/pcr2" --query "Parameter.Value" --output text 2>/dev/null || echo "NOT_FOUND")

if [[ "$SSM_PCR0" == "NOT_FOUND" ]]; then
    echo -e "${RED}ERROR: Could not fetch PCR values from SSM${NC}"
    echo "Make sure you have AWS credentials configured."
    exit 1
fi

# Get manifest values from CloudFront
echo "Fetching PCR manifest from CloudFront..."
MANIFEST=$(curl -sf https://pcr-manifest.vettid.dev/pcr-manifest.json || echo "{}")

if [[ "$MANIFEST" == "{}" ]]; then
    echo -e "${RED}ERROR: Could not fetch PCR manifest from CloudFront${NC}"
    exit 1
fi

MANIFEST_VERSION=$(echo "$MANIFEST" | jq -r '.version')
MANIFEST_TIMESTAMP=$(echo "$MANIFEST" | jq -r '.timestamp')
CURRENT_SET=$(echo "$MANIFEST" | jq -r '.pcr_sets[] | select(.is_current == true)')
MANIFEST_PCR0=$(echo "$CURRENT_SET" | jq -r '.pcr0')
MANIFEST_PCR1=$(echo "$CURRENT_SET" | jq -r '.pcr1')
MANIFEST_PCR2=$(echo "$CURRENT_SET" | jq -r '.pcr2')
MANIFEST_ID=$(echo "$CURRENT_SET" | jq -r '.id')
MANIFEST_DESC=$(echo "$CURRENT_SET" | jq -r '.description // "No description"')
MANIFEST_VALID_FROM=$(echo "$CURRENT_SET" | jq -r '.valid_from')

# Get mobile bundled values
ANDROID_PCR_FILE="$VETTID_ROOT/vettid-android/app/src/main/java/com/vettid/app/core/attestation/PcrConfigManager.kt"
IOS_PCR_FILE="$VETTID_ROOT/vettid-ios/VettID/Resources/expected_pcrs.json"

ANDROID_PCR0=""
IOS_PCR0=""
ANDROID_STALE=false
IOS_STALE=false

if [[ -f "$ANDROID_PCR_FILE" ]]; then
    ANDROID_PCR0=$(grep -A1 'DEFAULT_PCRS = ExpectedPcrs' "$ANDROID_PCR_FILE" | grep 'pcr0' | sed 's/.*pcr0 = "\([^"]*\)".*/\1/' || echo "NOT_FOUND")
    ANDROID_VERSION=$(grep -A6 'DEFAULT_PCRS = ExpectedPcrs' "$ANDROID_PCR_FILE" | grep 'version' | sed 's/.*version = "\([^"]*\)".*/\1/' || echo "unknown")
fi

if [[ -f "$IOS_PCR_FILE" ]]; then
    IOS_PCR0=$(jq -r '.pcr_sets[] | select(.is_current == true) | .pcr0' "$IOS_PCR_FILE" 2>/dev/null || echo "NOT_FOUND")
    IOS_VERSION=$(jq -r '.pcr_sets[] | select(.is_current == true) | .id' "$IOS_PCR_FILE" 2>/dev/null || echo "unknown")
fi

# Display results
echo ""
echo "=== Source of Truth (SSM Parameter Store) ==="
echo "  PCR0: ${SSM_PCR0:0:16}...${SSM_PCR0: -8}"
echo "  PCR1: ${SSM_PCR1:0:16}...${SSM_PCR1: -8}"
echo "  PCR2: ${SSM_PCR2:0:16}...${SSM_PCR2: -8}"

echo ""
echo "=== CloudFront Manifest ==="
echo "  Version: $MANIFEST_VERSION"
echo "  Timestamp: $MANIFEST_TIMESTAMP"
echo "  Current Set: $MANIFEST_ID"
echo "  Description: $MANIFEST_DESC"

ERRORS=0
WARNINGS=0

# Check SSM vs Manifest
echo ""
echo "=== Verification Results ==="
echo ""
echo "1. SSM ↔ Manifest Consistency:"

if [[ "$SSM_PCR0" == "$MANIFEST_PCR0" ]]; then
    echo -e "   PCR0: ${GREEN}✓ Match${NC}"
else
    echo -e "   PCR0: ${RED}✗ MISMATCH${NC}"
    echo "         SSM:      $SSM_PCR0"
    echo "         Manifest: $MANIFEST_PCR0"
    ERRORS=$((ERRORS + 1))
fi

if [[ "$SSM_PCR1" == "$MANIFEST_PCR1" ]]; then
    echo -e "   PCR1: ${GREEN}✓ Match${NC}"
else
    echo -e "   PCR1: ${RED}✗ MISMATCH${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [[ "$SSM_PCR2" == "$MANIFEST_PCR2" ]]; then
    echo -e "   PCR2: ${GREEN}✓ Match${NC}"
else
    echo -e "   PCR2: ${RED}✗ MISMATCH${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check mobile bundled values
echo ""
echo "2. Mobile Bundled Fallbacks:"

if [[ -n "$ANDROID_PCR0" && "$ANDROID_PCR0" != "NOT_FOUND" ]]; then
    if [[ "$ANDROID_PCR0" == "$SSM_PCR0" ]]; then
        echo -e "   Android ($ANDROID_VERSION): ${GREEN}✓ Current${NC}"
    else
        echo -e "   Android ($ANDROID_VERSION): ${YELLOW}⚠ Stale${NC}"
        echo "         Bundled:    ${ANDROID_PCR0:0:16}...${ANDROID_PCR0: -8}"
        echo "         Production: ${SSM_PCR0:0:16}...${SSM_PCR0: -8}"
        WARNINGS=$((WARNINGS + 1))
        ANDROID_STALE=true
    fi
else
    echo -e "   Android: ${YELLOW}⚠ Not found${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

if [[ -n "$IOS_PCR0" && "$IOS_PCR0" != "NOT_FOUND" ]]; then
    if [[ "$IOS_PCR0" == "$SSM_PCR0" ]]; then
        echo -e "   iOS ($IOS_VERSION): ${GREEN}✓ Current${NC}"
    else
        echo -e "   iOS ($IOS_VERSION): ${YELLOW}⚠ Stale${NC}"
        echo "         Bundled:    ${IOS_PCR0:0:16}...${IOS_PCR0: -8}"
        echo "         Production: ${SSM_PCR0:0:16}...${SSM_PCR0: -8}"
        WARNINGS=$((WARNINGS + 1))
        IOS_STALE=true
    fi
else
    echo -e "   iOS: ${YELLOW}⚠ Not found${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

# Summary
echo ""
echo "=== Summary ==="

if [[ $ERRORS -gt 0 ]]; then
    echo -e "${RED}FAILED: $ERRORS error(s) found${NC}"
    echo "The SSM and manifest PCR values are out of sync."
    echo "Run: cd cdk && npx tsx scripts/publish-pcr-set.ts --help"
    exit 1
fi

if [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}PASSED with $WARNINGS warning(s)${NC}"
    echo "Mobile bundled fallbacks are stale but apps will fetch current values from manifest."

    # Apply updates automatically
    if $APPLY_UPDATES; then
        echo ""
        echo "=== Applying Updates ==="

        if $ANDROID_STALE && [[ -f "$ANDROID_PCR_FILE" ]]; then
            echo ""
            echo "Updating Android bundled PCRs..."

            # Use sed to update the Android file
            # Update pcr0
            sed -i "s/pcr0 = \"[a-f0-9]\{96\}\"/pcr0 = \"$SSM_PCR0\"/" "$ANDROID_PCR_FILE"
            # Update pcr1
            sed -i "s/pcr1 = \"[a-f0-9]\{96\}\"/pcr1 = \"$SSM_PCR1\"/" "$ANDROID_PCR_FILE"
            # Update pcr2
            sed -i "s/pcr2 = \"[a-f0-9]\{96\}\"/pcr2 = \"$SSM_PCR2\"/" "$ANDROID_PCR_FILE"
            # Update version in DEFAULT_PCRS block
            sed -i "s/version = \"[0-9-]*-v[0-9]*\"/version = \"$MANIFEST_ID\"/" "$ANDROID_PCR_FILE"
            # Update publishedAt
            sed -i "s/publishedAt = \"[^\"]*\"/publishedAt = \"$MANIFEST_VALID_FROM\"/" "$ANDROID_PCR_FILE"
            # Update comment
            sed -i "s/PCR values from VettID vault enclave build [0-9-]*-v[0-9]*/PCR values from VettID vault enclave build $MANIFEST_ID/" "$ANDROID_PCR_FILE"

            echo -e "   ${GREEN}✓ Updated $ANDROID_PCR_FILE${NC}"
        fi

        if $IOS_STALE && [[ -f "$IOS_PCR_FILE" ]]; then
            echo ""
            echo "Updating iOS bundled PCRs..."

            # Write new iOS JSON file
            cat > "$IOS_PCR_FILE" << EOF
{
  "pcr_sets": [
    {
      "id": "$MANIFEST_ID",
      "pcr0": "$SSM_PCR0",
      "pcr1": "$SSM_PCR1",
      "pcr2": "$SSM_PCR2",
      "valid_from": "$MANIFEST_VALID_FROM",
      "valid_until": null,
      "is_current": true
    }
  ]
}
EOF
            echo -e "   ${GREEN}✓ Updated $IOS_PCR_FILE${NC}"
        fi

        echo ""
        echo -e "${GREEN}Updates applied successfully!${NC}"
        echo "Don't forget to commit the changes to the mobile repos."

    elif $UPDATE_MOBILE; then
        echo ""
        echo "=== Update Commands ==="
        echo ""
        echo "To update Android bundled PCRs, edit:"
        echo "  $ANDROID_PCR_FILE"
        echo ""
        echo "Update DEFAULT_PCRS to:"
        echo "  pcr0 = \"$SSM_PCR0\""
        echo "  pcr1 = \"$SSM_PCR1\""
        echo "  pcr2 = \"$SSM_PCR2\""
        echo "  version = \"$MANIFEST_ID\""
        echo ""
        echo "To update iOS bundled PCRs, edit:"
        echo "  $IOS_PCR_FILE"
        echo ""
        echo "Update pcr_sets[0] to:"
        cat << EOF
  {
    "id": "$MANIFEST_ID",
    "pcr0": "$SSM_PCR0",
    "pcr1": "$SSM_PCR1",
    "pcr2": "$SSM_PCR2",
    "valid_from": "$MANIFEST_VALID_FROM",
    "valid_until": null,
    "is_current": true
  }
EOF
    else
        echo ""
        echo "Run with --update-mobile to see update commands."
        echo "Run with --apply to automatically update the files."
    fi
else
    echo -e "${GREEN}PASSED: All PCR values are in sync${NC}"
fi
