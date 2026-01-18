#!/bin/bash
# VettID Enclave Deployment Verification Script
#
# Run after deploy-enclave.sh to verify:
# 1. SSM parameters are updated with correct PCRs
# 2. API endpoint returns matching PCR values
# 3. Running enclave matches expected PCRs
#
# Usage: ./verify-deployment.sh [--fix]
#   --fix  Automatically update SSM if API is out of sync

set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
API_URL="https://api.vettid.dev"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

FIX_MODE=false
for arg in "$@"; do
    case $arg in
        --fix) FIX_MODE=true ;;
    esac
done

echo "=== VettID Enclave Deployment Verification ==="
echo ""

ERRORS=0

# 1. Check SSM parameters exist
echo "Checking SSM parameters..."
SSM_CURRENT=$(aws ssm get-parameter --name "/vettid/enclave/pcr/current" --query 'Parameter.Value' --output text --region "$REGION" 2>/dev/null || echo "")
SSM_PCR0=$(aws ssm get-parameter --name "/vettid/enclave/pcr/pcr0" --query 'Parameter.Value' --output text --region "$REGION" 2>/dev/null || echo "")
SSM_PCR1=$(aws ssm get-parameter --name "/vettid/enclave/pcr/pcr1" --query 'Parameter.Value' --output text --region "$REGION" 2>/dev/null || echo "")
SSM_PCR2=$(aws ssm get-parameter --name "/vettid/enclave/pcr/pcr2" --query 'Parameter.Value' --output text --region "$REGION" 2>/dev/null || echo "")

if [ -z "$SSM_CURRENT" ]; then
    log_error "SSM parameter /vettid/enclave/pcr/current not found"
    ERRORS=$((ERRORS + 1))
else
    SSM_CURRENT_PCR0=$(echo "$SSM_CURRENT" | jq -r '.PCR0')
    SSM_CURRENT_PCR1=$(echo "$SSM_CURRENT" | jq -r '.PCR1')
    SSM_CURRENT_PCR2=$(echo "$SSM_CURRENT" | jq -r '.PCR2')
    SSM_VERSION=$(echo "$SSM_CURRENT" | jq -r '.version')
    log_ok "SSM /vettid/enclave/pcr/current exists (version: $SSM_VERSION)"
fi

if [ -n "$SSM_PCR0" ]; then
    log_ok "SSM /vettid/enclave/pcr/pcr0 exists"
else
    log_warn "SSM /vettid/enclave/pcr/pcr0 not found (optional)"
fi

# 2. Verify parent's PCR0 param matches /current (critical for attestation)
if [ -n "$SSM_PCR0" ]; then
    if [ -n "$SSM_CURRENT_PCR0" ] && [ "$SSM_PCR0" != "$SSM_CURRENT_PCR0" ]; then
        log_error "CRITICAL: /vettid/enclave/pcr/pcr0 does not match /current"
        log_error "  Parent reads:  ${SSM_PCR0:0:20}..."
        log_error "  Current:       ${SSM_CURRENT_PCR0:0:20}..."
        log_error "  This will cause parent crash loop!"
        ERRORS=$((ERRORS + 1))
    else
        log_ok "SSM /vettid/enclave/pcr/pcr0 matches current"
    fi
else
    log_error "SSM /vettid/enclave/pcr/pcr0 not found - parent will fail!"
    ERRORS=$((ERRORS + 1))
fi

# 3. Check individual SSM params match combined param (optional)
if [ -n "$SSM_PCR0" ] && [ -n "$SSM_CURRENT_PCR0" ]; then
    if [ "$SSM_PCR0" != "$SSM_CURRENT_PCR0" ]; then
        log_warn "SSM /pcr/pcr0 differs from /current (informational only)"
    fi
fi

# 4. Check API endpoint
echo ""
echo "Checking API endpoint..."
API_RESPONSE=$(curl -s "$API_URL/vault/pcrs/current" 2>/dev/null || echo "")

if [ -z "$API_RESPONSE" ]; then
    log_error "API endpoint $API_URL/vault/pcrs/current not responding"
    ERRORS=$((ERRORS + 1))
else
    API_PCR0=$(echo "$API_RESPONSE" | jq -r '.pcrs.PCR0')
    API_PCR1=$(echo "$API_RESPONSE" | jq -r '.pcrs.PCR1')
    API_PCR2=$(echo "$API_RESPONSE" | jq -r '.pcrs.PCR2')
    API_VERSION=$(echo "$API_RESPONSE" | jq -r '.version')
    log_ok "API endpoint responding (version: $API_VERSION)"

    # Check if API matches SSM
    if [ "$API_PCR0" != "$SSM_CURRENT_PCR0" ]; then
        log_warn "API PCR0 differs from SSM (Lambda cache may need to expire)"
        log_warn "  API: ${API_PCR0:0:20}..."
        log_warn "  SSM: ${SSM_CURRENT_PCR0:0:20}..."
    else
        log_ok "API PCR0 matches SSM"
    fi
fi

# 4. Check running enclave (if we can reach an instance)
echo ""
echo "Checking running enclave..."

# Find an enclave instance
INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Application,Values=vettid-enclave" "Name=instance-state-name,Values=running" \
    --query 'Reservations[0].Instances[0].InstanceId' \
    --output text \
    --region "$REGION" 2>/dev/null || echo "None")

if [ "$INSTANCE_ID" == "None" ] || [ -z "$INSTANCE_ID" ]; then
    log_warn "No running enclave instance found (skipping enclave PCR check)"
else
    log_ok "Found enclave instance: $INSTANCE_ID"

    # Try to get PCRs from enclave via SSM
    CMD_ID=$(aws ssm send-command \
        --instance-ids "$INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters 'commands=["nitro-cli describe-enclaves 2>/dev/null | jq -r \".[] | .Measurements\" || echo \"{}\""]' \
        --query 'Command.CommandId' \
        --output text \
        --region "$REGION" 2>/dev/null || echo "")

    if [ -n "$CMD_ID" ]; then
        sleep 3
        ENCLAVE_PCRS=$(aws ssm get-command-invocation \
            --command-id "$CMD_ID" \
            --instance-id "$INSTANCE_ID" \
            --query 'StandardOutputContent' \
            --output text \
            --region "$REGION" 2>/dev/null || echo "{}")

        if [ -n "$ENCLAVE_PCRS" ] && [ "$ENCLAVE_PCRS" != "{}" ]; then
            ENCLAVE_PCR0=$(echo "$ENCLAVE_PCRS" | jq -r '.PCR0' 2>/dev/null || echo "")

            if [ -n "$ENCLAVE_PCR0" ] && [ "$ENCLAVE_PCR0" != "null" ]; then
                log_ok "Got PCRs from running enclave"

                if [ "$ENCLAVE_PCR0" != "$SSM_CURRENT_PCR0" ]; then
                    log_error "ENCLAVE PCR0 MISMATCH!"
                    log_error "  Running: ${ENCLAVE_PCR0:0:40}..."
                    log_error "  SSM:     ${SSM_CURRENT_PCR0:0:40}..."
                    ERRORS=$((ERRORS + 1))

                    if [ "$FIX_MODE" = true ]; then
                        echo ""
                        log_warn "Fixing SSM parameter..."
                        ENCLAVE_PCR1=$(echo "$ENCLAVE_PCRS" | jq -r '.PCR1')
                        ENCLAVE_PCR2=$(echo "$ENCLAVE_PCRS" | jq -r '.PCR2')
                        VERSION="$(date +%Y-%m-%d)-v1"
                        PUBLISHED_AT="$(date -Iseconds)"
                        PCR_JSON="{\"PCR0\":\"$ENCLAVE_PCR0\",\"PCR1\":\"$ENCLAVE_PCR1\",\"PCR2\":\"$ENCLAVE_PCR2\",\"version\":\"$VERSION\",\"published_at\":\"$PUBLISHED_AT\"}"

                        aws ssm put-parameter \
                            --name "/vettid/enclave/pcr/current" \
                            --value "$PCR_JSON" \
                            --type String \
                            --overwrite \
                            --region "$REGION"

                        log_ok "SSM parameter updated (version: $VERSION)"
                        log_warn "Note: API cache will expire in ~5 minutes"
                    fi
                else
                    log_ok "Enclave PCR0 matches SSM"
                fi
            fi
        else
            log_warn "Could not retrieve PCRs from enclave (may not be running)"
        fi
    fi
fi

# Summary
echo ""
echo "=== Verification Summary ==="
if [ $ERRORS -eq 0 ]; then
    log_ok "All checks passed"
    exit 0
else
    log_error "$ERRORS error(s) found"
    if [ "$FIX_MODE" = false ]; then
        echo ""
        echo "Run with --fix to automatically repair SSM parameters"
    fi
    exit 1
fi
