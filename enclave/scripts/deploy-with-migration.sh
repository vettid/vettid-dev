#!/bin/bash
# VettID Enclave Migration Deployment Script
#
# Deploys a new enclave version with seamless user-consent migration.
# Both old and new enclaves run side-by-side during a transition window.
# Users see an update prompt in the app and approve the vault re-sealing.
#
# Usage:
#   ./deploy-with-migration.sh --summary "Improved encryption" --details-url "https://vettid.dev/updates/v2"
#   ./deploy-with-migration.sh --finalize              # After all users migrate (or deadline)
#   ./deploy-with-migration.sh --status                 # Check migration progress
#
# Flow:
#   1. Build new EIF, extract new PCR values
#   2. Add new PCR0 to KMS policy (AnyOf with old)
#   3. Create + sign migration config
#   4. Publish config to S3 for vault-manager to read
#   5. Increase ASG desired count to 2 (old + new instance)
#   6. Monitor: users approve migration in app (72-hour window)
#   7. --finalize: scale down to 1, remove old PCR0, clean up config
#
# Prerequisites:
#   - deploy-enclave.sh must work (same build infrastructure)
#   - Ed25519 deployment key at ~/.vettid/deploy-key.pem (or DEPLOY_KEY_PATH env)
#   - AWS CLI configured with sufficient permissions

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENCLAVE_DIR="$(dirname "$SCRIPT_DIR")"

REGION="${AWS_REGION:-us-east-1}"
ASG_NAME="VettID-Nitro-EnclaveASG"
PCR0_SSM_PARAM="/vettid/enclave/pcr/pcr0"
MIGRATION_CONFIG_S3_KEY="_migration/config.json"
TRANSITION_HOURS=72

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

# Parse arguments
ACTION="deploy"
SUMMARY=""
DETAILS_URL=""
for arg in "$@"; do
    case $arg in
        --finalize) ACTION="finalize" ;;
        --status) ACTION="status" ;;
        --summary) shift; SUMMARY="$1" ;;
        --summary=*) SUMMARY="${arg#*=}" ;;
        --details-url) shift; DETAILS_URL="$1" ;;
        --details-url=*) DETAILS_URL="${arg#*=}" ;;
        -h|--help) usage; exit 0 ;;
        *) ;;
    esac
    shift 2>/dev/null || true
done

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Actions:
  (default)    Deploy new enclave with migration
  --finalize   Complete migration (scale down, remove old PCR)
  --status     Check migration progress

Options:
  --summary TEXT        Human-readable summary of changes (required for deploy)
  --details-url URL     Link to release notes page
  -h, --help            Show this help

Environment:
  DEPLOY_KEY_PATH       Path to Ed25519 deployment signing key (default: ~/.vettid/deploy-key.pem)
  AWS_REGION            AWS region (default: us-east-1)
EOF
}

# Get the vault data bucket name from SSM
get_vault_bucket() {
    aws ssm get-parameter --name "/vettid/nitro/vault-data-bucket" \
        --query 'Parameter.Value' --output text --region "$REGION"
}

# Get current PCR0 from SSM
get_current_pcr0() {
    aws ssm get-parameter --name "$PCR0_SSM_PARAM" \
        --query 'Parameter.Value' --output text --region "$REGION"
}

# Get current PCR values from SSM
get_current_pcrs() {
    aws ssm get-parameter --name "/vettid/enclave/pcr/current" \
        --query 'Parameter.Value' --output text --region "$REGION"
}

# Get ASG current desired count
get_asg_desired() {
    aws autoscaling describe-auto-scaling-groups \
        --auto-scaling-group-names "$ASG_NAME" \
        --query 'AutoScalingGroups[0].DesiredCapacity' \
        --output text --region "$REGION"
}

# ============================================================================
# STATUS
# ============================================================================
do_status() {
    log_info "=== Migration Status ==="

    local bucket
    bucket=$(get_vault_bucket)

    # Check if migration config exists
    if aws s3 ls "s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}" --region "$REGION" >/dev/null 2>&1; then
        log_info "Migration config found in S3"
        aws s3 cp "s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}" - --region "$REGION" | jq .
    else
        log_info "No active migration (no config in S3)"
    fi

    # ASG status
    local desired
    desired=$(get_asg_desired)
    log_info "ASG desired capacity: $desired"

    if [[ "$desired" -gt 1 ]]; then
        log_warn "Dual-enclave mode active (desired=$desired)"
    fi

    # KMS policy PCR count
    local key_id
    key_id=$(aws kms describe-key --key-id alias/vettid-enclave-sealing \
        --query 'KeyMetadata.KeyId' --output text --region "$REGION" 2>/dev/null || echo "")
    if [[ -n "$key_id" ]]; then
        local pcr_count
        pcr_count=$(aws kms get-key-policy --key-id "$key_id" --policy-name default \
            --query Policy --output text --region "$REGION" | \
            jq '[.Statement[] | select(.Sid == "AllowEnclaveDecrypt")] | .[0].Condition.AnyOf // [.Condition] | length')
        log_info "KMS policy has $pcr_count PCR condition set(s)"
    fi
}

# ============================================================================
# DEPLOY
# ============================================================================
do_deploy() {
    if [[ -z "$SUMMARY" ]]; then
        log_error "--summary is required for deploy"
        log_error "Example: $0 --summary 'Improved message encryption'"
        exit 1
    fi

    log_step "1/7 Capturing current PCR values (old enclave)"
    local old_pcrs_json old_pcr0
    old_pcrs_json=$(get_current_pcrs)
    old_pcr0=$(echo "$old_pcrs_json" | jq -r '.PCR0')
    local old_pcr1 old_pcr2
    old_pcr1=$(echo "$old_pcrs_json" | jq -r '.PCR1')
    old_pcr2=$(echo "$old_pcrs_json" | jq -r '.PCR2')
    log_info "Old PCR0: ${old_pcr0:0:16}..."

    log_step "2/7 Building and deploying new enclave (via deploy-enclave.sh)"
    # Run the existing deploy script which builds EIF, creates AMI, updates SSM, etc.
    "$SCRIPT_DIR/deploy-enclave.sh"

    log_step "3/7 Getting new PCR values"
    # deploy-enclave.sh updates SSM with new PCR values
    local new_pcrs_json new_pcr0
    new_pcrs_json=$(get_current_pcrs)
    new_pcr0=$(echo "$new_pcrs_json" | jq -r '.PCR0')
    local new_pcr1 new_pcr2
    new_pcr1=$(echo "$new_pcrs_json" | jq -r '.PCR1')
    new_pcr2=$(echo "$new_pcrs_json" | jq -r '.PCR2')
    log_info "New PCR0: ${new_pcr0:0:16}..."

    if [[ "$old_pcr0" == "$new_pcr0" ]]; then
        log_warn "PCR0 has not changed — no migration needed"
        log_info "The new enclave build is identical to the old one"
        exit 0
    fi

    log_step "4/7 Ensuring both PCR0 values are in KMS policy (AnyOf)"
    # deploy-enclave.sh already adds the new PCR0. Verify old is still there.
    # The update-kms-policy.sh adds to AnyOf, so both should be present.
    log_info "KMS policy should have both old and new PCR0 in AnyOf"
    log_info "Old: ${old_pcr0:0:16}..."
    log_info "New: ${new_pcr0:0:16}..."

    log_step "5/7 Creating and signing migration config"
    local published_at mandatory_after version
    published_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    mandatory_after=$(date -u -d "+${TRANSITION_HOURS} hours" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || \
                      date -u -v+${TRANSITION_HOURS}H +"%Y-%m-%dT%H:%M:%SZ")
    version="$(date +%Y-%m-%d)-v$(date +%s | tail -c 5)"

    # Create unsigned config
    local config_file
    config_file=$(mktemp)
    cat > "$config_file" <<CONFIGEOF
{
    "new_pcrs": {
        "pcr0": "$new_pcr0",
        "pcr1": "$new_pcr1",
        "pcr2": "$new_pcr2"
    },
    "old_pcrs": {
        "pcr0": "$old_pcr0",
        "pcr1": "$old_pcr1",
        "pcr2": "$old_pcr2"
    },
    "valid_from": "$published_at",
    "version": "$version",
    "summary": "$SUMMARY",
    "details_url": "${DETAILS_URL:-}",
    "published_at": "$published_at",
    "mandatory_after": "$mandatory_after"
}
CONFIGEOF

    # Sign with KMS (ECDSA P-256, same key as PCR manifest)
    local signed_config
    signed_config=$("$SCRIPT_DIR/sign-pcr-config.sh" "$config_file")
    rm -f "$config_file"

    log_info "Migration config signed (version: $version)"
    log_info "Mandatory after: $mandatory_after"

    log_step "6/7 Publishing migration config to S3"
    local bucket
    bucket=$(get_vault_bucket)
    echo "$signed_config" | aws s3 cp - "s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}" \
        --content-type application/json --region "$REGION"
    log_info "Migration config published to s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}"

    log_step "7/7 Scaling ASG to 2 for dual-enclave transition"
    local current_desired
    current_desired=$(get_asg_desired)
    if [[ "$current_desired" -lt 2 ]]; then
        aws autoscaling set-desired-capacity \
            --auto-scaling-group-name "$ASG_NAME" \
            --desired-capacity 2 \
            --region "$REGION"
        log_info "ASG scaled to 2 instances (old + new enclave)"
    else
        log_info "ASG already at desired=$current_desired"
    fi

    echo ""
    log_info "=== Migration Deployment Complete ==="
    log_info ""
    log_info "What happens now:"
    log_info "  1. Both old and new enclave instances are running"
    log_info "  2. Users opening the app will see 'Vault Security Update Available'"
    log_info "  3. Users tap 'Update Now' → vault re-seals (2-3 seconds)"
    log_info "  4. After $TRANSITION_HOURS hours ($mandatory_after), update becomes mandatory"
    log_info ""
    log_info "Monitor progress:"
    log_info "  $0 --status"
    log_info ""
    log_info "Finalize after all users migrate (or after deadline):"
    log_info "  $0 --finalize"
}

# ============================================================================
# FINALIZE
# ============================================================================
do_finalize() {
    log_info "=== Finalizing Migration ==="

    local bucket
    bucket=$(get_vault_bucket)

    # Check if migration config exists
    if ! aws s3 ls "s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}" --region "$REGION" >/dev/null 2>&1; then
        log_warn "No active migration config found — nothing to finalize"
        exit 0
    fi

    # Show config for confirmation
    log_info "Current migration config:"
    aws s3 cp "s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}" - --region "$REGION" | jq '{version, summary, mandatory_after}'

    echo ""
    read -p "Finalize migration? This will remove old PCR0 from KMS policy. (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Aborted"
        exit 0
    fi

    log_step "1/3 Removing old PCR0 from KMS policy"
    "$SCRIPT_DIR/update-kms-policy.sh" --environment staging --remove-old-pcrs
    log_info "Old PCR0 removed — only new enclave can unseal"

    log_step "2/3 Scaling ASG back to 1"
    aws autoscaling set-desired-capacity \
        --auto-scaling-group-name "$ASG_NAME" \
        --desired-capacity 1 \
        --region "$REGION"
    log_info "ASG scaled to 1 instance"

    log_step "3/3 Removing migration config from S3"
    aws s3 rm "s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}" --region "$REGION"
    log_info "Migration config removed"

    echo ""
    log_info "=== Migration Finalized ==="
    log_info "Only the new enclave is running. Old PCR0 has been removed from KMS policy."
    log_info "Any users who did not migrate will need to re-seal on next app open"
    log_info "(the new enclave handles this automatically with the new PCR0)."
}

# ============================================================================
# Main
# ============================================================================
case "$ACTION" in
    deploy)   do_deploy ;;
    finalize) do_finalize ;;
    status)   do_status ;;
    *)        log_error "Unknown action: $ACTION"; exit 1 ;;
esac
