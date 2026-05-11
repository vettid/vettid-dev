#!/bin/bash
# VettID Unified Enclave Deployment Script
#
# Single command for enclave deployments. Automatically detects PCR0 changes
# and handles migration with user consent. Auto-finalizes when all users
# have migrated or the deadline passes.
#
# Usage:
#   ./deploy.sh --summary "Added wallet to profile"   # Full deploy
#   ./deploy.sh --dry-run --summary "..."              # Preview changes
#   ./deploy.sh --status                               # Check migration state
#   ./deploy.sh --finalize                             # Manual finalize
#
# Flow (PCR0 changed):
#   1. Build new enclave (calls deploy-enclave.sh --skip-refresh)
#   2. Update KMS policy: single → AnyOf [old, new]
#   3. Scale ASG to 2 (both old + new running)
#   4. Wait for both instances healthy
#   5. Publish signed migration config to S3
#   6. Schedule auto-finalize (EventBridge rule, checks every 5 min)
#   7. Done — operator walks away
#
# Flow (PCR0 unchanged):
#   1. Build new enclave
#   2. Instance refresh (simple replacement)
#   3. Verify health
#   4. Done

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENCLAVE_DIR="$(dirname "$SCRIPT_DIR")"

REGION="${AWS_REGION:-us-east-1}"
PCR0_SSM_PARAM="/vettid/enclave/pcr/pcr0"
MIGRATION_CONFIG_S3_KEY="_migration/config.json"
TRANSITION_HOURS=72
FINALIZE_LAMBDA_NAME="vettid-migration-finalize"
FINALIZE_RULE_NAME="vettid-migration-finalize-schedule"

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
USER_SUMMARY=""
# Default user-facing summary. Kept deliberately generic + action-oriented so
# users never see internal commit language. Override with --user-summary.
DEFAULT_USER_SUMMARY="Your approval is required to apply a security update to your vault."
DETAILS_URL=""
DEFAULT_DETAILS_URL="https://github.com/vettid/vettid-dev/blob/main/docs/SECURITY-UPDATES.md"
DRY_RUN=false
SKIP_KMS_FINALIZE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --finalize) ACTION="finalize"; shift ;;
        --status) ACTION="status"; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --skip-kms-finalize) SKIP_KMS_FINALIZE=true; shift ;;
        --summary) SUMMARY="$2"; shift 2 ;;
        --summary=*) SUMMARY="${1#*=}"; shift ;;
        --user-summary) USER_SUMMARY="$2"; shift 2 ;;
        --user-summary=*) USER_SUMMARY="${1#*=}"; shift ;;
        --details-url) DETAILS_URL="$2"; shift 2 ;;
        --details-url=*) DETAILS_URL="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

usage() {
    cat <<EOF
VettID Unified Enclave Deployment

Usage: $0 [ACTION] [OPTIONS]

Actions:
  (default)         Deploy new enclave (auto-detects if migration needed)
  --finalize        Manually finalize an active migration
  --status          Show current deployment/migration state

Options:
  --summary TEXT        Internal change description (for logs / release notes)
                        NOT shown to users. Required for deploy.
  --user-summary TEXT   User-facing message on the "Vault Security Update"
                        card. Default: "$DEFAULT_USER_SUMMARY"
  --details-url URL     Link to release notes shown in the app
  --dry-run             Preview changes without executing
  --skip-kms-finalize   Leave both PCR0s in KMS policy after deploy
  -h, --help            Show this help
EOF
}

# ============================================================================
# Helpers
# ============================================================================

get_asg_name() {
    aws autoscaling describe-auto-scaling-groups \
        --query 'AutoScalingGroups[?contains(AutoScalingGroupName, `VettID-Nitro-EnclaveASG`)].AutoScalingGroupName | [0]' \
        --output text --region "$REGION" 2>/dev/null
}

get_vault_bucket() {
    aws ssm get-parameter --name "/vettid/nitro/vault-data-bucket" \
        --query 'Parameter.Value' --output text --region "$REGION"
}

get_current_pcr0() {
    aws ssm get-parameter --name "$PCR0_SSM_PARAM" \
        --query 'Parameter.Value' --output text --region "$REGION"
}

get_current_pcrs() {
    aws ssm get-parameter --name "/vettid/enclave/pcr/current" \
        --query 'Parameter.Value' --output text --region "$REGION"
}

# get_staged_pcrs reads the post-build, pre-promotion PCR values.
# deploy-enclave.sh writes its build output to /vettid/enclave/pcr/staged-*
# instead of the live keys; this function is how deploy.sh learns the
# new PCR0 between Phase 2 (build) and Phase 4 (verify+promote).
get_staged_pcrs() {
    aws ssm get-parameter --name "/vettid/enclave/pcr/staged-current" \
        --query 'Parameter.Value' --output text --region "$REGION"
}

# promote_staged_pcrs copies /vettid/enclave/pcr/staged-* → live keys.
# Called only after a new instance attesting to the staged PCR0 has
# been launched and verified healthy (architect F6.5 fix). Promoting
# earlier would cause vettid-parent on the old instance to crash-loop
# at startup if it ever restarted before the new instance came up.
promote_staged_pcrs() {
    local pcr0 pcr1 pcr2 current_json
    pcr0=$(aws ssm get-parameter --name "/vettid/enclave/pcr/staged-pcr0" --query 'Parameter.Value' --output text --region "$REGION")
    pcr1=$(aws ssm get-parameter --name "/vettid/enclave/pcr/staged-pcr1" --query 'Parameter.Value' --output text --region "$REGION")
    pcr2=$(aws ssm get-parameter --name "/vettid/enclave/pcr/staged-pcr2" --query 'Parameter.Value' --output text --region "$REGION")
    current_json=$(aws ssm get-parameter --name "/vettid/enclave/pcr/staged-current" --query 'Parameter.Value' --output text --region "$REGION")

    aws ssm put-parameter --name "/vettid/enclave/pcr/pcr0" --value "$pcr0" --type String --overwrite --region "$REGION" > /dev/null
    aws ssm put-parameter --name "/vettid/enclave/pcr/pcr1" --value "$pcr1" --type String --overwrite --region "$REGION" > /dev/null
    aws ssm put-parameter --name "/vettid/enclave/pcr/pcr2" --value "$pcr2" --type String --overwrite --region "$REGION" > /dev/null
    aws ssm put-parameter --name "/vettid/enclave/pcr/current" --value "$current_json" --type String --overwrite --region "$REGION" > /dev/null
}

get_asg_desired() {
    aws autoscaling describe-auto-scaling-groups \
        --auto-scaling-group-names "$1" \
        --query 'AutoScalingGroups[0].DesiredCapacity' \
        --output text --region "$REGION"
}

get_kms_key_id() {
    aws kms list-aliases \
        --query 'Aliases[?AliasName==`alias/vettid-enclave-sealing`].TargetKeyId' \
        --output text --region "$REGION"
}

get_kms_policy() {
    aws kms get-key-policy --key-id "$1" --policy-name default \
        --query Policy --output text --region "$REGION"
}

# Wait for ASG instance refresh to complete
wait_for_refresh() {
    local asg_name="$1"
    local timeout=900  # 15 minutes
    local elapsed=0
    local interval=15

    while [[ $elapsed -lt $timeout ]]; do
        local status
        status=$(aws autoscaling describe-instance-refreshes \
            --auto-scaling-group-name "$asg_name" \
            --query 'InstanceRefreshes[0].Status' \
            --output text --region "$REGION" 2>/dev/null || echo "Unknown")

        case "$status" in
            Successful)
                log_info "Instance refresh completed successfully"
                return 0
                ;;
            Failed|Cancelled|RollbackFailed|RollbackSuccessful)
                log_error "Instance refresh failed with status: $status"
                return 1
                ;;
            *)
                # InProgress, Pending, Cancelling
                printf "."
                sleep $interval
                elapsed=$((elapsed + interval))
                ;;
        esac
    done

    log_error "Instance refresh timed out after ${timeout}s"
    return 1
}

# Wait for ASG instances to be healthy
wait_for_instances() {
    local asg_name="$1"
    local expected_count="$2"
    local timeout=300  # 5 minutes
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        local healthy_count
        healthy_count=$(aws autoscaling describe-auto-scaling-groups \
            --auto-scaling-group-names "$asg_name" \
            --query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService` && HealthStatus==`Healthy`] | length(@)' \
            --output text --region "$REGION" 2>/dev/null || echo "0")

        if [[ "$healthy_count" -ge "$expected_count" ]]; then
            log_info "$healthy_count healthy instance(s) running"
            return 0
        fi

        printf "."
        sleep 10
        elapsed=$((elapsed + 10))
    done

    log_error "Timed out waiting for $expected_count healthy instances"
    return 1
}

# Verify enclave health via SSM.
#
# The old cadence (3 retries × 30s = 90s wall budget) was racing the
# parent's actual boot sequence and false-failing every deploy. ASG
# flips the instance to "InService" as soon as EC2 status checks pass,
# but vettid-parent still has to: read SSM config, fetch the vsock
# secret from Secrets Manager, connect to NATS (with backoff on cold
# JetStream), boot the enclave EIF, complete the vsock handshake, and
# only THEN flip Healthy=true on /health. That regularly takes 2-3
# minutes, well past the old 90s budget.
#
# New cadence: poll every 5s for up to 5 minutes (60 attempts).
# Exits immediately on first healthy response, so a fast boot still
# returns in seconds. The longer budget covers real-world cold starts
# (cold JetStream connect can take ~90s on its own) without
# false-failing into Phase 4.5's journal-scan gate (which then has
# to be the real safety net — wasted work).
#
# curl -sf returns non-zero on HTTP >= 400, so a 503 (Healthy=false
# during boot) triggers the "HEALTH_FAIL" branch. That's correct
# behavior: we want to keep polling until 200.
verify_enclave_health() {
    local instance_id="$1"
    local retries=60
    local delay=5

    for attempt in $(seq 1 $retries); do
        # Check SSM agent is available
        local ssm_status
        ssm_status=$(aws ssm describe-instance-information \
            --filters "Key=InstanceIds,Values=$instance_id" \
            --query 'InstanceInformationList[0].PingStatus' \
            --output text --region "$REGION" 2>/dev/null || echo "Unknown")

        if [[ "$ssm_status" != "Online" ]]; then
            # Only log every 6th attempt (~30s) to keep deploy output readable.
            if (( attempt % 6 == 1 )); then
                log_warn "SSM not online for $instance_id yet (attempt $attempt/$retries, $((attempt*delay))s elapsed)"
            fi
            [[ $attempt -lt $retries ]] && sleep $delay
            continue
        fi

        # Check parent health endpoint
        local cmd_id
        cmd_id=$(aws ssm send-command \
            --instance-ids "$instance_id" \
            --document-name "AWS-RunShellScript" \
            --parameters 'commands=["curl -sf http://localhost:8080/health 2>/dev/null || echo HEALTH_FAIL"]' \
            --query 'Command.CommandId' \
            --output text --region "$REGION" 2>/dev/null || echo "")

        if [[ -z "$cmd_id" ]]; then
            if (( attempt % 6 == 1 )); then
                log_warn "Failed to send SSM command (attempt $attempt/$retries)"
            fi
            [[ $attempt -lt $retries ]] && sleep $delay
            continue
        fi

        # SSM command typically lands in <2s; give it 3 to leave headroom.
        sleep 3
        local health_output
        health_output=$(aws ssm get-command-invocation \
            --command-id "$cmd_id" \
            --instance-id "$instance_id" \
            --query 'StandardOutputContent' \
            --output text --region "$REGION" 2>/dev/null || echo "HEALTH_FAIL")

        if echo "$health_output" | grep -q '"Healthy":true\|"healthy":true'; then
            log_info "Enclave health check passed for $instance_id ($((attempt*delay))s elapsed)"
            return 0
        fi

        # Same throttled logging — surface the first failure and one
        # every ~30s after, not every attempt.
        if (( attempt == 1 || attempt % 6 == 0 )); then
            log_info "Waiting for $instance_id to report healthy (attempt $attempt/$retries, $((attempt*delay))s elapsed)"
        fi
        [[ $attempt -lt $retries ]] && sleep $delay
    done

    log_error "Enclave health check did not pass within $((retries*delay))s — Phase 4.5 journal scan is the remaining gate."
    return 1
}

# ============================================================================
# STATUS
# ============================================================================
do_status() {
    echo -e "${BLUE}=== VettID Deployment Status ===${NC}"
    echo ""

    local asg_name
    asg_name=$(get_asg_name)
    if [[ -z "$asg_name" || "$asg_name" == "None" ]]; then
        log_error "Could not find enclave ASG"
        return 1
    fi

    # Current PCR0
    local current_pcr0
    current_pcr0=$(get_current_pcr0 2>/dev/null || echo "unknown")
    echo -e "  Current PCR0: ${current_pcr0:0:32}..."

    # ASG status
    local desired
    desired=$(get_asg_desired "$asg_name")
    echo -e "  ASG Instances: $desired"

    # KMS policy
    local kms_key_id
    kms_key_id=$(get_kms_key_id 2>/dev/null || echo "")
    if [[ -n "$kms_key_id" && "$kms_key_id" != "None" ]]; then
        local policy pcr_value
        policy=$(get_kms_policy "$kms_key_id")
        pcr_value=$(echo "$policy" | jq -r '.Statement[] | select(.Sid == "AllowEnclaveDecrypt") | .Condition.StringEqualsIgnoreCase."kms:RecipientAttestation:PCR0"')
        if echo "$pcr_value" | jq -e 'type == "array"' >/dev/null 2>&1; then
            local pcr_count
            pcr_count=$(echo "$pcr_value" | jq 'length')
            echo -e "  KMS Policy: ${YELLOW}AnyOf [$pcr_count PCR0 values]${NC} (migration active)"
        else
            echo -e "  KMS Policy: ${GREEN}Single PCR0${NC} (normal)"
        fi
    fi

    # Migration config
    local bucket
    bucket=$(get_vault_bucket 2>/dev/null || echo "")
    if [[ -n "$bucket" ]] && aws s3 ls "s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}" --region "$REGION" >/dev/null 2>&1; then
        echo ""
        echo -e "  ${YELLOW}Migration: ACTIVE${NC}"
        local config
        config=$(aws s3 cp "s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}" - --region "$REGION" 2>/dev/null)
        echo "  Version:  $(echo "$config" | jq -r '.version')"
        echo "  Summary:  $(echo "$config" | jq -r '.summary')"
        echo "  Deadline: $(echo "$config" | jq -r '.mandatory_after')"
    else
        echo ""
        echo -e "  Migration: ${GREEN}None${NC}"
    fi

    # Auto-finalize schedule. The original idiom "(aws ... && echo yes
    # || echo no)" captured the describe-rule JSON along with the
    # literal "yes" in $rule_exists, so the comparison against "yes"
    # was always false and the status line lied. Check the exit code
    # instead.
    if aws events describe-rule --name "$FINALIZE_RULE_NAME" --region "$REGION" >/dev/null 2>&1; then
        echo -e "  Auto-finalize: ${GREEN}Scheduled (every 5 min)${NC}"
    else
        echo "  Auto-finalize: Not scheduled"
    fi

    echo ""
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

    local asg_name
    asg_name=$(get_asg_name)
    if [[ -z "$asg_name" || "$asg_name" == "None" ]]; then
        log_error "Could not find enclave ASG"
        exit 1
    fi

    # Phase tracking for error handler
    local PHASE="init"
    local KMS_MODIFIED=false
    local REFRESH_STARTED=false
    local ORIGINAL_KMS_POLICY=""

    trap 'on_error "$PHASE" "$KMS_MODIFIED" "$REFRESH_STARTED"' ERR

    # ------------------------------------------------------------------
    # Phase 1: Capture current state
    # ------------------------------------------------------------------
    PHASE="capture-state"
    log_step "Phase 1: Capturing current state"

    local old_pcrs_json old_pcr0 old_pcr1 old_pcr2
    old_pcrs_json=$(get_current_pcrs)
    old_pcr0=$(echo "$old_pcrs_json" | jq -r '.PCR0')
    old_pcr1=$(echo "$old_pcrs_json" | jq -r '.PCR1')
    old_pcr2=$(echo "$old_pcrs_json" | jq -r '.PCR2')
    log_info "Old PCR0: ${old_pcr0:0:24}..."

    local kms_key_id
    kms_key_id=$(get_kms_key_id)
    if [[ -z "$kms_key_id" || "$kms_key_id" == "None" ]]; then
        log_error "Could not find KMS sealing key"
        exit 1
    fi
    ORIGINAL_KMS_POLICY=$(get_kms_policy "$kms_key_id")

    if $DRY_RUN; then
        log_info "[DRY RUN] Would build new enclave and detect PCR0 change"
        log_info "[DRY RUN] Current KMS policy PCR0: ${old_pcr0:0:24}..."
        log_info "[DRY RUN] Summary: $SUMMARY"
        log_info "[DRY RUN] No changes made"
        exit 0
    fi

    # ------------------------------------------------------------------
    # Phase 1.5: Pre-build test gate
    # ------------------------------------------------------------------
    # Run the Go unit tests before the ~15 minute EIF build. This
    # catches the class of wire-contract drift that previously shipped
    # silently — IncomingProfileUpdateNotification.Fields was typed as
    # map[string]string while senders emitted map[string]ProfileFieldValue,
    # and the receiver dropped every peer broadcast that carried any
    # public fields. enclave/vault-manager/peer_wire_contract_test.go
    # exercises the marshal-then-unmarshal contract for every peer
    # subject; any new sender/receiver pair must add a test there.
    #
    # No --skip-tests flag by design. If tests are failing, the right
    # fix is to fix the tests (or the code), not to bypass the gate.
    # An emergency-rollback path runs an OLD known-good build — it
    # does not need to re-run this script's build phase.
    PHASE="pretest"
    log_step "Phase 1.5: Running Go unit tests (pre-build gate)"
    local enclave_dir="$SCRIPT_DIR/.."
    if ! (cd "$enclave_dir" && go test ./vault-manager/ ./supervisor/ -count=1 -timeout 120s); then
        log_error "Go tests failed — aborting build."
        log_error "Fix the failing tests, then re-run $0 --summary '...'"
        exit 1
    fi
    log_info "Tests passed; proceeding to build."

    # ------------------------------------------------------------------
    # Phase 2: Build new enclave
    # ------------------------------------------------------------------
    PHASE="build"
    log_step "Phase 2: Building new enclave (this takes ~15 minutes)"
    "$SCRIPT_DIR/deploy-enclave.sh" --skip-refresh

    # Read new PCR values from STAGED keys. deploy-enclave.sh writes
    # to /staged-* (architect F6.5 fix); live keys are still pointing
    # at the old PCR0 here, by design — promotion happens after the
    # new instance is verified in Phase 4.
    local new_pcrs_json new_pcr0 new_pcr1 new_pcr2
    new_pcrs_json=$(get_staged_pcrs)
    new_pcr0=$(echo "$new_pcrs_json" | jq -r '.PCR0')
    new_pcr1=$(echo "$new_pcrs_json" | jq -r '.PCR1')
    new_pcr2=$(echo "$new_pcrs_json" | jq -r '.PCR2')
    log_info "New PCR0: ${new_pcr0:0:24}..."

    # ------------------------------------------------------------------
    # Check if PCR0 changed
    # ------------------------------------------------------------------
    if [[ "$old_pcr0" == "$new_pcr0" ]]; then
        log_info "PCR0 unchanged — simple instance refresh (no migration needed)"
        PHASE="simple-refresh"

        # Start instance refresh
        aws autoscaling start-instance-refresh \
            --auto-scaling-group-name "$asg_name" \
            --preferences '{"MinHealthyPercentage": 0, "InstanceWarmup": 300}' \
            --region "$REGION" >/dev/null
        REFRESH_STARTED=true

        log_info "Waiting for instance refresh..."
        wait_for_refresh "$asg_name"

        log_info "Running verification..."
        "$SCRIPT_DIR/verify-deployment.sh" --fix || true

        log_info "=== Deploy Complete (no migration) ==="
        exit 0
    fi

    log_warn "PCR0 CHANGED — migration required (user consent needed)"

    # ------------------------------------------------------------------
    # Phase 3: KMS transition
    # ------------------------------------------------------------------
    PHASE="kms-update"
    log_step "Phase 3: Updating KMS policy (AnyOf [old, new])"

    local new_policy
    new_policy=$(echo "$ORIGINAL_KMS_POLICY" | jq --arg old "$old_pcr0" --arg new "$new_pcr0" \
        '(.Statement[] | select(.Sid == "AllowEnclaveDecrypt") | .Condition.StringEqualsIgnoreCase."kms:RecipientAttestation:PCR0") = [$old, $new]')
    aws kms put-key-policy --key-id "$kms_key_id" --policy-name default \
        --policy "$new_policy" --region "$REGION"
    KMS_MODIFIED=true
    log_info "KMS policy now allows both PCR0 values"

    # ------------------------------------------------------------------
    # Phase 4: Scale to dual-enclave
    # ------------------------------------------------------------------
    PHASE="scale-up"
    log_step "Phase 4: Scaling ASG to 2 (old + new enclave)"

    # CRITICAL: this is the migration branch. We just bumped the launch
    # template to point at the NEW AMI in Phase 2; the existing instance
    # is therefore on the OLD AMI by design — that's the source of the
    # migration. Do NOT run an instance refresh here. Doing so would
    # replace the only enclave that can unseal existing user data, and
    # connecting users would land on the new (empty-state) enclave with
    # no path back. (See incident 2026-05-06: a stale-AMI heuristic
    # mistook the migration source for leftover state and refreshed it,
    # destroying both phones' vault state in S3 on first contact.)
    #
    # ASG scale-up below brings up the NEW AMI as a SECOND instance
    # alongside the existing OLD one — exactly what migration needs.
    local current_instances current_inst_id current_inst_ami expected_old_ami
    current_instances=$(aws autoscaling describe-auto-scaling-groups \
        --auto-scaling-group-names "$asg_name" \
        --query 'AutoScalingGroups[0].Instances[*].InstanceId' \
        --output text --region "$REGION")

    # Pre-flight: there should be exactly one instance on the OLD AMI.
    # The OLD AMI is whatever the running enclave was on before Phase 2
    # bumped the launch template — i.e. the instance's actual ImageId.
    # If we see anything other than one instance on a single AMI here,
    # a previous deploy didn't complete cleanly and migration would be
    # ambiguous; abort so the operator can investigate.
    local inst_count=0
    for inst_id in $current_instances; do
        inst_count=$((inst_count + 1))
        current_inst_id="$inst_id"
        current_inst_ami=$(aws ec2 describe-instances --instance-ids "$inst_id" \
            --query 'Reservations[0].Instances[0].ImageId' --output text --region "$REGION" 2>/dev/null)
    done
    if [[ "$inst_count" -ne 1 ]]; then
        log_error "Expected exactly 1 enclave instance before scale-up; saw $inst_count. Aborting migration to avoid ambiguous state."
        exit 1
    fi
    log_info "Pre-flight: existing instance $current_inst_id on AMI $current_inst_ami (will be the migration source)"

    # Pin BOTH MinSize and MaxSize to 2 for the duration of the migration
    # window. Without MinSize=2, the CPU-based scaleOnCpuUtilization policy
    # (target 70%, defined in nitro-stack.ts) sees low CPU on the freshly-
    # scaled-up pair and triggers AlarmLow within ~5-6 minutes, scaling
    # DesiredCapacity from 2 back to 1 and terminating one of the instances.
    # If that instance happens to be the OLD migration source, users can no
    # longer re-seal via the old PCR0 (KMS still allows both, so they CAN
    # connect to the new enclave — but a stale migration check that came
    # back BEFORE the new config was published, or any other timing edge,
    # leaves them in an ambiguous "logged in but never prompted" state).
    # The auto-finalize Lambda restores MinSize=1 when it scales down at
    # the end of the migration window.
    aws autoscaling update-auto-scaling-group \
        --auto-scaling-group-name "$asg_name" \
        --min-size 2 \
        --max-size 2 \
        --region "$REGION"

    aws autoscaling set-desired-capacity \
        --auto-scaling-group-name "$asg_name" \
        --desired-capacity 2 \
        --region "$REGION"

    log_info "Waiting for both instances to be healthy..."
    wait_for_instances "$asg_name" 2

    # Identify the new instance by AMI, NOT by ASG list ordering.
    # Incident 2026-05-09: the previous heuristic `tail -1` of the ASG
    # instance list picked the OLD instance (list order isn't
    # guaranteed to be by launch time). The downstream "actual PCR0"
    # verification then read OLD's PCR0, the corrective code rewrote
    # staged SSM with OLD, and the promoted live PCR0 ended up wrong
    # on a fleet that auto-finalize then collapsed to a single NEW
    # instance — every vettid-parent restart on that instance read
    # SSM=OLD and crash-looped against the actual NEW enclave.
    #
    # The pre-flight loop above already captured `current_inst_ami` =
    # the OLD AMI (whatever the lone pre-scale instance was running).
    # The new instance is the one whose AMI is NOT that.
    local new_instance_id new_inst_ami all_instances inst_ami
    new_instance_id=""
    all_instances=$(aws autoscaling describe-auto-scaling-groups \
        --auto-scaling-group-names "$asg_name" \
        --query 'AutoScalingGroups[0].Instances[*].InstanceId' \
        --output text --region "$REGION")
    for inst_id in $all_instances; do
        inst_ami=$(aws ec2 describe-instances --instance-ids "$inst_id" \
            --query 'Reservations[0].Instances[0].ImageId' --output text --region "$REGION" 2>/dev/null)
        if [[ "$inst_ami" != "$current_inst_ami" ]]; then
            new_instance_id="$inst_id"
            new_inst_ami="$inst_ami"
            break
        fi
    done
    if [[ -z "$new_instance_id" ]]; then
        log_error "Could not identify new instance — every ASG instance is still on the migration-source AMI ($current_inst_ami)."
        log_error "This means the launch template did not pick up the new AMI before scale-up. Aborting."
        exit 1
    fi
    log_info "Identified new instance $new_instance_id on AMI $new_inst_ami (migration source: $current_inst_id on $current_inst_ami)"
    log_info "Verifying new instance health ($new_instance_id)..."
    verify_enclave_health "$new_instance_id" || log_warn "Health check inconclusive — continuing (both PCR0s in KMS)"

    # Post-launch PCR0 verification: read actual PCR0 from the running enclave
    # and correct SSM/KMS if the build-time value doesn't match runtime
    log_info "Verifying actual enclave PCR0 on $new_instance_id..."
    local verify_pcr0_cmd actual_pcr0
    verify_pcr0_cmd=$(aws ssm send-command \
        --instance-ids "$new_instance_id" \
        --document-name "AWS-RunShellScript" \
        --parameters 'commands=["nitro-cli describe-enclaves 2>/dev/null | jq -r \".[0].Measurements.PCR0 // empty\" 2>/dev/null || nitro-cli describe-eif --eif-path /opt/vettid/enclave/vettid-vault-enclave.eif 2>/dev/null | jq -r \".Measurements.PCR0\""]' \
        --query 'Command.CommandId' \
        --output text \
        --region "$REGION" 2>/dev/null || echo "")

    if [[ -n "$verify_pcr0_cmd" ]]; then
        sleep 10
        actual_pcr0=$(aws ssm get-command-invocation \
            --command-id "$verify_pcr0_cmd" \
            --instance-id "$new_instance_id" \
            --query 'StandardOutputContent' \
            --output text \
            --region "$REGION" 2>/dev/null | tr -d '[:space:]')

        if [[ -n "$actual_pcr0" && ${#actual_pcr0} -gt 40 && "$actual_pcr0" != "$new_pcr0" ]]; then
            log_warn "PCR0 MISMATCH: SSM has ${new_pcr0:0:16}... but actual enclave is ${actual_pcr0:0:16}..."
            log_info "Correcting SSM and KMS to match actual enclave PCR0"

            # Update STAGED SSM. Live keys are not touched here —
            # they will be promoted from staged after the Pre-Phase-5
            # dual-enclave gate succeeds. Architect F6.5 fix.
            aws ssm put-parameter --name "/vettid/enclave/pcr/staged-pcr0" \
                --value "$actual_pcr0" --type String --overwrite --region "$REGION"

            local current_json
            current_json=$(aws ssm get-parameter --name "/vettid/enclave/pcr/staged-current" \
                --query 'Parameter.Value' --output text --region "$REGION")
            updated_json=$(echo "$current_json" | jq --arg pcr0 "$actual_pcr0" '.PCR0 = $pcr0')
            aws ssm put-parameter --name "/vettid/enclave/pcr/staged-current" \
                --value "$updated_json" --type String --overwrite --region "$REGION"

            # Update KMS policy to AnyOf [old, actual]
            local corrected_policy
            corrected_policy=$(echo "$ORIGINAL_KMS_POLICY" | jq \
                --arg old "$old_pcr0" --arg new "$actual_pcr0" \
                '(.Statement[] | select(.Sid == "AllowEnclaveDecrypt") | .Condition.StringEqualsIgnoreCase."kms:RecipientAttestation:PCR0") = [$old, $new]')
            aws kms put-key-policy --key-id "$kms_key_id" --policy-name default \
                --policy "$corrected_policy" --region "$REGION"

            new_pcr0="$actual_pcr0"
            log_info "Corrected: SSM and KMS now use actual PCR0 ${actual_pcr0:0:24}..."
        elif [[ -n "$actual_pcr0" && ${#actual_pcr0} -gt 40 ]]; then
            log_info "PCR0 verified: SSM matches actual enclave"
        else
            log_warn "Could not read actual PCR0 from instance — verify manually"
        fi
    else
        log_warn "Could not send verification command to instance — verify PCR0 manually"
    fi

    # ------------------------------------------------------------------
    # Phase 4.5: Journal scan for handler errors on the new instance
    # ------------------------------------------------------------------
    # Liveness (verify_enclave_health) only confirms the parent is
    # responding on :8080. It says nothing about whether the enclave
    # is correctly handling forwarded vault traffic. Today's class of
    # bug — sender/receiver wire-schema drift — surfaces as a stream
    # of "Sanitized error returned to client" lines in the parent
    # journal as broadcasts pile up and get dropped. The wire-contract
    # Go tests at Phase 1.5 catch it at build time; this scan is the
    # belt-and-suspenders runtime check, in case a future regression
    # slips past unit tests (e.g. a code path only exercised at scale).
    #
    # Window: the new instance has had at least the time it took to
    # come InService + verify_enclave_health (~30-90s of real traffic
    # if any peer messages have arrived). Anything in the journal from
    # the new instance's boot to now is fair game.
    PHASE="post-launch-journal-scan"
    log_step "Phase 4.5: Scanning new instance journal for handler errors"
    local scan_cmd scan_out scan_err_count
    scan_cmd=$(aws ssm send-command \
        --instance-ids "$new_instance_id" \
        --document-name "AWS-RunShellScript" \
        --parameters 'commands=["journalctl -u vettid-parent --no-pager --since \"15 minutes ago\" | grep -cE \"Sanitized error returned to client|cannot unmarshal|message replay detected\" || true"]' \
        --query 'Command.CommandId' --output text --region "$REGION" 2>/dev/null || echo "")
    if [[ -n "$scan_cmd" ]]; then
        sleep 5
        scan_out=$(aws ssm get-command-invocation --command-id "$scan_cmd" \
            --instance-id "$new_instance_id" --query 'StandardOutputContent' \
            --output text --region "$REGION" 2>/dev/null | tr -d '[:space:]')
        scan_err_count="${scan_out:-0}"
        # Replay-detected lines are tolerable in small numbers during ASG
        # churn (duplicate JetStream redeliveries). Sanitized-error lines
        # are not — they indicate a handler is rejecting valid traffic.
        # Threshold of 0 is intentionally strict.
        if [[ "$scan_err_count" =~ ^[0-9]+$ ]] && [[ "$scan_err_count" -gt 0 ]]; then
            log_error "New instance journal shows $scan_err_count handler-error / replay-rejection line(s)."
            log_error "This is the failure mode that dropped every peer profile-update broadcast on 2026-05-10."
            log_error "Fetch the journal and investigate before promoting:"
            log_error "  aws ssm send-command --instance-ids $new_instance_id --document-name AWS-RunShellScript \\"
            log_error "    --parameters 'commands=[\"journalctl -u vettid-parent --since 15min --no-pager | grep -E \\\"Sanitized error|cannot unmarshal|replay detected\\\" | tail -40\"]' --region $REGION"
            log_error "Aborting; old PCR0 is still live, KMS allows both — no user-visible damage."
            exit 1
        fi
        log_info "New instance journal is clean (no handler errors or replay rejections)"
    else
        log_warn "Could not send SSM command for journal scan — verify manually"
    fi

    # ------------------------------------------------------------------
    # Pre-Phase-5 gate: confirm BOTH old and new PCR0s have a healthy
    # enclave behind them before publishing the migration config.
    #
    # This is the safety net for the regression that destroyed two users'
    # data in the 2026-05-06-v2 deploy: Phase 4 erroneously refreshed the
    # old instance, leaving only the new PCR0 alive. Migration config got
    # published anyway, telling phones to migrate — they connected to the
    # new (empty-state) enclave and overwrote their S3 vault state. Refuse
    # to publish the config unless we can prove both PCR0s are reachable.
    # ------------------------------------------------------------------
    PHASE="verify-dual-pcr"
    log_step "Verifying both old and new enclaves are running before publishing migration config"

    local current_inst_ids ami_set
    current_inst_ids=$(aws autoscaling describe-auto-scaling-groups \
        --auto-scaling-group-names "$asg_name" \
        --query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' \
        --output text --region "$REGION")
    ami_set=""
    for inst_id in $current_inst_ids; do
        inst_ami=$(aws ec2 describe-instances --instance-ids "$inst_id" \
            --query 'Reservations[0].Instances[0].ImageId' --output text --region "$REGION" 2>/dev/null)
        ami_set="${ami_set}${inst_ami}\n"
    done
    distinct_amis=$(printf "%b" "$ami_set" | sort -u | grep -c .)
    if [[ "$distinct_amis" -lt 2 ]]; then
        log_error "Refusing to publish migration config — only $distinct_amis distinct AMI(s) running."
        log_error "Migration requires both old and new enclaves alive simultaneously."
        log_error "Running instances:"
        printf "%b" "$ami_set" | sort -u | sed 's/^/  /'
        exit 1
    fi
    log_info "Verified: $distinct_amis distinct enclave AMIs running (migration safe)"

    # ------------------------------------------------------------------
    # Promote staged SSM PCR0 → live
    # ------------------------------------------------------------------
    # Architect F6.5 fix: deploy-enclave.sh writes the new build's PCR
    # values to /vettid/enclave/pcr/staged-* instead of the live
    # /vettid/enclave/pcr/pcr0 + /current. The "live" keys must only
    # update once we've confirmed (a) the new instance is healthy and
    # attesting to the staged PCR0 (Phase 4), AND (b) both old and new
    # enclaves are running so any vettid-parent that reads the new
    # SSM PCR0 has a matching enclave to handshake against (above).
    #
    # Aborting at any earlier point leaves the live keys pointing at
    # the OLD PCR0, which still matches the running fleet — no
    # crash-loop risk. (See incident 2026-05-09: SSM PCR0 was poisoned
    # to a never-deployed AMI's PCR0 and parent crash-looped ~10,000
    # times silently before discovery.)
    PHASE="promote-staged-pcr"
    log_step "Promoting staged SSM PCR0 → live"
    promote_staged_pcrs
    log_info "Live SSM PCR0 now reflects new enclave (${new_pcr0:0:24}...)"

    # ------------------------------------------------------------------
    # Phase 5: Publish migration config
    # ------------------------------------------------------------------
    PHASE="publish-config"
    log_step "Phase 5: Publishing migration config"

    local published_at mandatory_after version
    published_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    mandatory_after=$(date -u -d "+${TRANSITION_HOURS} hours" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || \
                      date -u -v+${TRANSITION_HOURS}H +"%Y-%m-%dT%H:%M:%SZ")
    # Read version from SSM (set by deploy-enclave.sh with auto-increment)
    version=$(aws ssm get-parameter --name "/vettid/enclave/pcr/current" --query 'Parameter.Value' --output text --region "$REGION" 2>/dev/null | jq -r '.version // empty' 2>/dev/null || echo "")
    if [ -z "$version" ]; then
        version="$(date +%Y-%m-%d)-v$(date +%H%M)"
    fi

    local config_file
    config_file=$(mktemp)
    cat > "$config_file" <<CONFIGEOF
{
    "new_pcrs": { "pcr0": "$new_pcr0", "pcr1": "$new_pcr1", "pcr2": "$new_pcr2" },
    "old_pcrs": { "pcr0": "$old_pcr0", "pcr1": "$old_pcr1", "pcr2": "$old_pcr2" },
    "valid_from": "$published_at",
    "version": "$version",
    "summary": "${USER_SUMMARY:-$DEFAULT_USER_SUMMARY}",
    "details_url": "${DETAILS_URL:-$DEFAULT_DETAILS_URL}",
    "published_at": "$published_at",
    "mandatory_after": "$mandatory_after"
}
CONFIGEOF

    # Sign with KMS if signing script exists
    local signed_config
    if [[ -x "$SCRIPT_DIR/sign-pcr-config.sh" ]]; then
        signed_config=$("$SCRIPT_DIR/sign-pcr-config.sh" "$config_file")
    else
        signed_config=$(cat "$config_file")
        log_warn "sign-pcr-config.sh not found — config published unsigned"
    fi
    rm -f "$config_file"

    local bucket
    bucket=$(get_vault_bucket)
    echo "$signed_config" | aws s3 cp - "s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}" \
        --content-type application/json --region "$REGION"
    log_info "Migration config published (version: $version, deadline: $mandatory_after)"

    # ------------------------------------------------------------------
    # Phase 6: Verify auto-finalize schedule
    # ------------------------------------------------------------------
    # The EventBridge rule that polls the finalize Lambda is provisioned
    # by CDK (NitroStack.MigrationFinalizeSchedule). This phase just
    # sanity-checks it exists so a bad cdk deploy doesn't silently leave
    # the cleanup unscheduled.
    PHASE="verify-finalize-schedule"
    log_step "Phase 6: Verifying auto-finalize schedule"

    if aws events describe-rule --name "$FINALIZE_RULE_NAME" --region "$REGION" >/dev/null 2>&1; then
        log_info "Auto-finalize rule is in place (polls every 5 min)"
    else
        log_warn "Auto-finalize rule ($FINALIZE_RULE_NAME) not found in EventBridge"
        log_warn "Expected CDK stack VettID-Nitro to provision it. Run:"
        log_warn "  cd cdk && npm run deploy -- VettID-Nitro"
        log_warn "Manual finalize while it's missing: $0 --finalize"
    fi

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    echo ""
    log_info "=== Migration Deployment Complete ==="
    echo ""
    log_info "Summary: $SUMMARY"
    log_info "Version: $version"
    log_info "Deadline: $mandatory_after"
    echo ""
    log_info "Both old and new enclave instances are running."
    log_info "Users will see 'Vault Security Update Available' in the app."
    log_info "Auto-finalize will clean up when all users have migrated."
    echo ""
    log_info "Check status: $0 --status"
}

# ============================================================================
# FINALIZE (manual override)
# ============================================================================
do_finalize() {
    log_info "=== Finalizing Migration ==="

    local asg_name
    asg_name=$(get_asg_name)
    if [[ -z "$asg_name" || "$asg_name" == "None" ]]; then
        log_error "Could not find enclave ASG"
        exit 1
    fi

    local bucket
    bucket=$(get_vault_bucket)

    if ! aws s3 ls "s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}" --region "$REGION" >/dev/null 2>&1; then
        log_warn "No active migration config — nothing to finalize"
        exit 0
    fi

    # Show config
    log_info "Active migration:"
    aws s3 cp "s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}" - --region "$REGION" | jq '{version, summary, mandatory_after}'

    echo ""
    read -p "Finalize migration? This removes old PCR0 from KMS and scales to 1 instance. (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Aborted"
        exit 0
    fi

    finalize_migration "$asg_name" "$bucket"
}

# Shared finalize logic (used by manual finalize and Lambda)
finalize_migration() {
    local asg_name="$1"
    local bucket="$2"

    log_step "1/4 Updating KMS policy (single PCR0)"
    local current_pcr0 kms_key_id current_policy new_policy
    current_pcr0=$(get_current_pcr0)
    kms_key_id=$(get_kms_key_id)
    current_policy=$(get_kms_policy "$kms_key_id")
    new_policy=$(echo "$current_policy" | jq --arg pcr "$current_pcr0" \
        '(.Statement[] | select(.Sid == "AllowEnclaveDecrypt") | .Condition.StringEqualsIgnoreCase."kms:RecipientAttestation:PCR0") = $pcr')
    aws kms put-key-policy --key-id "$kms_key_id" --policy-name default \
        --policy "$new_policy" --region "$REGION"
    log_info "KMS policy updated — only current PCR0: ${current_pcr0:0:24}..."

    log_step "2/4 Scaling ASG to 1"
    # Drop MinSize FIRST. The deploy phase pinned MinSize=2 to keep
    # both PCR0s alive during the migration window; SetDesiredCapacity
    # to 1 here would otherwise fail with
    #   ValidationError: New SetDesiredCapacity value 1 is below min
    #   value 2 for the AutoScalingGroup
    # leaving the ASG stuck at 2 with the OLD PCR0 already evicted
    # from KMS (step 1 ran). Update min/max/desired in one call so
    # there's no intermediate state where the parameters disagree.
    aws autoscaling update-auto-scaling-group \
        --auto-scaling-group-name "$asg_name" \
        --min-size 1 --max-size 1 --desired-capacity 1 \
        --region "$REGION"
    log_info "ASG scaled to 1 instance"

    log_step "3/4 Removing migration config"
    aws s3 rm "s3://${bucket}/${MIGRATION_CONFIG_S3_KEY}" --region "$REGION"
    log_info "Migration config deleted"

    # NOTE: The auto-finalize EventBridge rule is intentionally left
    # in place. It used to be torn down here (and by the Lambda on
    # successful auto-finalize) which is why every subsequent migration
    # shipped without a schedule. The rule is now CDK-owned, durable,
    # and a no-op when no migration config is active.
    log_step "4/4 Auto-finalize rule"
    log_info "Auto-finalize schedule left in place (CDK-owned, no-op when idle)"

    echo ""
    log_info "=== Migration Finalized ==="
    log_info "Single enclave running with new PCR0."
}

# ============================================================================
# Error handler
# ============================================================================
on_error() {
    local phase="$1"
    local kms_modified="$2"
    local refresh_started="$3"

    echo ""
    log_error "Deploy failed during phase: $phase"
    echo ""

    if [[ "$kms_modified" == "true" ]]; then
        log_warn "KMS policy was modified to allow both old and new PCR0."
        log_warn "This is a SAFE state — both enclaves can decrypt."
        log_warn "To finalize later: $0 --finalize"
    fi

    if [[ "$refresh_started" == "true" ]]; then
        log_warn "ASG instance refresh was started."
        log_warn "Check: aws autoscaling describe-instance-refreshes --auto-scaling-group-name \$(./deploy.sh --status 2>/dev/null | grep ASG)"
    fi
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
