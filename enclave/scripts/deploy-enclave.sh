#!/bin/bash
# VettID Nitro Enclave Deployment Script
#
# This script:
# 1. Launches a Nitro-enabled EC2 instance for building
# 2. Copies enclave source code to the instance
# 3. Builds Docker image and EIF
# 4. Creates an AMI with the EIF baked in
# 5. Updates SSM parameter with new AMI ID
# 6. Triggers ASG instance refresh
# 7. Cleans up the build instance
#
# Usage: ./deploy-enclave.sh [--skip-cleanup]

set -euo pipefail

# Configuration
REGION="${AWS_REGION:-us-east-1}"
VPC_ID="vpc-09abe63ccf7035ef5"
# Use PRIVATE subnet for security - SSM VPC endpoints are configured
SUBNET_ID="subnet-00ee1b2d2260c0015"
INSTANCE_TYPE="c6a.2xlarge"  # Nitro-enabled, enough RAM for EIF build
KEY_NAME="${EC2_KEY_NAME:-}"  # Optional SSH key (not needed with SSM)
AMI_SSM_PARAM="/vettid/enclave/ami-id"
PCR0_SSM_PARAM="/vettid/enclave/pcr/pcr0"
ASG_NAME="VettID-Nitro-EnclaveASG"  # Will be looked up
BUILD_TIMEOUT=1800  # 30 minutes max for build

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments
SKIP_CLEANUP=false
for arg in "$@"; do
    case $arg in
        --skip-cleanup) SKIP_CLEANUP=true ;;
        *) log_error "Unknown argument: $arg"; exit 1 ;;
    esac
done

# Get script directory (where enclave source is)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENCLAVE_DIR="$(dirname "$SCRIPT_DIR")"

log_info "Enclave source directory: $ENCLAVE_DIR"

# Find Amazon Linux 2023 AMI for build instance
log_info "Finding Amazon Linux 2023 AMI..."
BUILD_AMI=$(aws ec2 describe-images \
    --owners amazon \
    --filters \
        "Name=name,Values=al2023-ami-2023*-x86_64" \
        "Name=state,Values=available" \
        "Name=architecture,Values=x86_64" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
    --output text \
    --region "$REGION")

if [ -z "$BUILD_AMI" ] || [ "$BUILD_AMI" == "None" ]; then
    log_error "Could not find Amazon Linux 2023 AMI"
    exit 1
fi
log_info "Using build AMI: $BUILD_AMI"

# Get or create security group for build instance
log_info "Setting up security group..."
BUILD_SG_NAME="vettid-enclave-build-sg"
BUILD_SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=$BUILD_SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
    --query 'SecurityGroups[0].GroupId' \
    --output text \
    --region "$REGION" 2>/dev/null || echo "None")

if [ "$BUILD_SG_ID" == "None" ] || [ -z "$BUILD_SG_ID" ]; then
    log_info "Creating security group..."
    BUILD_SG_ID=$(aws ec2 create-security-group \
        --group-name "$BUILD_SG_NAME" \
        --description "Security group for VettID enclave build instances (SSM access only, no SSH)" \
        --vpc-id "$VPC_ID" \
        --query 'GroupId' \
        --output text \
        --region "$REGION")
    # No inbound rules needed - SSM uses VPC endpoints (outbound HTTPS)
fi
log_info "Using security group: $BUILD_SG_ID"

# Get IAM instance profile (use the packer build profile)
INSTANCE_PROFILE="vettid-packer-build-profile"
INSTANCE_ROLE="vettid-packer-build-role"
log_info "Using instance profile: $INSTANCE_PROFILE"

# Ensure required managed policies are attached to the role
for POLICY_ARN in "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore" "arn:aws:iam::aws:policy/AmazonS3FullAccess"; do
    if ! aws iam list-attached-role-policies --role-name "$INSTANCE_ROLE" --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null | grep -q "$POLICY_ARN"; then
        POLICY_NAME=$(basename "$POLICY_ARN")
        log_info "Attaching $POLICY_NAME policy to role..."
        aws iam attach-role-policy --role-name "$INSTANCE_ROLE" --policy-arn "$POLICY_ARN" --region "$REGION"
    fi
done

# Create user data script for build instance
log_info "Creating user data script..."
USER_DATA=$(cat << 'USERDATA'
#!/bin/bash
set -euxo pipefail
exec > >(tee /var/log/user-data.log) 2>&1

echo "=== Installing dependencies ==="
dnf update -y
dnf install -y docker git golang aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel

# Start docker
systemctl start docker
systemctl enable docker

# Configure nitro enclaves allocator
cat > /etc/nitro_enclaves/allocator.yaml << EOF
---
memory_mib: 8192
cpu_count: 2
EOF

# Start nitro enclaves allocator
systemctl start nitro-enclaves-allocator
systemctl enable nitro-enclaves-allocator

# Add ec2-user to docker and ne groups
usermod -aG docker ec2-user
usermod -aG ne ec2-user

# Create working directory
mkdir -p /opt/vettid/build
chown ec2-user:ec2-user /opt/vettid/build

# Signal ready
touch /tmp/build-ready

echo "=== Build instance ready ==="
USERDATA
)

# Launch build instance
log_info "Launching build instance..."
INSTANCE_OPTS=(
    --image-id "$BUILD_AMI"
    --instance-type "$INSTANCE_TYPE"
    --subnet-id "$SUBNET_ID"
    --security-group-ids "$BUILD_SG_ID"
    --iam-instance-profile "Name=$INSTANCE_PROFILE"
    --enclave-options "Enabled=true"
    --user-data "$USER_DATA"
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=vettid-enclave-build},{Key=Purpose,Value=EIF-Build},{Key=AutoCleanup,Value=true}]"
    --region "$REGION"
)

if [ -n "$KEY_NAME" ]; then
    INSTANCE_OPTS+=(--key-name "$KEY_NAME")
fi

INSTANCE_ID=$(aws ec2 run-instances "${INSTANCE_OPTS[@]}" \
    --query 'Instances[0].InstanceId' \
    --output text)

log_info "Launched instance: $INSTANCE_ID"

# Cleanup function
cleanup() {
    if [ "$SKIP_CLEANUP" = true ]; then
        log_warn "Skipping cleanup (--skip-cleanup specified)"
        log_info "Instance $INSTANCE_ID is still running"
        return
    fi

    log_info "Cleaning up build instance..."
    aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" || true

    # Wait for termination
    aws ec2 wait instance-terminated --instance-ids "$INSTANCE_ID" --region "$REGION" || true
    log_info "Build instance terminated"
}

trap cleanup EXIT

# Wait for instance to be running
log_info "Waiting for instance to be running..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

# Get instance private IP (no public IP in private subnet)
INSTANCE_IP=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' \
    --output text \
    --region "$REGION")

log_info "Instance private IP: $INSTANCE_IP (using SSM for access, no public IP)"

# Wait for SSM agent to be ready and user data to complete
log_info "Waiting for SSM agent and instance setup..."
WAIT_COUNT=0
MAX_WAIT=60  # 5 minutes max
SSM_READY=false

while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    # Check if SSM agent is online
    SSM_STATUS=$(aws ssm describe-instance-information \
        --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
        --query 'InstanceInformationList[0].PingStatus' \
        --output text \
        --region "$REGION" 2>/dev/null || echo "Offline")

    if [ "$SSM_STATUS" = "Online" ]; then
        if [ "$SSM_READY" = false ]; then
            log_info "SSM agent is online"
            SSM_READY=true
        fi

        # Check if user data completed
        CHECK_RESULT=$(aws ssm send-command \
            --instance-ids "$INSTANCE_ID" \
            --document-name "AWS-RunShellScript" \
            --parameters 'commands=["test -f /tmp/build-ready && echo READY || echo WAITING"]' \
            --query 'Command.CommandId' \
            --output text \
            --region "$REGION" 2>/dev/null || echo "")

        if [ -n "$CHECK_RESULT" ]; then
            sleep 3
            CHECK_OUTPUT=$(aws ssm get-command-invocation \
                --command-id "$CHECK_RESULT" \
                --instance-id "$INSTANCE_ID" \
                --query 'StandardOutputContent' \
                --output text \
                --region "$REGION" 2>/dev/null || echo "")

            if echo "$CHECK_OUTPUT" | grep -q "READY"; then
                log_info "Instance setup complete"
                break
            fi
        fi
    fi

    sleep 5
    WAIT_COUNT=$((WAIT_COUNT + 1))
    echo -n "."
done
echo ""

if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
    log_warn "Timeout waiting for instance setup, proceeding anyway..."
fi

# Use SSM to run the build
log_info "Starting EIF build via SSM..."

# First, copy source code to instance via SSM
log_info "Copying source code to instance..."

# Create a tarball of the enclave source
TARBALL="/tmp/enclave-source-$$.tar.gz"
tar -czf "$TARBALL" -C "$ENCLAVE_DIR" .

# Upload to S3 temporarily
S3_BUCKET="vettid-vault-data-$(aws sts get-caller-identity --query Account --output text)"
S3_KEY="build-artifacts/enclave-source-$(date +%s).tar.gz"
aws s3 cp "$TARBALL" "s3://$S3_BUCKET/$S3_KEY" --region "$REGION"
rm "$TARBALL"

log_info "Source uploaded to s3://$S3_BUCKET/$S3_KEY"

# Create build script and upload to S3
BUILD_SCRIPT="/tmp/build-enclave-$$.sh"
cat > "$BUILD_SCRIPT" << 'BUILDEOF'
#!/bin/bash
set -euxo pipefail

REGION="__REGION__"
S3_BUCKET="__S3_BUCKET__"
S3_KEY="__S3_KEY__"

cd /opt/vettid/build

# Download source from S3
aws s3 cp "s3://${S3_BUCKET}/${S3_KEY}" source.tar.gz --region "$REGION"
tar -xzf source.tar.gz
rm source.tar.gz

# SECURITY: Fetch vsock shared secret from Secrets Manager and write to build context
# This secret will be baked into the EIF for enclave-side authentication
echo "=== Fetching vsock shared secret ==="
aws secretsmanager get-secret-value \
    --secret-id vettid/vsock-shared-secret \
    --region "$REGION" \
    --query SecretString \
    --output text > vsock-secret.hex
chmod 600 vsock-secret.hex
echo "Vsock secret fetched (length: $(wc -c < vsock-secret.hex) bytes)"

# Build Docker image (secret file is in build context)
echo "=== Building Docker image ==="
docker build -f Dockerfile.enclave -t vettid-enclave:latest .

# SECURITY: Remove secret from build context after Docker build
rm -f vsock-secret.hex

# Build EIF
echo "=== Building EIF ==="
nitro-cli build-enclave \
    --docker-uri vettid-enclave:latest \
    --output-file vettid-vault-enclave.eif \
    2>&1 | tee /tmp/eif-build.log

# Extract PCR values
echo "=== Extracting PCR values ==="
nitro-cli describe-eif --eif-path vettid-vault-enclave.eif > /tmp/eif-info.json
PCR0=$(cat /tmp/eif-info.json | jq -r '.Measurements.PCR0')
PCR1=$(cat /tmp/eif-info.json | jq -r '.Measurements.PCR1')
PCR2=$(cat /tmp/eif-info.json | jq -r '.Measurements.PCR2')

echo "PCR0: $PCR0"
echo "PCR1: $PCR1"
echo "PCR2: $PCR2"

# Store PCR values in SSM (individual parameters - new path structure)
aws ssm put-parameter --name "/vettid/enclave/pcr/pcr0" --value "$PCR0" --type String --overwrite --region "$REGION"
aws ssm put-parameter --name "/vettid/enclave/pcr/pcr1" --value "$PCR1" --type String --overwrite --region "$REGION"
aws ssm put-parameter --name "/vettid/enclave/pcr/pcr2" --value "$PCR2" --type String --overwrite --region "$REGION"

# Also update legacy parameter path that parent process reads for attestation verification
# Parent expects /vettid/enclave/pcr0 (without /pcr/ prefix)
aws ssm put-parameter --name "/vettid/enclave/pcr0" --value "$PCR0" --type String --overwrite --region "$REGION"
log_info "Updated /vettid/enclave/pcr0 for parent attestation verification"

# Store combined PCR values for /vault/pcrs/current API endpoint
VERSION="$(date +%Y-%m-%d)-v1"
PUBLISHED_AT="$(date -Iseconds)"
PCR_JSON=$(cat <<PCRJSON
{"PCR0":"$PCR0","PCR1":"$PCR1","PCR2":"$PCR2","version":"$VERSION","published_at":"$PUBLISHED_AT"}
PCRJSON
)
aws ssm put-parameter --name "/vettid/enclave/pcr/current" --value "$PCR_JSON" --type String --overwrite --region "$REGION"
echo "Updated /vettid/enclave/pcr/current with version $VERSION"

# Install EIF to standard location
mkdir -p /opt/vettid/enclave
cp vettid-vault-enclave.eif /opt/vettid/enclave/

# Install parent binary
cd /opt/vettid/build/parent
go build -o /usr/local/bin/vettid-parent .

# Create systemd services
cat > /etc/systemd/system/vettid-enclave.service << 'SVCEOF'
[Unit]
Description=VettID Nitro Enclave
After=nitro-enclaves-allocator.service
Requires=nitro-enclaves-allocator.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/nitro-cli run-enclave --enclave-cid 16 --eif-path /opt/vettid/enclave/vettid-vault-enclave.eif --memory 6144 --cpu-count 2
ExecStop=/usr/bin/nitro-cli terminate-enclave --all

[Install]
WantedBy=multi-user.target
SVCEOF

cat > /etc/systemd/system/vettid-parent.service << 'SVCEOF'
[Unit]
Description=VettID Enclave Parent Process
After=vettid-enclave.service
Requires=vettid-enclave.service

[Service]
Type=simple
ExecStart=/usr/local/bin/vettid-parent --config /etc/vettid/parent.yaml
Restart=always
RestartSec=5
Environment=AWS_REGION=us-east-1

[Install]
WantedBy=multi-user.target
SVCEOF

# Create config directory and parent configuration
mkdir -p /etc/vettid

cat > /etc/vettid/parent.yaml << 'CONFIGEOF'
# VettID Parent Process Configuration

# Development mode (use TCP instead of vsock)
dev_mode: false

# NATS connection settings
nats:
  url: "nats://nats.internal.vettid.dev:4222"
  credentials_file: "/etc/vettid/nats.creds"
  reconnect_wait_ms: 2000
  max_reconnects: -1  # Unlimited

# S3 storage settings
s3:
  bucket: "vettid-vault-data-449757308783"
  region: "us-east-1"
  key_prefix: "vaults/"

# Enclave connection settings
enclave:
  cid: 16      # Enclave CID (assigned when enclave starts)
  port: 5000   # vsock port

# Health check settings
health:
  port: 8080
  interval_seconds: 30

# Handler loader settings (for WASM handler loading)
# Note: bucket and manifest_table use defaults from config.go
handlers:
  signing_key_secret_id: "vettid/handler-signing-key"

# KMS configuration for Nitro attestation-based sealing
# Key ARN is fetched at boot time from SSM parameter /vettid/nitro/sealing-key-arn
# This key requires PCR0 attestation for decryption
kms:
  sealing_key_arn: ""  # Set by init script from SSM
  region: "us-east-1"
CONFIGEOF

# Fetch KMS sealing key ARN and update config
KMS_ARN=$(aws ssm get-parameter --name /vettid/nitro/sealing-key-arn --region $REGION --query Parameter.Value --output text 2>/dev/null || echo "")
if [ -n "$KMS_ARN" ]; then
    sed -i "s|sealing_key_arn: \"\"|sealing_key_arn: \"$KMS_ARN\"|" /etc/vettid/parent.yaml
    echo "KMS sealing key ARN configured: $KMS_ARN"
fi

# Reload systemd and enable services for boot
systemctl daemon-reload
systemctl enable vettid-enclave.service
systemctl enable vettid-parent.service

# Flush filesystem buffers to ensure service files are persisted before AMI creation
sync

echo "=== Build complete ==="
echo "BUILD_SUCCESS" > /tmp/build-status
BUILDEOF

# Replace placeholders in build script
sed -i "s|__REGION__|$REGION|g" "$BUILD_SCRIPT"
sed -i "s|__S3_BUCKET__|$S3_BUCKET|g" "$BUILD_SCRIPT"
sed -i "s|__S3_KEY__|$S3_KEY|g" "$BUILD_SCRIPT"

# Upload build script to S3
BUILD_SCRIPT_S3_KEY="build-artifacts/build-script-$(date +%s).sh"
aws s3 cp "$BUILD_SCRIPT" "s3://$S3_BUCKET/$BUILD_SCRIPT_S3_KEY" --region "$REGION"
rm "$BUILD_SCRIPT"

log_info "Build script uploaded to s3://$S3_BUCKET/$BUILD_SCRIPT_S3_KEY"

# Send command via SSM to download and run the build script
COMMAND_ID=$(aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=[\"aws s3 cp s3://$S3_BUCKET/$BUILD_SCRIPT_S3_KEY /tmp/build.sh --region $REGION\",\"chmod +x /tmp/build.sh\",\"sudo /tmp/build.sh\"]" \
    --timeout-seconds "$BUILD_TIMEOUT" \
    --cloud-watch-output-config '{"CloudWatchOutputEnabled":true,"CloudWatchLogGroupName":"/vettid/enclave-build"}' \
    --query 'Command.CommandId' \
    --output text \
    --region "$REGION")

log_info "Build command started: $COMMAND_ID"
log_info "Waiting for build to complete (this may take 10-15 minutes)..."

# Wait for command to complete
while true; do
    STATUS=$(aws ssm get-command-invocation \
        --command-id "$COMMAND_ID" \
        --instance-id "$INSTANCE_ID" \
        --query 'Status' \
        --output text \
        --region "$REGION" 2>/dev/null || echo "Pending")

    case "$STATUS" in
        Success)
            log_info "Build completed successfully!"
            break
            ;;
        Failed|Cancelled|TimedOut)
            log_error "Build failed with status: $STATUS"
            # Get output for debugging
            aws ssm get-command-invocation \
                --command-id "$COMMAND_ID" \
                --instance-id "$INSTANCE_ID" \
                --region "$REGION"
            exit 1
            ;;
        *)
            echo -n "."
            sleep 10
            ;;
    esac
done
echo ""

# Clean up S3 artifacts
aws s3 rm "s3://$S3_BUCKET/$S3_KEY" --region "$REGION" || true
aws s3 rm "s3://$S3_BUCKET/$BUILD_SCRIPT_S3_KEY" --region "$REGION" || true

# Create AMI from the build instance
log_info "Creating AMI from build instance..."
AMI_NAME="vettid-enclave-$(date +%Y%m%d-%H%M%S)"
NEW_AMI_ID=$(aws ec2 create-image \
    --instance-id "$INSTANCE_ID" \
    --name "$AMI_NAME" \
    --description "VettID Nitro Enclave AMI - $(date)" \
    --no-reboot \
    --query 'ImageId' \
    --output text \
    --region "$REGION")

log_info "AMI creation started: $NEW_AMI_ID"

# Wait for AMI to be available
log_info "Waiting for AMI to be available..."
aws ec2 wait image-available --image-ids "$NEW_AMI_ID" --region "$REGION"
log_info "AMI is now available: $NEW_AMI_ID"

# Tag the AMI
aws ec2 create-tags \
    --resources "$NEW_AMI_ID" \
    --tags "Key=Name,Value=$AMI_NAME" "Key=Application,Value=vettid-enclave" "Key=BuildDate,Value=$(date -Iseconds)" \
    --region "$REGION"

# Update SSM parameter with new AMI ID
log_info "Updating SSM parameter with new AMI ID..."
aws ssm put-parameter \
    --name "$AMI_SSM_PARAM" \
    --value "$NEW_AMI_ID" \
    --type String \
    --overwrite \
    --region "$REGION"

log_info "SSM parameter updated: $AMI_SSM_PARAM = $NEW_AMI_ID"

# Get PCR0 value for verification
PCR0_VALUE=$(aws ssm get-parameter --name "$PCR0_SSM_PARAM" --query 'Parameter.Value' --output text --region "$REGION")
log_info "PCR0 value: $PCR0_VALUE"

# Find and refresh the ASG
log_info "Looking for enclave ASG..."
ASG_NAME=$(aws autoscaling describe-auto-scaling-groups \
    --query 'AutoScalingGroups[?contains(AutoScalingGroupName, `Enclave`)].AutoScalingGroupName' \
    --output text \
    --region "$REGION" | head -1)

if [ -n "$ASG_NAME" ] && [ "$ASG_NAME" != "None" ]; then
    log_info "Found ASG: $ASG_NAME"
    log_info "Starting instance refresh..."

    aws autoscaling start-instance-refresh \
        --auto-scaling-group-name "$ASG_NAME" \
        --preferences '{"MinHealthyPercentage": 0, "InstanceWarmup": 300}' \
        --region "$REGION" || log_warn "Instance refresh may already be in progress"

    log_info "Instance refresh started. New instances will use AMI: $NEW_AMI_ID"
else
    log_warn "No enclave ASG found. You may need to manually update launch template."
fi

log_info "=== Deployment Complete ==="
log_info "New AMI: $NEW_AMI_ID"
log_info "PCR0: $PCR0_VALUE"
log_info ""
log_info "Next steps:"
log_info "1. Verify instance refresh completes: aws autoscaling describe-instance-refreshes --auto-scaling-group-name $ASG_NAME"
log_info "2. Test enclave functionality"
log_info "3. Update KMS key policy if PCR0 changed (redeploy CDK)"
