#!/bin/bash
# VettID NATS Cluster AMI Deployment Script
#
# This script:
# 1. Launches an ARM64 EC2 instance for building
# 2. Installs NATS server, CLI, and configurations
# 3. Creates an AMI with everything pre-installed
# 4. Updates SSM parameter with new AMI ID
# 5. Triggers ASG instance refresh
# 6. Cleans up the build instance
#
# Usage: ./deploy-nats-ami.sh [--skip-cleanup]

set -euo pipefail

# Configuration
REGION="${AWS_REGION:-us-east-1}"
INSTANCE_TYPE="t4g.small"  # ARM64, enough for building
AMI_SSM_PARAM="/vettid/nats/ami-id"
ASG_NAME_PATTERN="NATS"
BUILD_TIMEOUT=600  # 10 minutes max for build

# NATS versions
NATS_SERVER_VERSION="2.10.24"
NATS_CLI_VERSION="0.3.0"

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

# Get VPC and subnet from existing NATS infrastructure
log_info "Finding NATS VPC and subnet..."
NATS_VPC_ID=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Name,Values=*NATS*" \
    --query 'Vpcs[0].VpcId' \
    --output text \
    --region "$REGION" 2>/dev/null || echo "None")

if [ "$NATS_VPC_ID" == "None" ] || [ -z "$NATS_VPC_ID" ]; then
    log_error "Could not find NATS VPC. Deploy VettID-NATS stack first."
    exit 1
fi
log_info "Using VPC: $NATS_VPC_ID"

# Get a private subnet in the NATS VPC
SUBNET_ID=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$NATS_VPC_ID" "Name=tag:aws-cdk:subnet-type,Values=Private" \
    --query 'Subnets[0].SubnetId' \
    --output text \
    --region "$REGION")

if [ -z "$SUBNET_ID" ] || [ "$SUBNET_ID" == "None" ]; then
    # Try public subnet if no private
    SUBNET_ID=$(aws ec2 describe-subnets \
        --filters "Name=vpc-id,Values=$NATS_VPC_ID" \
        --query 'Subnets[0].SubnetId' \
        --output text \
        --region "$REGION")
fi
log_info "Using subnet: $SUBNET_ID"

# Find Amazon Linux 2023 ARM64 AMI for build instance
log_info "Finding Amazon Linux 2023 ARM64 AMI..."
BUILD_AMI=$(aws ec2 describe-images \
    --owners amazon \
    --filters \
        "Name=name,Values=al2023-ami-2023*-arm64" \
        "Name=state,Values=available" \
        "Name=architecture,Values=arm64" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
    --output text \
    --region "$REGION")

if [ -z "$BUILD_AMI" ] || [ "$BUILD_AMI" == "None" ]; then
    log_error "Could not find Amazon Linux 2023 ARM64 AMI"
    exit 1
fi
log_info "Using build AMI: $BUILD_AMI"

# Get or create security group for build instance
log_info "Setting up security group..."
BUILD_SG_NAME="vettid-nats-build-sg"
BUILD_SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=$BUILD_SG_NAME" "Name=vpc-id,Values=$NATS_VPC_ID" \
    --query 'SecurityGroups[0].GroupId' \
    --output text \
    --region "$REGION" 2>/dev/null || echo "None")

if [ "$BUILD_SG_ID" == "None" ] || [ -z "$BUILD_SG_ID" ]; then
    log_info "Creating security group..."
    BUILD_SG_ID=$(aws ec2 create-security-group \
        --group-name "$BUILD_SG_NAME" \
        --description "Security group for VettID NATS AMI build instances" \
        --vpc-id "$NATS_VPC_ID" \
        --query 'GroupId' \
        --output text \
        --region "$REGION")
fi
log_info "Using security group: $BUILD_SG_ID"

# Get IAM instance profile from existing NATS ASG
log_info "Finding NATS instance profile..."
NATS_ASG=$(aws autoscaling describe-auto-scaling-groups \
    --query "AutoScalingGroups[?contains(AutoScalingGroupName, '$ASG_NAME_PATTERN')].AutoScalingGroupName" \
    --output text \
    --region "$REGION" | head -1)

if [ -z "$NATS_ASG" ] || [ "$NATS_ASG" == "None" ]; then
    log_error "Could not find NATS ASG. Deploy VettID-NATS stack first."
    exit 1
fi

# Get launch template from ASG
LAUNCH_TEMPLATE_ID=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$NATS_ASG" \
    --query 'AutoScalingGroups[0].LaunchTemplate.LaunchTemplateId' \
    --output text \
    --region "$REGION" 2>/dev/null || echo "")

if [ -z "$LAUNCH_TEMPLATE_ID" ] || [ "$LAUNCH_TEMPLATE_ID" == "None" ]; then
    # Try MixedInstancesPolicy
    LAUNCH_TEMPLATE_ID=$(aws autoscaling describe-auto-scaling-groups \
        --auto-scaling-group-names "$NATS_ASG" \
        --query 'AutoScalingGroups[0].MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification.LaunchTemplateId' \
        --output text \
        --region "$REGION" 2>/dev/null || echo "")
fi

INSTANCE_PROFILE_ARN=""
if [ -n "$LAUNCH_TEMPLATE_ID" ] && [ "$LAUNCH_TEMPLATE_ID" != "None" ]; then
    INSTANCE_PROFILE_ARN=$(aws ec2 describe-launch-template-versions \
        --launch-template-id "$LAUNCH_TEMPLATE_ID" \
        --versions '$Latest' \
        --query 'LaunchTemplateVersions[0].LaunchTemplateData.IamInstanceProfile.Arn' \
        --output text \
        --region "$REGION" 2>/dev/null || echo "")
fi

if [ -z "$INSTANCE_PROFILE_ARN" ] || [ "$INSTANCE_PROFILE_ARN" == "None" ]; then
    log_warn "Could not find instance profile from launch template, using default"
    INSTANCE_PROFILE_NAME="vettid-nats-instance-profile"
else
    INSTANCE_PROFILE_NAME=$(basename "$INSTANCE_PROFILE_ARN")
fi
log_info "Using instance profile: $INSTANCE_PROFILE_NAME"

# Create user data script for build instance
log_info "Creating user data script..."
USER_DATA=$(cat << 'USERDATA'
#!/bin/bash
set -euxo pipefail
exec > >(tee /var/log/user-data.log) 2>&1

echo "=== Installing dependencies ==="
dnf update -y
dnf install -y jq awscli openssl unzip

echo "=== Creating nats user ==="
useradd -r -s /sbin/nologin nats || true

echo "=== Downloading NATS Server ==="
NATS_VERSION="__NATS_SERVER_VERSION__"
curl -L -o /tmp/nats-server.tar.gz "https://github.com/nats-io/nats-server/releases/download/v${NATS_VERSION}/nats-server-v${NATS_VERSION}-linux-arm64.tar.gz"
tar -xzf /tmp/nats-server.tar.gz -C /tmp
mv /tmp/nats-server-v${NATS_VERSION}-linux-arm64/nats-server /usr/local/bin/
chmod +x /usr/local/bin/nats-server
rm -rf /tmp/nats-server*

echo "=== Downloading NATS CLI ==="
NATS_CLI_VERSION="__NATS_CLI_VERSION__"
curl -L -o /tmp/nats-cli.zip "https://github.com/nats-io/natscli/releases/download/v${NATS_CLI_VERSION}/nats-${NATS_CLI_VERSION}-linux-arm64.zip"
unzip -q /tmp/nats-cli.zip -d /tmp
mv /tmp/nats-${NATS_CLI_VERSION}-linux-arm64/nats /usr/local/bin/
chmod +x /usr/local/bin/nats
rm -rf /tmp/nats-cli* /tmp/nats-${NATS_CLI_VERSION}*

echo "=== Verifying installations ==="
/usr/local/bin/nats-server --version
/usr/local/bin/nats --version

echo "=== Creating directories ==="
mkdir -p /etc/nats /var/lib/nats/jetstream /var/lib/nats/resolver /var/log/nats
chown -R nats:nats /var/lib/nats /var/log/nats

echo "=== Creating systemd service ==="
cat > /etc/systemd/system/nats.service << 'SVCEOF'
[Unit]
Description=NATS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nats
Group=nats
ExecStart=/usr/local/bin/nats-server -c /etc/nats/nats.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF

echo "=== Creating startup script ==="
# This script runs at boot to configure instance-specific settings
cat > /usr/local/bin/nats-init.sh << 'INITEOF'
#!/bin/bash
set -e

# Use IMDSv2 for metadata
IMDS_TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
REGION=$(curl -sf -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
INSTANCE_ID=$(curl -sf -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
PRIVATE_IP=$(curl -sf -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)

echo "Initializing NATS for instance $INSTANCE_ID at $PRIVATE_IP"

# Fetch operator JWT from Secrets Manager
OPERATOR_JWT=$(aws secretsmanager get-secret-value \
    --secret-id vettid/nats/operator-jwt \
    --query SecretString \
    --output text \
    --region "$REGION" 2>/dev/null || echo "")

if [ -z "$OPERATOR_JWT" ]; then
    echo "WARNING: Operator JWT not found in Secrets Manager"
fi

# Fetch system account JWT from API
ACCOUNT_RESOLVER_URL=$(aws ssm get-parameter \
    --name /vettid/nats/account-resolver-url \
    --query Parameter.Value \
    --output text \
    --region "$REGION" 2>/dev/null || echo "")

SYSTEM_ACCOUNT_JWT=""
if [ -n "$ACCOUNT_RESOLVER_URL" ]; then
    # Get system account public key
    SYS_ACCOUNT_PK=$(aws ssm get-parameter \
        --name /vettid/nats/system-account-pk \
        --query Parameter.Value \
        --output text \
        --region "$REGION" 2>/dev/null || echo "")

    if [ -n "$SYS_ACCOUNT_PK" ]; then
        SYSTEM_ACCOUNT_JWT=$(curl -sf "${ACCOUNT_RESOLVER_URL}${SYS_ACCOUNT_PK}" 2>/dev/null || echo "")
    fi
fi

# Create NATS configuration
# Note: TLS disabled - data is encrypted at application layer
cat > /etc/nats/nats.conf << CONFEOF
# VettID NATS Server Configuration
# Instance: ${INSTANCE_ID}
# Generated at: $(date -Iseconds)

server_name: nats-${INSTANCE_ID}
listen: 0.0.0.0:4222

# Cluster configuration
cluster {
    name: vettid-nats
    listen: 0.0.0.0:6222

    routes = [
        nats-route://cluster.internal.vettid.dev:6222
    ]
}

# HTTP monitoring
http: 0.0.0.0:8222

# JetStream configuration
jetstream {
    store_dir: /var/lib/nats/jetstream
    max_mem: 256MB
    max_file: 10GB
}

# Logging
debug: false
trace: false
logtime: true
log_file: /var/log/nats/nats.log

# Limits
max_connections: 10000
max_payload: 1MB
max_pending: 64MB

# Note: TLS disabled for internal connections
# Data is already encrypted at the application layer (Protean Credential)
# and NATS is only accessible within the private VPC
CONFEOF

# Add operator/resolver config if available
if [ -n "$OPERATOR_JWT" ]; then
    cat >> /etc/nats/nats.conf << AUTHEOF

# JWT-based authentication
operator: /etc/nats/operator.jwt

# System account for internal operations
system_account: ${SYS_ACCOUNT_PK:-SYS}

# Account resolver
resolver: {
    type: full
    dir: /var/lib/nats/resolver
    allow_delete: false
    interval: "2m"
    limit: 1000
}

# Pre-load system account
resolver_preload: {
    ${SYS_ACCOUNT_PK:-SYS}: ${SYSTEM_ACCOUNT_JWT:-""}
}
AUTHEOF

    # Write operator JWT
    echo "$OPERATOR_JWT" > /etc/nats/operator.jwt
    chown nats:nats /etc/nats/operator.jwt
    chmod 600 /etc/nats/operator.jwt
fi

chown nats:nats /etc/nats/nats.conf

echo "NATS initialization complete"
INITEOF

chmod +x /usr/local/bin/nats-init.sh

echo "=== Creating boot service ==="
cat > /etc/systemd/system/nats-init.service << 'BOOTSVC'
[Unit]
Description=NATS Initialization
Before=nats.service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/nats-init.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
BOOTSVC

systemctl daemon-reload
systemctl enable nats-init.service
systemctl enable nats.service

echo "=== Syncing filesystem ==="
sync
sleep 2
sync

echo "=== Build complete ==="
touch /tmp/build-ready
sync
USERDATA
)

# Replace version placeholders
USER_DATA=$(echo "$USER_DATA" | sed "s/__NATS_SERVER_VERSION__/$NATS_SERVER_VERSION/g")
USER_DATA=$(echo "$USER_DATA" | sed "s/__NATS_CLI_VERSION__/$NATS_CLI_VERSION/g")

# Launch build instance
log_info "Launching build instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "$BUILD_AMI" \
    --instance-type "$INSTANCE_TYPE" \
    --subnet-id "$SUBNET_ID" \
    --security-group-ids "$BUILD_SG_ID" \
    --iam-instance-profile "Name=$INSTANCE_PROFILE_NAME" \
    --user-data "$USER_DATA" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=vettid-nats-ami-build},{Key=Purpose,Value=AMI-Build},{Key=AutoCleanup,Value=true}]" \
    --query 'Instances[0].InstanceId' \
    --output text \
    --region "$REGION")

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
    log_info "Build instance terminated"
}

trap cleanup EXIT

# Wait for instance to be running
log_info "Waiting for instance to be running..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

# Get instance IP
INSTANCE_IP=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' \
    --output text \
    --region "$REGION")

log_info "Instance IP: $INSTANCE_IP"

# Wait for SSM agent and user data to complete
log_info "Waiting for SSM agent and build to complete..."
WAIT_COUNT=0
MAX_WAIT=120  # 10 minutes max

while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    # Check if SSM agent is online
    SSM_STATUS=$(aws ssm describe-instance-information \
        --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
        --query 'InstanceInformationList[0].PingStatus' \
        --output text \
        --region "$REGION" 2>/dev/null || echo "Offline")

    if [ "$SSM_STATUS" = "Online" ]; then
        # Check if build completed
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
                log_info "Build completed successfully!"
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
    log_error "Timeout waiting for build to complete"
    exit 1
fi

# Verify NATS installation
log_info "Verifying NATS installation..."
VERIFY_CMD=$(aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["/usr/local/bin/nats-server --version","/usr/local/bin/nats --version","systemctl is-enabled nats.service","systemctl is-enabled nats-init.service"]' \
    --query 'Command.CommandId' \
    --output text \
    --region "$REGION")

sleep 5
VERIFY_OUTPUT=$(aws ssm get-command-invocation \
    --command-id "$VERIFY_CMD" \
    --instance-id "$INSTANCE_ID" \
    --query 'StandardOutputContent' \
    --output text \
    --region "$REGION")

log_info "Verification output:"
echo "$VERIFY_OUTPUT"

# Create AMI from the build instance
log_info "Creating AMI from build instance..."
AMI_NAME="vettid-nats-$(date +%Y%m%d-%H%M%S)"
NEW_AMI_ID=$(aws ec2 create-image \
    --instance-id "$INSTANCE_ID" \
    --name "$AMI_NAME" \
    --description "VettID NATS Cluster AMI - NATS $NATS_SERVER_VERSION - $(date)" \
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
    --tags "Key=Name,Value=$AMI_NAME" "Key=Application,Value=vettid-nats" "Key=NatsVersion,Value=$NATS_SERVER_VERSION" "Key=BuildDate,Value=$(date -Iseconds)" \
    --region "$REGION"

# Create/update SSM parameter with new AMI ID
log_info "Updating SSM parameter with new AMI ID..."
aws ssm put-parameter \
    --name "$AMI_SSM_PARAM" \
    --value "$NEW_AMI_ID" \
    --type String \
    --overwrite \
    --region "$REGION" 2>/dev/null || \
aws ssm put-parameter \
    --name "$AMI_SSM_PARAM" \
    --value "$NEW_AMI_ID" \
    --type String \
    --region "$REGION"

log_info "SSM parameter updated: $AMI_SSM_PARAM = $NEW_AMI_ID"

# Find and refresh the ASG
log_info "Starting instance refresh for ASG: $NATS_ASG"
aws autoscaling start-instance-refresh \
    --auto-scaling-group-name "$NATS_ASG" \
    --preferences '{"MinHealthyPercentage": 50, "InstanceWarmup": 300}' \
    --region "$REGION" || log_warn "Instance refresh may already be in progress"

log_info "=== Deployment Complete ==="
log_info "New AMI: $NEW_AMI_ID"
log_info "NATS Server Version: $NATS_SERVER_VERSION"
log_info "NATS CLI Version: $NATS_CLI_VERSION"
log_info ""
log_info "Next steps:"
log_info "1. Verify instance refresh: aws autoscaling describe-instance-refreshes --auto-scaling-group-name $NATS_ASG"
log_info "2. Update CDK to use AMI from SSM parameter instead of user data installation"
log_info "3. Test NATS cluster connectivity"
