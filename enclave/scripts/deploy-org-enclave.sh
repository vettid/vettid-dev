#!/bin/bash
# VettID Org Vault Enclave Deployment Script
#
# Builds the org vault EIF (Dockerfile.org-enclave) on a remote Nitro-capable
# EC2 instance via SSM, fetching the vsock secret from Secrets Manager.
#
# Designed for the demo: builds + runs the org vault enclave on a single instance.
# Production would use AMI baking similar to deploy-enclave.sh.
#
# Usage:
#   ./deploy-org-enclave.sh \
#     --instance-id i-xxxxx \
#     --staging-bucket vettid-demo-build-staging-XXX \
#     --vsock-secret-id vettid/demo-org-vsock-secret
#
# Required env: AWS_REGION (defaults to us-east-1)

set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"

ENCLAVE_INSTANCE_ID=""
STAGING_BUCKET=""
VSOCK_SECRET_ID="vettid/demo-org-vsock-secret"

while [[ $# -gt 0 ]]; do
    case $1 in
        --instance-id) ENCLAVE_INSTANCE_ID="$2"; shift 2 ;;
        --staging-bucket) STAGING_BUCKET="$2"; shift 2 ;;
        --vsock-secret-id) VSOCK_SECRET_ID="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [ -z "$ENCLAVE_INSTANCE_ID" ] || [ -z "$STAGING_BUCKET" ]; then
    echo "Usage: $0 --instance-id i-xxxxx --staging-bucket BUCKET [--vsock-secret-id SECRET]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENCLAVE_DIR="$(dirname "$SCRIPT_DIR")"

echo "==> 1/5: Tarballing enclave source"
TARBALL=$(mktemp /tmp/vettid-enclave-org-XXXXXX.tar.gz)
trap 'rm -f "$TARBALL"' EXIT

cd "$ENCLAVE_DIR"
tar -czf "$TARBALL" \
    --exclude='bin' \
    --exclude='*.eif' \
    --exclude='vsock-secret.hex' \
    supervisor org-vault-manager parent go.mod go.sum \
    Dockerfile.org-enclave Makefile

echo "    Tarball size: $(du -h "$TARBALL" | cut -f1)"

echo "==> 2/5: Uploading source to S3"
S3_KEY="org-enclave-source-$(date +%s).tar.gz"
aws s3 cp "$TARBALL" "s3://${STAGING_BUCKET}/${S3_KEY}" --region "$REGION"

echo "==> 3/5: Sending build command via SSM"

BUILD_SCRIPT=$(cat <<'BUILDSCRIPT'
set -euxo pipefail
REGION="__REGION__"
STAGING_BUCKET="__STAGING_BUCKET__"
S3_KEY="__S3_KEY__"
VSOCK_SECRET_ID="__VSOCK_SECRET_ID__"

BUILD_DIR=/opt/vettid/org-build
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
rm -rf ./*

aws s3 cp "s3://${STAGING_BUCKET}/${S3_KEY}" source.tar.gz --region "$REGION"
tar -xzf source.tar.gz
rm source.tar.gz

# Fetch vsock secret from Secrets Manager.
# CDK stores it as JSON {"secret": "..."}, so use jq to extract the raw hex.
SECRET_JSON=$(aws secretsmanager get-secret-value \
    --secret-id "$VSOCK_SECRET_ID" \
    --region "$REGION" \
    --query SecretString \
    --output text)
echo "$SECRET_JSON" | jq -r .secret > vsock-secret.hex
chmod 600 vsock-secret.hex
SECRET_LEN=$(wc -c < vsock-secret.hex)
if [ "$SECRET_LEN" -lt 32 ]; then
    echo "ERROR: vsock secret too short ($SECRET_LEN bytes)"
    exit 1
fi

docker build -q -f Dockerfile.org-enclave -t vettid-org-enclave:latest .

# SECURITY: Remove the vsock secret file from the build context after Docker build
rm -f vsock-secret.hex

nitro-cli build-enclave \
    --docker-uri vettid-org-enclave:latest \
    --output-file vettid-org-enclave.eif

nitro-cli describe-eif --eif-path vettid-org-enclave.eif

# Terminate any existing enclaves before launching the new one
nitro-cli describe-enclaves | jq -r '.[].EnclaveID' | while read ID; do
    if [ -n "$ID" ]; then
        nitro-cli terminate-enclave --enclave-id "$ID"
    fi
done

nitro-cli run-enclave \
    --eif-path vettid-org-enclave.eif \
    --memory 4096 \
    --cpu-count 2 \
    --enclave-cid 16

nitro-cli describe-enclaves
echo "Org vault enclave running"
BUILDSCRIPT
)

BUILD_SCRIPT="${BUILD_SCRIPT//__REGION__/$REGION}"
BUILD_SCRIPT="${BUILD_SCRIPT//__STAGING_BUCKET__/$STAGING_BUCKET}"
BUILD_SCRIPT="${BUILD_SCRIPT//__S3_KEY__/$S3_KEY}"
BUILD_SCRIPT="${BUILD_SCRIPT//__VSOCK_SECRET_ID__/$VSOCK_SECRET_ID}"

BUILD_SCRIPT_B64=$(echo "$BUILD_SCRIPT" | base64 -w0)

CMD_ID=$(aws ssm send-command \
    --instance-ids "$ENCLAVE_INSTANCE_ID" \
    --document-name AWS-RunShellScript \
    --comment "Build and run org vault EIF" \
    --parameters "commands=[\"echo $BUILD_SCRIPT_B64 | base64 -d | sudo bash\"]" \
    --region "$REGION" \
    --query 'Command.CommandId' \
    --output text)

echo "    SSM command: $CMD_ID"

echo "==> 4/5: Waiting for build to complete (up to 15 min)"
STATUS=""
for i in {1..90}; do
    STATUS=$(aws ssm get-command-invocation \
        --command-id "$CMD_ID" \
        --instance-id "$ENCLAVE_INSTANCE_ID" \
        --region "$REGION" \
        --query Status \
        --output text 2>/dev/null || echo "Pending")

    if [ "$STATUS" = "Success" ] || [ "$STATUS" = "Failed" ] || [ "$STATUS" = "Cancelled" ]; then
        break
    fi
    sleep 10
done

if [ "$STATUS" != "Success" ]; then
    echo "==> Build $STATUS"
    aws ssm get-command-invocation \
        --command-id "$CMD_ID" \
        --instance-id "$ENCLAVE_INSTANCE_ID" \
        --region "$REGION" \
        --query 'StandardErrorContent' \
        --output text
    exit 1
fi

echo "==> 5/5: Verifying enclave is running"
aws ssm send-command \
    --instance-ids "$ENCLAVE_INSTANCE_ID" \
    --document-name AWS-RunShellScript \
    --parameters 'commands=["nitro-cli describe-enclaves"]' \
    --region "$REGION" >/dev/null

echo
echo "==> Org vault enclave deployed and running on $ENCLAVE_INSTANCE_ID"
