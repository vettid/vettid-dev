#!/usr/bin/env bash
# LocalStack bootstrap for the Tier-2 migration test harness.
# Creates the AWS resources the production parent expects to find.
#
# Status: scaffolded but unused — the harness it supports isn't
# runnable yet (see ../README.md for the missing dev-mode hooks).
# When complete this script runs once before the parent containers
# start, idempotent so re-runs work.

set -euo pipefail

aws() {
    command aws --endpoint-url "${AWS_ENDPOINT_URL:-http://localstack:4566}" "$@"
}

echo "==> Create S3 vault data bucket"
aws s3 mb s3://vettid-vault-data-test --region us-east-1 || true

echo "==> Create KMS sealing key (enclave attestation policy is no-op in LocalStack)"
SEALING_ARN=$(aws kms create-key \
    --description "vettid-enclave-sealing (test)" \
    --key-usage ENCRYPT_DECRYPT \
    --key-spec SYMMETRIC_DEFAULT \
    --query 'KeyMetadata.Arn' --output text)
aws kms create-alias --alias-name alias/vettid-enclave-sealing --target-key-id "$SEALING_ARN" || true

echo "==> Create KMS PCR signing key (ECDSA P-256)"
SIGNING_ARN=$(aws kms create-key \
    --description "vettid-pcr-signing (test)" \
    --key-usage SIGN_VERIFY \
    --key-spec ECC_NIST_P256 \
    --query 'KeyMetadata.Arn' --output text)
aws kms create-alias --alias-name alias/vettid-pcr-signing --target-key-id "$SIGNING_ARN" || true

echo "==> Write SSM parameters the parent reads at startup"
aws ssm put-parameter --name /vettid/nitro/sealing-key-arn --type String --value "$SEALING_ARN" --overwrite
aws ssm put-parameter --name /vettid/nitro/vault-data-bucket --type String --value "vettid-vault-data-test" --overwrite
aws ssm put-parameter --name /vettid/attestation/pcr-signing-key-arn --type String --value "$SIGNING_ARN" --overwrite
aws ssm put-parameter --name /vettid/attestation/pcr-signing-key-id --type String --value "$(basename "$SIGNING_ARN")" --overwrite

echo "==> LocalStack bootstrap complete"
echo "    sealing key: $SEALING_ARN"
echo "    signing key: $SIGNING_ARN"

# Hand ARNs off to the parent containers via the shared volume. The
# parent-dev image deliberately doesn't bake aws-cli in just so it
# can read back values we already know here.
if [ -d /shared ]; then
    cat > /shared/arns.env <<EOF
KMS_SEALING_KEY_ARN=$SEALING_ARN
KMS_PCR_SIGNING_KEY_ARN=$SIGNING_ARN
S3_BUCKET=vettid-vault-data-test
EOF
    echo "==> wrote /shared/arns.env for parent containers"
fi
