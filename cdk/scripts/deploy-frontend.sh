#!/bin/bash
# deploy-frontend.sh - Deploy frontend with build-time config injection
# This script replaces placeholders in config.js with actual CDK output values

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDK_DIR="$(dirname "$SCRIPT_DIR")"
FRONTEND_DIR="$CDK_DIR/frontend"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}VettID Frontend Deployment${NC}"
echo "================================"

# Get CDK outputs
echo -e "${YELLOW}Fetching CDK stack outputs...${NC}"
STACK_NAME="VettIDStack"

# Use custom domain for API (required for httpOnly cookie to work across subdomains)
API_URL="https://api.vettid.dev"
REGION=$(aws configure get region || echo "us-east-1")
ADMIN_USER_POOL_ID=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query "Stacks[0].Outputs[?OutputKey=='OutAdminUserPoolId'].OutputValue" --output text)
MEMBER_USER_POOL_ID=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query "Stacks[0].Outputs[?OutputKey=='OutMemberUserPoolId'].OutputValue" --output text)
ADMIN_COGNITO_DOMAIN=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query "Stacks[0].Outputs[?OutputKey=='OutAdminCognitoDomain'].OutputValue" --output text)
ADMIN_CLIENT_ID=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query "Stacks[0].Outputs[?OutputKey=='OutAdminClientId'].OutputValue" --output text)
MEMBER_COGNITO_DOMAIN=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query "Stacks[0].Outputs[?OutputKey=='OutMemberCognitoDomain'].OutputValue" --output text)
MEMBER_CLIENT_ID=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query "Stacks[0].Outputs[?OutputKey=='OutMemberClientId'].OutputValue" --output text)
S3_BUCKET=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query "Stacks[0].Outputs[?OutputKey=='OutSiteBucket'].OutputValue" --output text)
DISTRIBUTION_ID=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query "Stacks[0].Outputs[?OutputKey=='OutDistributionId'].OutputValue" --output text)
ADMIN_DISTRIBUTION_ID=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query "Stacks[0].Outputs[?OutputKey=='OutAdminDistributionId'].OutputValue" --output text)

# Validate required values (API_URL is now hardcoded to custom domain)
if [[ -z "$API_URL" ]]; then
    echo -e "${RED}Error: API URL not set${NC}"
    exit 1
fi

echo "API URL: $API_URL"
echo "Region: $REGION"
echo "Admin User Pool ID: $ADMIN_USER_POOL_ID"
echo "Member User Pool ID: $MEMBER_USER_POOL_ID"
echo "S3 Bucket: $S3_BUCKET"

# Create temp directory for processed files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Copy frontend files to temp directory
cp -r "$FRONTEND_DIR"/* "$TEMP_DIR/"

# Replace placeholders in config.js
echo -e "${YELLOW}Injecting configuration values...${NC}"
CONFIG_FILE="$TEMP_DIR/shared/config.js"

if [[ -f "$CONFIG_FILE" ]]; then
    sed -i "s|__API_URL__|$API_URL|g" "$CONFIG_FILE"
    sed -i "s|__REGION__|$REGION|g" "$CONFIG_FILE"
    sed -i "s|__ADMIN_USER_POOL_ID__|$ADMIN_USER_POOL_ID|g" "$CONFIG_FILE"
    sed -i "s|__MEMBER_USER_POOL_ID__|$MEMBER_USER_POOL_ID|g" "$CONFIG_FILE"
    sed -i "s|__ADMIN_COGNITO_DOMAIN__|$ADMIN_COGNITO_DOMAIN|g" "$CONFIG_FILE"
    sed -i "s|__ADMIN_CLIENT_ID__|$ADMIN_CLIENT_ID|g" "$CONFIG_FILE"
    sed -i "s|__MEMBER_COGNITO_DOMAIN__|$MEMBER_COGNITO_DOMAIN|g" "$CONFIG_FILE"
    sed -i "s|__MEMBER_CLIENT_ID__|$MEMBER_CLIENT_ID|g" "$CONFIG_FILE"

    echo -e "${GREEN}Configuration injected successfully${NC}"
else
    echo -e "${RED}Error: config.js not found at $CONFIG_FILE${NC}"
    exit 1
fi

# Verify no placeholders remain
if grep -q "__API_URL__\|__REGION__\|__ADMIN_\|__MEMBER_" "$CONFIG_FILE"; then
    echo -e "${RED}Error: Some placeholders were not replaced${NC}"
    grep "__" "$CONFIG_FILE"
    exit 1
fi

# Replace placeholders in admin/index.html for CSP header
ADMIN_HTML="$TEMP_DIR/admin/index.html"
if [[ -f "$ADMIN_HTML" ]]; then
    sed -i "s|__API_URL__|$API_URL|g" "$ADMIN_HTML"
    sed -i "s|__ADMIN_COGNITO_DOMAIN__|$ADMIN_COGNITO_DOMAIN|g" "$ADMIN_HTML"
    echo -e "${GREEN}Admin HTML CSP header configured${NC}"
fi

# Replace placeholders in admin/login.html for CSP header
ADMIN_LOGIN_HTML="$TEMP_DIR/admin/login.html"
if [[ -f "$ADMIN_LOGIN_HTML" ]]; then
    sed -i "s|__API_URL__|$API_URL|g" "$ADMIN_LOGIN_HTML"
    sed -i "s|__ADMIN_COGNITO_DOMAIN__|$ADMIN_COGNITO_DOMAIN|g" "$ADMIN_LOGIN_HTML"
    echo -e "${GREEN}Admin Login HTML CSP header configured${NC}"
fi

# Replace placeholders in account/index.html for CSP header
ACCOUNT_HTML="$TEMP_DIR/account/index.html"
if [[ -f "$ACCOUNT_HTML" ]]; then
    sed -i "s|__API_URL__|$API_URL|g" "$ACCOUNT_HTML"
    sed -i "s|__MEMBER_COGNITO_DOMAIN__|$MEMBER_COGNITO_DOMAIN|g" "$ACCOUNT_HTML"
    echo -e "${GREEN}Account HTML CSP header configured${NC}"
fi

# Upload to S3
echo -e "${YELLOW}Uploading to S3...${NC}"
aws s3 sync "$TEMP_DIR" "s3://$S3_BUCKET" \
    --delete \
    --exclude ".git/*" \
    --exclude "*.md" \
    --cache-control "max-age=31536000" \
    --content-type "text/html" \
    --exclude "*" \
    --include "*.html"

aws s3 sync "$TEMP_DIR" "s3://$S3_BUCKET" \
    --exclude ".git/*" \
    --exclude "*.md" \
    --exclude "*.html" \
    --cache-control "max-age=86400"

# Set correct content types
aws s3 cp "s3://$S3_BUCKET/shared/config.js" "s3://$S3_BUCKET/shared/config.js" \
    --content-type "application/javascript" \
    --metadata-directive REPLACE \
    --cache-control "no-cache, no-store, must-revalidate"

# Copy shared and assets into admin directory (admin.vettid.dev uses OriginPath /admin)
echo -e "${YELLOW}Copying shared resources to admin directory...${NC}"
aws s3 cp "s3://$S3_BUCKET/shared/" "s3://$S3_BUCKET/admin/shared/" --recursive
aws s3 cp "s3://$S3_BUCKET/assets/" "s3://$S3_BUCKET/admin/assets/" --recursive

# Set correct content type for admin config.js
aws s3 cp "s3://$S3_BUCKET/admin/shared/config.js" "s3://$S3_BUCKET/admin/shared/config.js" \
    --content-type "application/javascript" \
    --metadata-directive REPLACE \
    --cache-control "no-cache, no-store, must-revalidate"

echo -e "${GREEN}Upload complete${NC}"

# Invalidate CloudFront cache
echo -e "${YELLOW}Invalidating CloudFront cache...${NC}"
aws cloudfront create-invalidation --distribution-id "$DISTRIBUTION_ID" --paths "/*" > /dev/null
if [[ -n "$ADMIN_DISTRIBUTION_ID" && "$ADMIN_DISTRIBUTION_ID" != "None" ]]; then
    aws cloudfront create-invalidation --distribution-id "$ADMIN_DISTRIBUTION_ID" --paths "/*" > /dev/null
fi

echo -e "${GREEN}Deployment complete!${NC}"
echo ""
echo "Site URLs:"
echo "  Main: https://vettid.dev"
echo "  Admin: https://admin.vettid.dev"
echo "  Account: https://vettid.dev/account"
