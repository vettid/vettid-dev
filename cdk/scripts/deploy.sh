#!/bin/bash
#
# VettID Full Deployment Script
#
# Usage:
#   ./scripts/deploy.sh                    # Deploy all stacks + frontend
#   ./scripts/deploy.sh --frontend-only    # Deploy frontend only
#   ./scripts/deploy.sh --infra-only       # Deploy infrastructure only
#   ./scripts/deploy.sh VettID-Infrastructure  # Deploy specific stack + frontend
#
# This script ensures proper deployment order:
# 1. Build TypeScript
# 2. Deploy CDK infrastructure (if requested)
# 3. Deploy frontend with config injection (if requested)
#
# WARNING: Never use 'aws s3 sync --delete' directly on frontend folders.
#          Always use this script or deploy-frontend.sh to preserve shared resources.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDK_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Parse arguments
DEPLOY_INFRA=true
DEPLOY_FRONTEND=true
STACKS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --frontend-only)
            DEPLOY_INFRA=false
            shift
            ;;
        --infra-only)
            DEPLOY_FRONTEND=false
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] [STACK_NAMES...]"
            echo ""
            echo "Options:"
            echo "  --frontend-only    Deploy frontend only (skip CDK)"
            echo "  --infra-only       Deploy infrastructure only (skip frontend)"
            echo "  --help, -h         Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                           # Deploy all stacks + frontend"
            echo "  $0 VettID-Infrastructure     # Deploy specific stack + frontend"
            echo "  $0 --frontend-only           # Deploy frontend only"
            exit 0
            ;;
        -*)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
        *)
            STACKS="$STACKS $1"
            shift
            ;;
    esac
done

cd "$CDK_DIR"

echo -e "${GREEN}VettID Deployment${NC}"
echo "================================"

# Step 1: Build TypeScript
echo -e "${YELLOW}Building TypeScript...${NC}"
npm run build

# Step 2: Deploy CDK infrastructure
if [ "$DEPLOY_INFRA" = true ]; then
    echo -e "${YELLOW}Deploying CDK infrastructure...${NC}"
    if [ -z "$STACKS" ]; then
        # Deploy all stacks
        npx cdk deploy --all --require-approval never
    else
        # Deploy specific stacks
        npx cdk deploy $STACKS --require-approval never
    fi
    echo -e "${GREEN}Infrastructure deployment complete${NC}"
else
    echo -e "${YELLOW}Skipping infrastructure deployment${NC}"
fi

# Step 3: Deploy frontend
if [ "$DEPLOY_FRONTEND" = true ]; then
    echo -e "${YELLOW}Deploying frontend...${NC}"
    bash "$SCRIPT_DIR/deploy-frontend.sh"
    echo -e "${GREEN}Frontend deployment complete${NC}"
else
    echo -e "${YELLOW}Skipping frontend deployment${NC}"
fi

echo ""
echo -e "${GREEN}Deployment complete!${NC}"
echo ""
echo "Site URLs:"
echo "  Main:    https://vettid.dev"
echo "  Admin:   https://admin.vettid.dev"
echo "  Account: https://account.vettid.dev"
