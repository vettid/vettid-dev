#!/bin/bash
set -euo pipefail

# terminate-enclave-fleet.sh
# Terminates the old enclave fleet after successful migration.
# Should only be run after verification period completes.
#
# Usage:
#   ./terminate-enclave-fleet.sh --environment staging

ENVIRONMENT=""
FORCE=false

# ASG names by environment
declare -A OLD_ASG=(
    ["staging"]="vettid-enclave-old-staging"
    ["production"]="vettid-enclave-old-prod"
)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 --environment <staging|production> [--force]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validation
if [[ -z "$ENVIRONMENT" ]]; then
    echo "Error: --environment is required"
    exit 1
fi

if [[ ! -v "OLD_ASG[$ENVIRONMENT]" ]]; then
    echo "Error: Unknown environment: $ENVIRONMENT"
    exit 1
fi

ASG_NAME="${OLD_ASG[$ENVIRONMENT]}"

echo "=== Terminating Old Enclave Fleet ==="
echo "Environment: $ENVIRONMENT"
echo "ASG: $ASG_NAME"
echo ""

# Check if ASG exists
ASG_EXISTS=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$ASG_NAME" \
    --query 'AutoScalingGroups[0].AutoScalingGroupName' \
    --output text 2>/dev/null) || ASG_EXISTS="None"

if [[ "$ASG_EXISTS" == "None" ]] || [[ -z "$ASG_EXISTS" ]]; then
    echo "ASG $ASG_NAME does not exist or already deleted"
    exit 0
fi

# Get current capacity
CURRENT_CAPACITY=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$ASG_NAME" \
    --query 'AutoScalingGroups[0].DesiredCapacity' \
    --output text)

echo "Current capacity: $CURRENT_CAPACITY"

if [[ "$CURRENT_CAPACITY" -gt 0 ]]; then
    if [[ "$FORCE" != true ]]; then
        echo ""
        echo "Warning: ASG still has $CURRENT_CAPACITY instances"
        echo "Use --force to terminate anyway"
        exit 1
    fi

    echo ""
    echo "Scaling down to 0 instances..."

    # Scale down to 0
    aws autoscaling update-auto-scaling-group \
        --auto-scaling-group-name "$ASG_NAME" \
        --min-size 0 \
        --max-size 0 \
        --desired-capacity 0

    # Wait for instances to terminate
    echo "Waiting for instances to terminate..."
    MAX_WAIT=300
    WAITED=0

    while [[ $WAITED -lt $MAX_WAIT ]]; do
        INSTANCE_COUNT=$(aws autoscaling describe-auto-scaling-groups \
            --auto-scaling-group-names "$ASG_NAME" \
            --query 'AutoScalingGroups[0].Instances | length(@)' \
            --output text)

        if [[ "$INSTANCE_COUNT" == "0" ]]; then
            echo "All instances terminated"
            break
        fi

        echo "  Remaining instances: $INSTANCE_COUNT"
        sleep 10
        WAITED=$((WAITED + 10))
    done

    if [[ $WAITED -ge $MAX_WAIT ]]; then
        echo "Warning: Timeout waiting for instances to terminate"
    fi
fi

echo ""
echo "Deleting Auto Scaling Group..."

# Delete the ASG
aws autoscaling delete-auto-scaling-group \
    --auto-scaling-group-name "$ASG_NAME" \
    --force-delete

echo "ASG deletion initiated"

# Delete associated launch template (if exists)
LAUNCH_TEMPLATE="${ASG_NAME}-lt"
echo ""
echo "Checking for launch template: $LAUNCH_TEMPLATE"

LT_EXISTS=$(aws ec2 describe-launch-templates \
    --launch-template-names "$LAUNCH_TEMPLATE" \
    --query 'LaunchTemplates[0].LaunchTemplateName' \
    --output text 2>/dev/null) || LT_EXISTS="None"

if [[ "$LT_EXISTS" != "None" ]] && [[ -n "$LT_EXISTS" ]]; then
    echo "Deleting launch template..."
    aws ec2 delete-launch-template --launch-template-name "$LAUNCH_TEMPLATE"
    echo "Launch template deleted"
else
    echo "No launch template found"
fi

echo ""
echo "=== Old Fleet Termination Complete ==="
