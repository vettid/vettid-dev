#!/bin/bash
# deploy-ses-templates.sh - Deploy SES email templates
# Creates or updates SES templates from template-*.json files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDK_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}VettID SES Template Deployment${NC}"
echo "================================"

# Track results
CREATED=0
UPDATED=0
FAILED=0

# Find all template-*.json files
TEMPLATE_FILES=$(find "$CDK_DIR" -maxdepth 1 -name "template-*.json" -type f | sort)

if [[ -z "$TEMPLATE_FILES" ]]; then
    echo -e "${RED}No template files found in $CDK_DIR${NC}"
    exit 1
fi

echo -e "${BLUE}Found template files:${NC}"
echo "$TEMPLATE_FILES" | while read -r file; do
    echo "  - $(basename "$file")"
done
echo ""

# Process each template
echo "$TEMPLATE_FILES" | while read -r TEMPLATE_FILE; do
    FILENAME=$(basename "$TEMPLATE_FILE")
    TEMPLATE_NAME=$(jq -r '.Template.TemplateName' "$TEMPLATE_FILE")

    if [[ -z "$TEMPLATE_NAME" || "$TEMPLATE_NAME" == "null" ]]; then
        echo -e "${RED}Error: Could not extract TemplateName from $FILENAME${NC}"
        continue
    fi

    echo -e "${YELLOW}Processing: $TEMPLATE_NAME${NC}"

    # Check if template exists
    if aws ses get-template --template-name "$TEMPLATE_NAME" &>/dev/null; then
        # Template exists, update it
        echo -e "  Template exists, updating..."
        if aws ses update-template --cli-input-json "file://$TEMPLATE_FILE" 2>/dev/null; then
            echo -e "  ${GREEN}Updated: $TEMPLATE_NAME${NC}"
        else
            echo -e "  ${RED}Failed to update: $TEMPLATE_NAME${NC}"
        fi
    else
        # Template doesn't exist, create it
        echo -e "  Template not found, creating..."
        if aws ses create-template --cli-input-json "file://$TEMPLATE_FILE" 2>/dev/null; then
            echo -e "  ${GREEN}Created: $TEMPLATE_NAME${NC}"
        else
            echo -e "  ${RED}Failed to create: $TEMPLATE_NAME${NC}"
        fi
    fi
done

echo ""
echo -e "${GREEN}SES template deployment complete!${NC}"
echo ""

# List all templates
echo -e "${BLUE}Current SES templates:${NC}"
aws ses list-templates --query 'TemplatesMetadata[*].Name' --output text | tr '\t' '\n' | sort | while read -r name; do
    if [[ -n "$name" ]]; then
        echo "  - $name"
    fi
done
