#!/bin/bash
# Build script for shared-utils Lambda layer
# Creates the nodejs/node_modules structure required by Lambda layers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Clean previous builds
rm -rf layer nodejs

# Build TypeScript
npm run build

# Create Lambda layer structure
mkdir -p layer/nodejs/node_modules/@vettid/shared-utils

# Copy compiled code and package.json
cp -r dist/* layer/nodejs/node_modules/@vettid/shared-utils/
cp package.json layer/nodejs/node_modules/@vettid/shared-utils/

# Copy production dependencies only
cd layer/nodejs/node_modules/@vettid/shared-utils
npm install --omit=dev --ignore-scripts
cd "$SCRIPT_DIR"

echo "Layer built successfully in: $SCRIPT_DIR/layer"
