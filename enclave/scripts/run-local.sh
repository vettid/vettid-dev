#!/bin/bash
# Run VettID enclave components locally for development
# This runs the supervisor and parent process outside of an actual enclave
# Useful for development and testing without Nitro hardware

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENCLAVE_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== VettID Local Development Mode ==="
echo "WARNING: This runs outside of Nitro enclave - no attestation or sealing available"
echo ""

# Check if binaries are built
if [[ ! -f "$ENCLAVE_DIR/bin/supervisor" ]]; then
    echo "Building binaries..."
    cd "$ENCLAVE_DIR" && make build-local
fi

# Create local directories
mkdir -p /tmp/vettid-enclave/{state,logs}

# Set development environment variables
export VETTID_DEV_MODE=true
export VETTID_STATE_DIR=/tmp/vettid-enclave/state
export VETTID_LOG_DIR=/tmp/vettid-enclave/logs
export VETTID_VSOCK_PORT=5000  # Use TCP for local dev instead of vsock

echo "Starting supervisor in local dev mode..."
echo "  State dir: $VETTID_STATE_DIR"
echo "  Log dir: $VETTID_LOG_DIR"
echo "  TCP port: $VETTID_VSOCK_PORT (simulating vsock)"
echo ""

# Run supervisor
exec "$ENCLAVE_DIR/bin/supervisor" --dev-mode
