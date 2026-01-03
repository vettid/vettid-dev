#!/bin/bash
# Build VettID Nitro Enclave Image
# This script builds the Docker image and converts it to EIF format

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENCLAVE_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${OUTPUT_DIR:-$ENCLAVE_DIR}"

DOCKER_IMAGE="vettid-enclave:latest"
EIF_FILE="$OUTPUT_DIR/vettid-vault-enclave.eif"

echo "=== VettID Nitro Enclave Build ==="
echo "Building from: $ENCLAVE_DIR"
echo "Output: $EIF_FILE"
echo ""

# Check for nitro-cli
if ! command -v nitro-cli &> /dev/null; then
    echo "Error: nitro-cli not found. Install with:"
    echo "  sudo amazon-linux-extras install aws-nitro-enclaves-cli"
    echo "  sudo yum install aws-nitro-enclaves-cli-devel"
    exit 1
fi

# Build Docker image
echo "=== Building Docker image ==="
cd "$ENCLAVE_DIR"
docker build -f Dockerfile.enclave -t "$DOCKER_IMAGE" .

# Build EIF
echo ""
echo "=== Building EIF ==="
nitro-cli build-enclave \
    --docker-uri "$DOCKER_IMAGE" \
    --output-file "$EIF_FILE"

# Extract and display PCR values
echo ""
echo "=== PCR Values (save these for attestation verification) ==="
nitro-cli describe-eif --eif-path "$EIF_FILE" | tee "$OUTPUT_DIR/pcr-values.json"

# Save PCRs to a separate file for app configuration
echo ""
echo "=== Extracting PCRs for app configuration ==="
nitro-cli describe-eif --eif-path "$EIF_FILE" | jq '{
  pcr0: .PCR0,
  pcr1: .PCR1,
  pcr2: .PCR2,
  build_time: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
}' > "$OUTPUT_DIR/expected-pcrs.json"

echo ""
echo "Build complete!"
echo "  EIF: $EIF_FILE"
echo "  PCRs: $OUTPUT_DIR/expected-pcrs.json"
echo ""
echo "To run the enclave:"
echo "  nitro-cli run-enclave --enclave-cid 16 --eif-path $EIF_FILE --memory 6144 --cpu-count 2"
