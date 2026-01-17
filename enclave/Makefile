# VettID Nitro Enclave Build System

.PHONY: all build-docker build-eif run-enclave stop-enclave validate-pcrs clean help

# Configuration
ENCLAVE_NAME := vettid-vault-enclave
DOCKER_IMAGE := vettid-enclave:latest
EIF_FILE := $(ENCLAVE_NAME).eif
ENCLAVE_CONFIG := enclave.json

# Memory and CPU allocation (must match enclave.json)
# Optimized for native Go handlers - 75% of c6a.2xlarge resources
MEMORY_MIB := 12288
CPU_COUNT := 6

# Build all components
all: build-docker build-eif

# Build the Docker image for the enclave
build-docker:
	@echo "Building Docker image for enclave..."
	docker build -f Dockerfile.enclave -t $(DOCKER_IMAGE) .

# Convert Docker image to EIF (Enclave Image Format)
build-eif: build-docker
	@echo "Converting Docker image to EIF..."
	nitro-cli build-enclave \
		--docker-uri $(DOCKER_IMAGE) \
		--output-file $(EIF_FILE)
	@echo "EIF built successfully: $(EIF_FILE)"
	@echo "PCR values:"
	@nitro-cli describe-eif --eif-path $(EIF_FILE) | grep -A 10 "PCR"

# Run the enclave (requires Nitro-enabled EC2 instance)
run-enclave: $(EIF_FILE)
	@echo "Starting enclave..."
	nitro-cli run-enclave \
		--enclave-cid 16 \
		--eif-path $(EIF_FILE) \
		--memory $(MEMORY_MIB) \
		--cpu-count $(CPU_COUNT)

# Run enclave in debug mode (allows console access)
run-enclave-debug: $(EIF_FILE)
	@echo "Starting enclave in debug mode..."
	nitro-cli run-enclave \
		--enclave-cid 16 \
		--eif-path $(EIF_FILE) \
		--memory $(MEMORY_MIB) \
		--cpu-count $(CPU_COUNT) \
		--debug-mode

# Attach to debug console (requires debug mode)
console:
	nitro-cli console --enclave-id $$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

# Stop the enclave
stop-enclave:
	@echo "Stopping enclave..."
	nitro-cli terminate-enclave --all

# Describe running enclaves
describe:
	nitro-cli describe-enclaves

# Validate PCR values against expected
validate-pcrs: $(EIF_FILE)
	./scripts/validate-pcrs.sh $(EIF_FILE)

# Build Go binaries locally (for testing without Docker)
build-local:
	@echo "Building supervisor..."
	cd supervisor && go build -o ../bin/supervisor .
	@echo "Building vault-manager..."
	cd vault-manager && go build -o ../bin/vault-manager .

# Run tests
test:
	cd supervisor && go test -v ./...
	cd vault-manager && go test -v ./...

# Clean build artifacts
clean:
	rm -f $(EIF_FILE)
	rm -rf bin/
	docker rmi $(DOCKER_IMAGE) 2>/dev/null || true

# Show help
help:
	@echo "VettID Nitro Enclave Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build Docker image and EIF"
	@echo "  build-docker     - Build Docker image only"
	@echo "  build-eif        - Build EIF from Docker image"
	@echo "  run-enclave      - Start the enclave"
	@echo "  run-enclave-debug- Start enclave in debug mode"
	@echo "  console          - Attach to debug console"
	@echo "  stop-enclave     - Stop running enclave"
	@echo "  describe         - Show running enclaves"
	@echo "  validate-pcrs    - Validate PCR values"
	@echo "  build-local      - Build Go binaries locally"
	@echo "  test             - Run tests"
	@echo "  clean            - Remove build artifacts"
	@echo "  help             - Show this help"
