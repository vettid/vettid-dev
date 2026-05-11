#!/usr/bin/env bash
# Tier-2 migration test harness entry point — STUB
#
# Status: not yet runnable. Prints the design checkpoint message
# until the dev-mode hooks documented in README.md are in place.
#
# Once those land, this script will:
#   1. docker compose up -d (LocalStack + NATS + init)
#   2. Wait for init to complete
#   3. docker compose up -d parent-old parent-new
#   4. Wait for both /ready endpoints
#   5. Run the test driver against the running stack
#   6. docker compose down (unless --keep)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cat <<'EOF' >&2
Tier-2 migration test harness is scaffolded but not yet runnable.

Required production-code changes before this will work:
  - supervisor/config.go: FakePCR0 env var (DevMode-gated)
  - supervisor/sealer_handler.go: in-process fake-KMS (DevMode-gated)
  - parent/parent.go: skip vsock attestation in DevMode (extend existing TCP fallback)
  - tests/migration/Dockerfile.parent-dev: build the parent image with DevMode=true
  - tests/migration/driver/: Go test driver (publishes NATS RPCs, asserts state)

See tests/migration/README.md for the full design checkpoint and
list of test scenarios to implement.

EOF

exit 1
