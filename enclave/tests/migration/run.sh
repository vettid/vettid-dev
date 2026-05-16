#!/usr/bin/env bash
# Tier-2 migration test harness entry point.
#
# Brings up the LocalStack + NATS + 2-parent compose stack, waits
# for both parents to report /ready, and (when implemented) runs
# the test driver. Without --keep, tears the stack down on exit.
#
# Usage:
#   ./run.sh                  # full sweep
#   ./run.sh happy-path       # single scenario by name
#   ./run.sh --keep           # leave the stack up after exit
#   ./run.sh --no-build       # skip image rebuild (faster iteration)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

KEEP=false
BUILD_FLAG=(--build)
SCENARIO=""

while [ $# -gt 0 ]; do
    case "$1" in
        --keep)     KEEP=true; shift ;;
        --no-build) BUILD_FLAG=(); shift ;;
        --help|-h)
            sed -n '2,12p' "$0"
            exit 0 ;;
        --*)        echo "unknown flag: $1" >&2; exit 2 ;;
        *)          SCENARIO="$1"; shift ;;
    esac
done

cleanup() {
    if [ "$KEEP" = true ]; then
        echo "==> --keep set; leaving stack up. Tear down with: docker compose -f $HERE/docker-compose.yml down -v"
        return
    fi
    echo "==> tearing down compose stack"
    docker compose -f "$HERE/docker-compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> docker compose up ${BUILD_FLAG[*]} -d"
docker compose -f "$HERE/docker-compose.yml" up "${BUILD_FLAG[@]}" -d

wait_for_ready() {
    local name="$1" port="$2" deadline=$(( $(date +%s) + 120 ))
    echo "==> waiting for $name on :$port"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if curl -sf "http://localhost:$port/ready" >/dev/null 2>&1; then
            echo "==> $name ready"
            return 0
        fi
        sleep 2
    done
    echo "==> $name did not report ready within 120s" >&2
    docker compose -f "$HERE/docker-compose.yml" logs --tail 80 "$name" >&2 || true
    return 1
}

wait_for_ready parent-old 8081
wait_for_ready parent-new 8082

if [ ! -d "$HERE/driver" ]; then
    echo "==> test driver not implemented yet; compose stack is up for manual inspection."
    echo "    parent-old: http://localhost:8081/ready"
    echo "    parent-new: http://localhost:8082/ready"
    echo "    pass --keep to skip teardown."
    exit 0
fi

echo "==> running test driver${SCENARIO:+ (scenario: $SCENARIO)}"
( cd "$HERE/driver" && go run . ${SCENARIO:+-scenario "$SCENARIO"} )
