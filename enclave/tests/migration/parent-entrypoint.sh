#!/usr/bin/env bash
# Container entrypoint for the Tier-2 migration harness "enclave"
# image. Starts the supervisor (TCP dev mode) and the parent in the
# same container so the parent can dial supervisor on localhost.
#
# Required env vars:
#   FAKE_PCR0_HEX           — 96 hex chars (48 bytes SHA-384) the
#                             supervisor will report as its running PCR0
#   AWS_ENDPOINT_URL        — LocalStack endpoint (KMS+S3+SSM)
#   AWS_REGION              — default us-east-1
#   AWS_ACCESS_KEY_ID       — anything (LocalStack ignores)
#   AWS_SECRET_ACCESS_KEY   — anything
#   NATS_URL                — e.g. nats://nats:4222
#   S3_BUCKET               — vettid-vault-data-test
#   KMS_SEALING_KEY_ARN     — from localstack-init SSM
#
# Renders /etc/vettid/parent.yaml from the template using envsubst,
# then exec-replaces this shell with `wait` so signals reach both
# children cleanly.

set -euo pipefail

: "${FAKE_PCR0_HEX:?FAKE_PCR0_HEX must be set}"
: "${NATS_URL:?NATS_URL must be set}"
: "${AWS_ENDPOINT_URL:=http://localstack:4566}"
: "${AWS_REGION:=us-east-1}"
# S3-specific endpoint used by parent's S3Client. Same host as
# AWS_ENDPOINT_URL by default — kept as a separate var so the
# yaml template can be opinionated about the S3 path-style flip
# without entangling KMS/SSM endpoint choice.
: "${S3_ENDPOINT:=$AWS_ENDPOINT_URL}"
: "${AWS_ACCESS_KEY_ID:=test}"
: "${AWS_SECRET_ACCESS_KEY:=test}"

# Source the ARN handoff written by the init container into the
# shared volume. Lets the parent-dev image stay aws-cli-free. `set -a`
# auto-exports every var defined by the sourced file so envsubst (a
# subprocess) actually sees them — without it, `${S3_BUCKET}` in the
# yaml template renders empty and parent's S3 client comes up with an
# empty bucket name.
if [ -n "${SHARED_ARNS:-}" ] && [ -f "$SHARED_ARNS" ]; then
    echo "==> sourcing ARNs from $SHARED_ARNS"
    set -a
    # shellcheck disable=SC1090
    . "$SHARED_ARNS"
    set +a
fi
: "${S3_BUCKET:?S3_BUCKET must be set (from /shared/arns.env or env)}"
: "${KMS_SEALING_KEY_ARN:?KMS_SEALING_KEY_ARN must be set (from /shared/arns.env or env)}"

export AWS_ENDPOINT_URL S3_ENDPOINT AWS_REGION AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

mkdir -p /etc/vettid
envsubst < /etc/vettid/parent.yaml.tmpl > /etc/vettid/parent.yaml
echo "==> rendered parent.yaml:"
cat /etc/vettid/parent.yaml

# vsock-secret file is what the production parent reads to authenticate
# to the supervisor over vsock. In dev/TCP mode it still has to exist
# so the handshake MAC is computable; the value isn't security-critical
# here because the harness is not exposed to anything beyond the docker
# network. Use a fixed test value so OLD and NEW both compute the same
# MAC.
mkdir -p /etc/vettid
echo -n "0000000000000000000000000000000000000000000000000000000000000000" > /etc/vettid/vsock-secret
chmod 0400 /etc/vettid/vsock-secret
cp /etc/vettid/vsock-secret /tmp/vettid-vsock-secret

echo "==> Starting supervisor (TCP dev mode, FAKE_PCR0_HEX=${FAKE_PCR0_HEX:0:16}…)"
/usr/local/bin/vettid-supervisor --dev-mode --tcp-port 5000 &
SUPERVISOR_PID=$!

# Give the supervisor a moment to bind :5000 before the parent dials.
# The parent will retry on connection-refused but starting them in
# order avoids noise in the logs.
sleep 1

echo "==> Starting parent (dials TCP localhost:5000)"
# `--dev-mode` is required: parent's CLI default is false and
# unconditionally overrides cfg.DevMode read from the yaml. Without
# this the parent tries vsock dial and crashes ("socket: operation
# not permitted") since this is a regular Linux container, not a
# Nitro host.
/usr/local/bin/vettid-parent --config /etc/vettid/parent.yaml --dev-mode &
PARENT_PID=$!

# Forward SIGTERM/SIGINT to both children so docker compose down is
# clean and we don't leave zombies on a kill-during scenario.
shutdown() {
    echo "==> shutdown signal — stopping parent ($PARENT_PID) and supervisor ($SUPERVISOR_PID)"
    kill -TERM "$PARENT_PID" "$SUPERVISOR_PID" 2>/dev/null || true
    wait "$PARENT_PID" "$SUPERVISOR_PID" 2>/dev/null || true
    exit 0
}
trap shutdown TERM INT

# If either child dies, the container should die too — otherwise a
# crashed parent would be invisible to docker.
wait -n "$SUPERVISOR_PID" "$PARENT_PID"
RC=$?
echo "==> a child exited with rc=$RC; tearing down container"
shutdown
