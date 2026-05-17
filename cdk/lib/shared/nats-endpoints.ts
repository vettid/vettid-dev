/**
 * Canonical NATS endpoint constants.
 *
 * SECURITY (#117): single source of truth for the internal NATS endpoint
 * literals that used to be duplicated across vault-stack.ts (Lambda env
 * vars), nitro-stack.ts (parent.yaml render), parent/config.go (Go
 * fallback), parent.yaml.example, deploy-enclave.sh, and
 * enclave/test/main.go.
 *
 * The domain is derived from the public zone name passed to NatsStack
 * (currently `vettid.dev`); keep this file in sync with that prop. The
 * NatsStack itself reads `internalNatsDomain` from `props.zoneName`, so
 * this constant only needs an update if the production zone moves.
 */

export const NATS_INTERNAL_PORT = 4222;
export const NATS_INTERNAL_HOST = 'nats.internal.vettid.dev';
export const NATS_INTERNAL_ENDPOINT = `${NATS_INTERNAL_HOST}:${NATS_INTERNAL_PORT}`;
export const NATS_INTERNAL_URL = `nats://${NATS_INTERNAL_ENDPOINT}`;
