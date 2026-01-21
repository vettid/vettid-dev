# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VettID is a privacy-first digital identity platform using AWS Nitro Enclaves for hardware-secured user vaults. The backend cannot access plaintext user data - all sensitive operations happen inside cryptographically attested enclaves.

## Build Commands

### CDK Infrastructure (TypeScript)
```bash
cd cdk
npm run build          # TypeScript compilation
npm run deploy         # Build and deploy all CDK stacks
npm run synth          # Synthesize CloudFormation templates
npm run destroy        # Tear down all stacks
```

### Enclave (Go)
```bash
cd enclave
make build-docker      # Build Docker image
make build-eif         # Convert to Enclave Image Format
make build-local       # Build Go binaries locally (for testing)
make run-enclave       # Start enclave on Nitro instance
make run-enclave-debug # Start with debug console access
```

## Testing

### TypeScript Tests
```bash
cd cdk
npm test                    # All tests
npm run test:unit          # Unit tests only
npm run test:integration   # Integration tests
npm run test:e2e           # End-to-end tests
npm run test:security      # Security audit tests
npm run test:coverage      # With coverage report

# Single test file
npx jest tests/unit/specific.test.ts

# Tests matching pattern
npx jest --testNamePattern="vault enrollment"
```

### Go Tests
```bash
cd enclave
make test              # Run supervisor and vault-manager tests
```

### Module Aliases
Tests use path aliases defined in `cdk/tests/jest.config.js`:
- `@/` → `lambda/`
- `@common/` → `lambda/common/`
- `@handlers/` → `lambda/handlers/`

## Architecture

### Three-Layer System

1. **API Layer** (`cdk/lambda/`) - HTTP API Gateway with Lambda handlers
   - `handlers/public/` - Unauthenticated endpoints
   - `handlers/registry/` - Member authentication required
   - `handlers/admin/` - Admin portal operations
   - `handlers/governance/` - Voting and proposals
   - `common/` - Shared utilities, DynamoDB helpers, response builders

2. **Enclave Layer** (`enclave/`) - Hardware-isolated Go services
   - `supervisor/` - Process manager inside enclave
   - `vault-manager/` - Core vault logic (credentials, connections, voting)
   - `parent/` - Orchestrates parent↔enclave communication via vsock

3. **Infrastructure** (`cdk/lib/`) - AWS CDK stacks
   - `InfrastructureStack` - DynamoDB, Cognito, API Gateway
   - `NATSStack` - Messaging cluster with JetStream
   - `NitroStack` - Enclave EC2 instances
   - `VaultStack` - Vault-specific Lambda handlers

### Communication Flow
```
Mobile App → NATS (E2E encrypted) → Parent Process → vsock → Enclave → Vault Manager
```

### Key Data Stores
- **DynamoDB**: Metadata (registrations, proposals, votes, audit logs)
- **S3**: Encrypted vault databases (per-user SQLite), handler WASM binaries, backups
- **Secrets Manager**: Sealed material, NATS account seeds

## Security Patterns

### Code Markers
Look for `// SECURITY:` comments marking critical sections that require extra care.

### Crypto Stack
- **x25519**: Key exchange for E2E encryption
- **Ed25519**: Digital signatures
- **Argon2id**: Password hashing and key derivation
- **CBOR**: Binary serialization for enclave messages
- **PCR attestation**: Hardware integrity verification

### Vault Access
Two-factor: PIN-derived DEK + password verification. Keys never leave enclave memory.

## Lambda Utilities

Use helpers from `lambda/common/util.ts`:
```typescript
import { ok, badRequest, notFound, getRegistration, getAdminEmail, putAudit } from '../../common/util';
```

Response helpers: `ok()`, `created()`, `badRequest()`, `unauthorized()`, `notFound()`, `conflict()`, `internalError()`

## Naming Conventions

- **Resource IDs**: `VET-` prefix (e.g., `VET-A1B2C3D4`)
- **OwnerSpace**: `{userGuid}` for user vaults, `{serviceGuid}` for service vaults
- **NATS Topics**: `Control.enclave.{id}.*`, `MessageSpace.{ownerSpace}.*`
- **Tables**: Lowercase with underscores (`registrations`, `vault_instances`)

## Key Documentation

- `docs/NITRO-ENCLAVE-VAULT-ARCHITECTURE.md` - Complete vault design
- `docs/PCR-HANDLING-GUIDE.md` - Attestation validation
- `docs/NATS-MESSAGING-ARCHITECTURE.md` - Messaging patterns
- `cdk/REFACTORING_GUIDE.md` - Code organization and migration
