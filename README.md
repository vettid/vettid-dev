# VettID Backend Infrastructure

VettID is a privacy-first digital identity platform that gives users complete control over their personal data through hardware-secured vaults running in AWS Nitro Enclaves.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Mobile Apps (iOS / Android)                        │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │ NATS (E2E Encrypted)
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AWS Infrastructure                                 │
│                                                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
│  │   API Gateway    │  │   NATS Cluster   │  │    Nitro Enclaves        │  │
│  │   + Lambda       │  │  ┌────────────┐  │  │  ┌────────────────────┐  │  │
│  │                  │  │  │OwnerSpace │  │  │  │    Supervisor      │  │  │
│  │  ┌────────────┐  │  │  │ (App↔Vault)│  │  │  │    ┌──────────┐   │  │  │
│  │  │  Admin     │  │  │  └────────────┘  │  │  │    │  Vault   │   │  │  │
│  │  │  Handlers  │  │  │  ┌────────────┐  │  │  │    │ Manager  │   │  │  │
│  │  └────────────┘  │  │  │MessageSpace│  │  │  │    │ (User A) │   │  │  │
│  │  ┌────────────┐  │  │  │(Vault↔Vault)│  │  │  │    └──────────┘   │  │  │
│  │  │  Member    │  │  │  └────────────┘  │  │  │    ┌──────────┐   │  │  │
│  │  │  Handlers  │  │  │                  │  │  │    │  Vault   │   │  │  │
│  │  └────────────┘  │  │                  │  │  │    │ Manager  │   │  │  │
│  └──────────────────┘  └──────────────────┘  │  │    │ (User B) │   │  │  │
│                                              │  │    └──────────┘   │  │  │
│  ┌──────────────────┐  ┌──────────────────┐  │  └────────────────────┘  │  │
│  │    DynamoDB      │  │       S3         │  │  Hardware-isolated       │  │
│  │   (Metadata)     │  │ (Encrypted Vaults)│  │  memory & attestation   │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Multi-Tenant Enclave Architecture

Each Nitro Enclave runs a supervisor process managing multiple vault-manager instances. User data is stored in per-user encrypted SQLite databases on S3, with encryption keys derived from the user's PIN and sealed material that can only be unsealed inside the enclave.

### NATS Messaging

Two logical deployments provide separation of concerns:
- **OwnerSpace** - Direct communication between a user's app and their vault
- **MessageSpace** - Cross-vault messaging for connections between users

## Key Features

### Hardware Security
- User data encrypted and processed inside AWS Nitro Enclaves
- PCR-based attestation allows mobile apps to verify enclave code integrity
- Zero-knowledge architecture: backend operators cannot access plaintext user data
- Per-user encryption keys never leave enclave memory

### Credentials & Secrets
- Store and manage identity credentials with version control
- Per-credential secret storage (passwords, API keys, sensitive data)
- Encrypted backup and multi-stage recovery workflow
- QR code-based recovery tokens

### User Connections
- Bidirectional connection requests between users
- Capability-based permissions (what data connections can access)
- End-to-end encrypted messaging with read receipts
- WebRTC calling with TURN relay support (Cloudflare)

### Service Connections (B2C)
- Connect with businesses running VettID Service Vaults
- Data contracts define what information services can access
- User-controlled: accept/reject contract updates, revoke access anytime
- Clean breaks: services lose all access immediately upon disconnection
- No caching: services access user data on-demand only

### Governance & Voting
- Proposal creation with scheduled open/close periods
- Privacy-preserving voting with Merkle proof verification
- PIN-authorized vote casting inside the vault
- Published results with aggregated counts

## Repository Structure

```
├── cdk/                    # AWS CDK Infrastructure
│   ├── lib/               # Stack definitions (9 stacks)
│   ├── lambda/            # Lambda handlers (TypeScript)
│   │   ├── handlers/      # API endpoint handlers by domain
│   │   └── common/        # Shared utilities
│   └── frontend/          # Web portals (admin, account, enrollment)
├── enclave/               # Nitro Enclave code (Go)
│   ├── vault-manager/     # Core vault logic (24 handler modules)
│   ├── parent/            # Parent process (outside enclave)
│   └── supervisor/        # Enclave process supervisor
├── docs/                  # Documentation
│   ├── specs/            # API specifications
│   └── runbooks/         # Operational procedures
└── packer/                # AMI build configuration
```

## Technology Stack

| Layer | Technologies |
|-------|-------------|
| Infrastructure | AWS CDK (TypeScript), CloudFormation |
| API | AWS Lambda, API Gateway, Cognito |
| Enclave | Go, AWS Nitro Enclaves, SQLite |
| Messaging | NATS with JetStream |
| Storage | DynamoDB (metadata), S3 (encrypted vaults) |
| Crypto | x25519, Ed25519, ChaCha20-Poly1305, Argon2id |
| Security | KMS, Secrets Manager, PCR attestation |

## Development

See [CLAUDE.md](CLAUDE.md) for build commands, testing instructions, and architecture details.

### Quick Start
```bash
cd cdk
npm install
npm run build
npm run deploy
```

### Testing
```bash
npm test              # All tests
npm run test:unit     # Unit tests
npm run test:e2e      # End-to-end tests
```

## Related Repositories

- [vettid-android](https://github.com/vettid/vettid-android) - Android app (Kotlin/Jetpack Compose)
- [vettid-ios](https://github.com/vettid/vettid-ios) - iOS app (Swift/SwiftUI)
- [vettid-test-harness](https://github.com/vettid/vettid-test-harness) - E2E test suite

## Security

VettID implements defense in depth:

- **Hardware isolation**: Nitro Enclaves provide CPU-level memory protection
- **Cryptographic attestation**: Apps verify enclave integrity before trusting it
- **Zero-knowledge**: Backend cannot decrypt user data even with full infrastructure access
- **End-to-end encryption**: All vault communication encrypted with keys only the user controls
- **Audit logging**: Comprehensive logging for security monitoring

For security issues, please email security@vettid.dev

## Documentation

- [Architecture Overview](docs/NITRO-ENCLAVE-VAULT-ARCHITECTURE.md)
- [NATS Messaging](docs/NATS-MESSAGING-ARCHITECTURE.md)
- [API Specifications](docs/specs/)
- [Operational Runbooks](docs/runbooks/)

## License

AGPL-3.0-or-later - See [LICENSE](LICENSE) for details.

## Links

- Website: [vettid.org](https://vettid.org)
- Documentation: [docs.vettid.dev](https://docs.vettid.dev)
