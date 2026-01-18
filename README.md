# VettID Backend Infrastructure

VettID is a privacy-first digital identity platform that gives users complete control over their personal data through hardware-secured vaults running in AWS Nitro Enclaves.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Mobile Apps                               │
│                   (iOS / Android)                                │
└──────────────────────────┬──────────────────────────────────────┘
                           │ NATS (E2E Encrypted)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     AWS Infrastructure                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   API GW    │  │    NATS     │  │    Nitro Enclaves       │  │
│  │  + Lambda   │  │   Cluster   │  │  ┌─────────────────┐    │  │
│  └─────────────┘  └─────────────┘  │  │  Vault Manager  │    │  │
│                                     │  │  (User Data)    │    │  │
│  ┌─────────────┐  ┌─────────────┐  │  └─────────────────┘    │  │
│  │  DynamoDB   │  │     S3      │  │  Hardware-isolated      │  │
│  │  (Metadata) │  │  (Encrypted │  │  memory & attestation   │  │
│  └─────────────┘  │   Blobs)    │  └─────────────────────────┘  │
│                   └─────────────┘                                │
└─────────────────────────────────────────────────────────────────┘
```

## Key Features

- **Hardware Security**: User data encrypted and processed inside AWS Nitro Enclaves
- **Zero-Knowledge Architecture**: Backend cannot access user plaintext data
- **Cryptographic Attestation**: Mobile apps verify enclave integrity via PCR values
- **Real-time Communication**: NATS messaging with end-to-end encryption
- **Privacy by Design**: No tracking, no ads, no data mining

## Repository Structure

```
├── cdk/                    # AWS CDK Infrastructure
│   ├── lib/               # Stack definitions
│   ├── lambda/            # Lambda handlers (TypeScript)
│   │   ├── handlers/      # API endpoint handlers
│   │   └── common/        # Shared utilities
│   └── scripts/           # Deployment scripts
├── enclave/               # Nitro Enclave code (Go)
│   ├── vault-manager/     # Core vault logic
│   ├── parent/            # Parent process (outside enclave)
│   └── supervisor/        # Enclave supervisor
├── docs/                  # Documentation
└── packer/                # AMI build configuration
```

## Technology Stack

- **Infrastructure**: AWS CDK (TypeScript)
- **API Layer**: AWS Lambda, API Gateway
- **Enclave**: Go, AWS Nitro Enclaves
- **Messaging**: NATS with JetStream
- **Storage**: DynamoDB, S3 (encrypted)
- **Security**: KMS, Secrets Manager, PCR attestation

## Related Repositories

- [vettid-android](https://github.com/vettid/vettid-android) - Android app (Kotlin/Jetpack Compose)
- [vettid-ios](https://github.com/vettid/vettid-ios) - iOS app (Swift/SwiftUI)
- [vettid-test-harness](https://github.com/vettid/vettid-test-harness) - E2E test suite
- [vettid.org](https://github.com/vettid/vettid.org) - Marketing website

## Security

VettID takes security seriously. Key security features:

- All user data encrypted with keys held only in Nitro Enclaves
- PCR-based attestation ensures code integrity
- No plaintext user data accessible to backend operators
- Regular security audits and penetration testing

For security issues, please email security@vettid.dev

## License

AGPL-3.0-or-later - See [LICENSE](LICENSE) for details.

## Links

- Website: [vettid.org](https://vettid.org)
- Documentation: [docs.vettid.dev](https://docs.vettid.dev)
