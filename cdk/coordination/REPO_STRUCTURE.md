# VettID Repository Structure

## Overview

The VettID project is split across multiple repositories for better organization and separation of concerns.

## Repositories

| Repository | Purpose | URL |
|------------|---------|-----|
| **vettid-dev** | Backend infrastructure (CDK, Lambda, coordination) | `github.com/mesmerverse/vettid-dev` |
| **vettid-android** | Android mobile application | `github.com/mesmerverse/vettid-android` |
| **vettid-ios** | iOS mobile application | `github.com/mesmerverse/vettid-ios` |

## Repository Contents

### vettid-dev (This Repository)

```
vettid-dev/
├── cdk/
│   ├── bin/                    # CDK app entry point
│   ├── lib/                    # CDK stack definitions
│   ├── lambda/                 # Lambda handler source code
│   │   ├── common/             # Shared utilities
│   │   └── handlers/           # Lambda handlers by category
│   ├── tests/                  # Backend tests
│   ├── coordination/           # Multi-instance coordination
│   │   ├── specs/              # API specifications (shared with mobile)
│   │   ├── status/             # Instance status files
│   │   └── tasks/              # Task assignments
│   ├── docs/                   # Architecture documentation
│   └── frontend/               # Web frontend (admin, account, register)
```

### vettid-android

```
vettid-android/
├── app/
│   └── src/
│       ├── main/
│       │   ├── java/com/vettid/app/
│       │   │   ├── core/       # Crypto, storage, network
│       │   │   ├── features/   # Feature modules
│       │   │   └── ui/         # UI components
│       │   └── res/            # Resources
│       └── test/               # Unit tests
└── gradle/                     # Gradle configuration
```

### vettid-ios

```
vettid-ios/
├── VettID/
│   └── Sources/
│       ├── Auth/               # Credential management
│       ├── API/                # Network client
│       ├── Enrollment/         # Enrollment flows
│       ├── NATS/               # NATS client
│       └── UI/                 # SwiftUI views
└── VettIDTests/                # Unit tests
```

## Coordination Protocol

### Shared Specifications

API specifications live in `vettid-dev/docs/specs/`:
- `vault-services-api.yaml` - OpenAPI 3.0 specification
- `credential-format.md` - Credential blob format
- `nats-topics.md` - NATS topic structure

Mobile instances should:
1. Clone `vettid-dev` to access specifications
2. Reference specs when implementing API clients

### Status Updates

Each instance updates their status in `vettid-dev`:
- Android: `cdk/coordination/status/android.json`
- iOS: `cdk/coordination/status/ios.json`
- Testing: `cdk/coordination/status/testing.json`

### Cross-Repository References

Mobile apps reference the backend API:
- Development: `https://api-dev.vettid.dev`
- Production: `https://api.vettid.dev`

## Migration Note

**IMPORTANT**: As of Phase 0 completion, mobile code is being migrated to separate repositories:
- Android code in `vettid-dev/android/` should be moved to `vettid-android`
- iOS code should be created directly in `vettid-ios`

The `android/` directory in this repo will be removed after migration.
