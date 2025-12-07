# Task: Migrate to Separate Repository

## Phase
Phase 0.5: Repository Migration

## Assigned To
Android Instance

## IMPORTANT: Repository Change

**The Android app code must now live in a separate repository.**

| Item | Value |
|------|-------|
| **New Repository** | `github.com/mesmerverse/vettid-android` |
| **Old Location** | `vettid-dev/android/` (to be removed) |
| **Coordination Repo** | `github.com/mesmerverse/vettid-dev` |

## Migration Steps

### 1. Clone the New Repository

```bash
# Clone the dedicated Android repo
git clone https://github.com/mesmerverse/vettid-android.git
cd vettid-android
```

### 2. Move Code from vettid-dev

The Phase 0 Android code was committed to `vettid-dev/android/`. You need to:
1. Copy the contents from `vettid-dev/android/` to `vettid-android/`
2. Ensure all files are properly transferred
3. Commit to `vettid-android`

```bash
# From vettid-android directory
cp -r /path/to/vettid-dev/android/* .
git add .
git commit -m "Initial Android app scaffold from Phase 0

Migrated from vettid-dev repository.

Features:
- Kotlin + Jetpack Compose + Hilt DI
- X25519, ChaCha20-Poly1305, Argon2id crypto
- EncryptedSharedPreferences credential storage
- Hardware Key Attestation (StrongBox/TEE)
- Unit tests for CryptoManager and CredentialStore

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
git push
```

### 3. Reference Specifications

API specifications remain in `vettid-dev`. Clone it for reference:

```bash
git clone https://github.com/mesmerverse/vettid-dev.git
```

Key specs to reference:
- `vettid-dev/cdk/coordination/specs/vault-services-api.yaml`
- `vettid-dev/cdk/coordination/specs/credential-format.md`
- `vettid-dev/cdk/coordination/specs/nats-topics.md`

### 4. Update Status

After migration, update your status in `vettid-dev`:

```bash
cd /path/to/vettid-dev
# Edit cdk/coordination/status/android.json
git add cdk/coordination/status/android.json
git commit -m "Update Android status: migrated to vettid-android repo"
git push
```

## Future Workflow

For all future phases:
1. Work in `vettid-android` repository
2. Reference specs from `vettid-dev/cdk/coordination/specs/`
3. Update status in `vettid-dev/cdk/coordination/status/android.json`
4. Report issues to `vettid-dev/cdk/coordination/results/issues/`

## Phase 1 Preview

After migration, Phase 1 will focus on:
- Completing enrollment flow UI
- Implementing full Protean credential authentication
- QR code scanning for vault enrollment
- Integration testing with backend APIs

## Acceptance Criteria

- [ ] Code successfully migrated to `vettid-android`
- [ ] Project builds successfully in new location
- [ ] Unit tests pass
- [ ] Status updated in `vettid-dev`
