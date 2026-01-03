# Checkpoint: Nitro Enclave Deployed - 2026-01-03

## Current State

### What's Done

1. **Nitro Enclave Architecture Deployed**
   - Lambda handlers updated to always use enclave mode
   - `enrollStart.ts` - Always requests enclave attestation
   - `enrollFinalize.ts` - Uses `requestCredentialCreate()` for enclave-based credential creation
   - `vault-stack.ts` - Removed `USE_NITRO_ENCLAVE` feature flag
   - VettID-Vault stack deployed successfully

2. **Mobile Documentation Created**
   - `docs/NITRO-ENCLAVE-MIGRATION-FOR-MOBILE.md` pushed to both repos
   - Explains attestation verification requirements
   - Documents encryption changes (encrypt to enclave public key)
   - Migration checklist for both platforms

3. **Old Issues Closed**
   - vettid-vault-ami #4 (Connection handlers E2E decryption) - Superseded
   - vettid-vault-ami #5 (Bootstrap encryption requirement) - Superseded

### What's Pending (Mobile Devs)

1. **iOS**
   - Implement CBOR parsing for attestation documents
   - Implement Nitro certificate chain verification
   - Update password encryption to use enclave public key
   - Test full enrollment flow

2. **Android**
   - Same as iOS (issue #2 in vettid-dev tracks this)
   - CBOR parsing, cert verification, PCR comparison
   - Update encryption target

### Files Modified in This Session

**vettid-dev/cdk/lambda/handlers/vault/**
- `enrollStart.ts` - Removed USE_NITRO_ENCLAVE flag, always request attestation
- `enrollFinalize.ts` - Removed legacy credential creation, enclave-only

**vettid-dev/cdk/lib/**
- `vault-stack.ts` - Removed USE_NITRO_ENCLAVE env var

**Documentation**
- `docs/NITRO-ENCLAVE-MIGRATION-FOR-MOBILE.md` - New file

### Key Technical Details

- Enclave attestation is CBOR-encoded (RFC 8949)
- Certificate chain validates to AWS Nitro root CA
- PCR values (pcr0, pcr1, pcr2) must match expected values
- Mobile encrypts password to `enclave_attestation.enclave_public_key`
- HKDF context remains `"transaction-encryption-v1"` for compatibility
- `vault_status` is always `"ENCLAVE_READY"` (no EC2 provisioning)

### Resume Point

When mobile devs are ready to test:
1. They should `git pull` to get the migration document
2. Implement attestation verification
3. Update password encryption
4. Test with fresh invitation code
5. Report results

The backend is ready - just waiting on mobile implementation.
