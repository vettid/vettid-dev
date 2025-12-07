# VettID Vault Services - Phased Development Plan

**Version:** 1.0
**Created:** December 6, 2025
**Status:** DRAFT - Awaiting Approval

---

## Executive Summary

This document outlines a phased development plan for implementing the VettID Vault Services system as described in the architecture documentation. The plan is designed for coordination across four Claude Code instances:

| Instance | Role | Primary Focus |
|----------|------|---------------|
| **Orchestrator** | Main coordinator | CDK infrastructure, Lambda handlers, coordination |
| **Testing** | General testing | API tests, integration tests, security validation |
| **Android** | Mobile (Android) | Android app development and testing |
| **iOS** | Mobile (iOS) | iOS app development and testing |

---

## Current State Analysis

### What Exists (93 Lambda Handlers)

The VettID scaffold already implements:

1. **Core Infrastructure** (Deployed)
   - 19 DynamoDB tables with GSIs
   - 2 Cognito User Pools (admin/member) with passwordless auth
   - HTTP API Gateway with JWT authorizers
   - 5 CloudFront distributions
   - S3 buckets for frontend and membership terms

2. **Member Handlers** (25 handlers)
   - PIN management, email preferences
   - Membership and subscription management
   - Voting and proposals

3. **Admin Handlers** (54 handlers)
   - Full registration/invite/user management
   - Membership terms and subscription management
   - Waitlist and proposal management

4. **Vault Handlers** (5 handlers - Basic)
   - `enrollStart`, `enrollSetPassword`, `enrollFinalize`
   - `actionRequest`, `authExecute`
   - X25519 transaction keys generation

### What Needs to Be Built

Based on the architecture documents, the following major systems need implementation:

1. **Protean Credential System** (Ledger)
   - Credential blob encryption/decryption (X25519 + XChaCha20-Poly1305)
   - CEK, TK, LAT key management
   - Argon2id password verification
   - Device attestation verification (Android/iOS)
   - Atomic session management

2. **Vault Services API**
   - Request routing and endpoint assignment
   - Token generation for namespace access
   - Vault provisioning coordination (EC2)
   - Backup storage management (S3)
   - System commands via control topic

3. **NATS Infrastructure**
   - Central NATS deployment (OwnerSpace/MessageSpace)
   - JWT-based access control
   - Namespace isolation per member

4. **Vault Instance (EC2/Appliance)**
   - Vault Manager service
   - Local NATS server
   - WASM runtime (Wasmtime/WasmEdge)
   - Handler execution environment

5. **Service Registry**
   - Handler catalog management
   - Signed WASM package distribution
   - Version management and updates

6. **Mobile Apps** (Android/iOS)
   - Credential storage and management
   - Vault enrollment flows
   - NATS communication
   - Device attestation

---

## Phased Development Plan

### Phase 0: Foundation & Coordination Setup
**Duration:** 1 sprint
**Dependencies:** None

#### Objectives
- Establish coordination infrastructure between Claude Code instances
- Set up testing framework
- Create mobile app project scaffolds

#### Tasks

**Orchestrator:**
1. Create coordination directory structure:
   ```
   cdk/coordination/
   ├── status/           # Instance status updates
   ├── tasks/            # Assigned tasks per instance
   ├── specs/            # API specifications for mobile apps
   └── results/          # Test results and feedback
   ```

2. Create initial API specification documents:
   - `specs/vault-services-api.yaml` (OpenAPI 3.0)
   - `specs/nats-topics.md` (Topic structure)
   - `specs/credential-format.md` (Blob structure)

3. Set up Jest test infrastructure for Lambda handlers

**Testing Instance:**
1. Read coordination specs from `cdk/coordination/`
2. Create test scaffolding:
   ```
   cdk/tests/
   ├── unit/           # Unit tests for handlers
   ├── integration/    # API integration tests
   ├── e2e/            # End-to-end tests
   └── security/       # Security validation tests
   ```

3. Create base test utilities:
   - DynamoDB local setup
   - Mock Cognito tokens
   - API test client

**Android Instance:**
1. Read API specs from `cdk/coordination/specs/`
2. Create Android project scaffold:
   ```
   android/
   ├── app/src/main/kotlin/dev/vettid/
   │   ├── auth/       # Credential management
   │   ├── vault/      # Vault communication
   │   ├── nats/       # NATS client
   │   └── ui/         # UI components
   ├── app/src/test/   # Unit tests
   └── app/src/androidTest/  # Instrumentation tests
   ```

3. Add dependencies:
   - TweetNaCl for X25519/Ed25519
   - NATS client library
   - Secure storage (EncryptedSharedPreferences)
   - Device attestation APIs

**iOS Instance:**
1. Read API specs from `cdk/coordination/specs/`
2. Create iOS project scaffold:
   ```
   ios/VettID/
   ├── Sources/
   │   ├── Auth/       # Credential management
   │   ├── Vault/      # Vault communication
   │   ├── NATS/       # NATS client
   │   └── UI/         # SwiftUI views
   ├── Tests/          # Unit tests
   └── UITests/        # UI tests
   ```

3. Add dependencies:
   - CryptoKit for X25519
   - Swift-NATS client
   - Keychain for secure storage
   - App Attest framework

#### Validation
- [ ] All instances can read/write to coordination directory
- [ ] Test framework runs successfully with sample test
- [ ] Mobile app projects build successfully
- [ ] Initial API specs are complete and documented

---

### Phase 1: Protean Credential System - Core
**Duration:** 2 sprints
**Dependencies:** Phase 0

#### Objectives
- Implement credential encryption/decryption
- Implement Argon2id password hashing
- Set up Ledger (RDS) infrastructure
- Implement LAT mutual authentication

#### Tasks

**Orchestrator:**

1. **RDS Infrastructure** (`cdk/lib/ledger-stack.ts`):
   ```typescript
   // New stack for Ledger database
   - Aurora PostgreSQL Serverless v2
   - VPC with private subnets
   - Security group (Lambda access only)
   - Secrets Manager for credentials
   ```

2. **Ledger Lambda Handlers** (`cdk/lambda/handlers/ledger/`):
   ```
   createCredential.ts     # Generate CEK, store in RDS
   rotateKeys.ts           # Rotate CEK/TK after auth
   validateLAT.ts          # LAT verification
   generateTransactionKeys.ts  # TK pool management
   verifyPassword.ts       # Argon2id verification
   ```

3. **Credential Utilities** (`cdk/lambda/common/crypto.ts`):
   ```typescript
   // Implement using tweetnacl-js
   - encryptCredentialBlob(plaintext, publicKey)
   - decryptCredentialBlob(ciphertext, privateKey)
   - generateX25519KeyPair()
   - deriveSymmetricKey(sharedSecret)
   - hashPassword(password) // Argon2id
   - verifyPassword(hash, password)
   ```

4. **Database Migrations** (`cdk/migrations/`):
   ```sql
   -- Users table
   CREATE TABLE users (
     user_guid UUID PRIMARY KEY,
     current_session_id UUID,
     session_started_at TIMESTAMP,
     last_activity_at TIMESTAMP
   );

   -- Credential keys table
   CREATE TABLE credential_keys (
     key_id UUID PRIMARY KEY,
     user_guid UUID REFERENCES users,
     public_key BYTEA,
     encrypted_private_key BYTEA,
     version INTEGER,
     created_at TIMESTAMP
   );

   -- Transaction keys table
   CREATE TABLE transaction_keys (
     key_id UUID PRIMARY KEY,
     user_guid UUID REFERENCES users,
     public_key BYTEA,
     encrypted_private_key BYTEA,
     status VARCHAR(20), -- 'unused', 'used'
     created_at TIMESTAMP
   );

   -- LAT table
   CREATE TABLE ledger_auth_tokens (
     token_id UUID PRIMARY KEY,
     user_guid UUID REFERENCES users,
     token_hash BYTEA,
     version INTEGER,
     status VARCHAR(20), -- 'active', 'used'
     created_at TIMESTAMP
   );
   ```

5. **API Endpoints**:
   ```
   POST /vault/credentials/create
   POST /vault/credentials/rotate
   POST /vault/auth/validate-lat
   POST /vault/auth/verify-password
   GET  /vault/transaction-keys
   POST /vault/transaction-keys/replenish
   ```

**Testing Instance:**

1. **Unit Tests** (`cdk/tests/unit/crypto/`):
   ```
   encryptDecrypt.test.ts   # Credential blob encryption
   argon2.test.ts           # Password hashing
   keyGeneration.test.ts    # X25519 key generation
   latValidation.test.ts    # LAT verification
   ```

2. **Integration Tests** (`cdk/tests/integration/ledger/`):
   ```
   credentialLifecycle.test.ts  # Full credential flow
   keyRotation.test.ts          # CEK/TK rotation
   concurrentSession.test.ts    # Atomic session tests
   ```

3. **Security Tests** (`cdk/tests/security/`):
   ```
   bruteForce.test.ts      # Rate limiting validation
   timingAttack.test.ts    # Constant-time operations
   replayAttack.test.ts    # LAT replay prevention
   ```

**Android Instance:**

1. **Credential Storage** (`android/app/src/main/kotlin/dev/vettid/auth/`):
   ```kotlin
   CredentialStore.kt      # Encrypted storage
   CredentialBlob.kt       # Blob structure
   CryptoUtils.kt          # X25519 operations
   ```

2. **Unit Tests**:
   ```kotlin
   CredentialStoreTest.kt
   CryptoUtilsTest.kt
   ```

**iOS Instance:**

1. **Credential Storage** (`ios/VettID/Sources/Auth/`):
   ```swift
   CredentialStore.swift   # Keychain storage
   CredentialBlob.swift    # Blob structure
   CryptoUtils.swift       # CryptoKit operations
   ```

2. **Unit Tests**:
   ```swift
   CredentialStoreTests.swift
   CryptoUtilsTests.swift
   ```

#### Validation
- [ ] Credential blob encrypts/decrypts correctly (all instances)
- [ ] Argon2id hashing meets timing requirements (>100ms)
- [ ] LAT rotation works correctly
- [ ] Transaction key pool replenishes properly
- [ ] Atomic session management prevents race conditions
- [ ] All unit tests pass
- [ ] Integration tests pass
- [ ] Security tests pass

#### Deployment
```bash
# Deploy Ledger stack
npm run deploy -- VettID-Ledger

# Run integration tests
npm run test:integration:ledger
```

---

### Phase 2: Device Attestation
**Duration:** 1 sprint
**Dependencies:** Phase 1

#### Objectives
- Implement Android Hardware Key Attestation
- Implement iOS App Attest
- Integrate attestation into authentication flow

#### Tasks

**Orchestrator:**

1. **Attestation Handlers** (`cdk/lambda/handlers/attestation/`):
   ```
   verifyAndroidAttestation.ts  # Hardware Key Attestation
   verifyIosAttestation.ts      # App Attest
   ```

2. **Attestation Utilities** (`cdk/lambda/common/attestation.ts`):
   ```typescript
   // Android attestation
   - parseAttestationCertChain(certs)
   - verifyKeyAttestationExtension(cert, challenge)
   - checkVerifiedBootState(attestation)

   // iOS attestation
   - verifyAppAttestAttestation(data, challenge, keyId)
   - verifyAppleCertChain(certChain)
   ```

3. **Update Auth Flow**:
   - Modify `enrollStart` to require attestation
   - Add attestation challenge generation
   - Store device attestation status

**Testing Instance:**

1. **Attestation Tests** (`cdk/tests/unit/attestation/`):
   ```
   androidAttestation.test.ts
   iosAttestation.test.ts
   attestationIntegration.test.ts
   ```

2. **Mock Attestation Data**:
   - Generate test attestation certificates
   - Create test App Attest assertions

**Android Instance:**

1. **Hardware Attestation** (`android/app/src/main/kotlin/dev/vettid/auth/`):
   ```kotlin
   DeviceAttestation.kt    # Generate attestation
   KeyAttestationHelper.kt # Parse extension
   ```

2. **Instrumentation Tests**:
   ```kotlin
   DeviceAttestationTest.kt  # Real device test
   ```

**iOS Instance:**

1. **App Attest** (`ios/VettID/Sources/Auth/`):
   ```swift
   DeviceAttestation.swift   # App Attest integration
   AttestationKey.swift      # Key management
   ```

2. **Device Tests**:
   ```swift
   DeviceAttestationTests.swift
   ```

#### Validation
- [ ] Android attestation works on real device
- [ ] iOS attestation works on real device
- [ ] Attestation integrated into enrollment flow
- [ ] Invalid attestations are rejected
- [ ] GrapheneOS attestation works (Android)
- [ ] Tests pass with mock attestation data

#### Manual Testing
1. **Android**: Install app on physical device, complete enrollment
2. **iOS**: Install app on physical device, complete enrollment
3. **Reject rooted/jailbroken devices**: Verify attestation fails

---

### Phase 3: Vault Services Enrollment
**Duration:** 2 sprints
**Dependencies:** Phase 2

#### Objectives
- Complete Vault Services enrollment flow
- Implement invite endpoint for web portal
- Implement QR code generation
- Integrate with existing Cognito users

#### Tasks

**Orchestrator:**

1. **Enrollment Handlers** (`cdk/lambda/handlers/vault/`):
   ```
   createInvite.ts         # Generate enrollment invite
   validateInvite.ts       # Validate invite code
   completeEnrollment.ts   # Finalize enrollment
   getEnrollmentStatus.ts  # Check enrollment state
   ```

2. **QR Code Generation**:
   ```typescript
   // Invite structure
   {
     type: 'vettid_vault_enrollment',
     code: 'invite_code',
     endpoint: 'vault.vettid.dev',
     expires_at: 'ISO timestamp'
   }
   ```

3. **Member Portal Updates**:
   - Add "Deploy Vault" tile to account page
   - Display QR code after initiation
   - Show vault status after enrollment

4. **API Endpoints**:
   ```
   POST /member/vault/deploy        # Initiate deployment
   GET  /member/vault/status        # Get vault status
   POST /vault/enroll/start         # Mobile: Start enrollment
   POST /vault/enroll/password      # Mobile: Set password
   POST /vault/enroll/finalize      # Mobile: Complete enrollment
   POST /vault/enroll/attestation   # Mobile: Submit attestation
   ```

**Testing Instance:**

1. **Enrollment Tests** (`cdk/tests/integration/enrollment/`):
   ```
   inviteGeneration.test.ts
   enrollmentFlow.test.ts
   qrCodeValidation.test.ts
   ```

2. **E2E Tests** (`cdk/tests/e2e/`):
   ```
   memberDeployVault.test.ts  # Full deploy → enroll flow
   ```

**Android Instance:**

1. **Enrollment UI** (`android/app/src/main/kotlin/dev/vettid/enrollment/`):
   ```kotlin
   EnrollmentActivity.kt
   QrScannerFragment.kt
   PasswordSetupFragment.kt
   EnrollmentViewModel.kt
   ```

2. **Enrollment Logic**:
   ```kotlin
   EnrollmentManager.kt     # Coordinate enrollment
   VaultServiceClient.kt    # API communication
   ```

3. **UI Tests**:
   ```kotlin
   EnrollmentFlowTest.kt
   ```

**iOS Instance:**

1. **Enrollment UI** (`ios/VettID/Sources/Enrollment/`):
   ```swift
   EnrollmentView.swift
   QRScannerView.swift
   PasswordSetupView.swift
   EnrollmentViewModel.swift
   ```

2. **Enrollment Logic**:
   ```swift
   EnrollmentManager.swift
   VaultServiceClient.swift
   ```

3. **UI Tests**:
   ```swift
   EnrollmentFlowTests.swift
   ```

#### Validation
- [ ] QR code generation works
- [ ] Mobile apps can scan QR code
- [ ] Enrollment flow completes successfully
- [ ] Credential stored securely on device
- [ ] Enrollment status visible in web portal
- [ ] Duplicate enrollment rejected
- [ ] Expired invites rejected

#### Manual Testing Checklist
1. [ ] Web: Click "Deploy Vault", see QR code
2. [ ] Android: Scan QR, complete enrollment
3. [ ] iOS: Scan QR, complete enrollment
4. [ ] Web: Verify "Vault Status: Enrolled"
5. [ ] Try enrolling again (should fail)

---

### Phase 4: NATS Infrastructure
**Duration:** 2 sprints
**Dependencies:** Phase 3

#### Objectives
- Deploy central NATS cluster
- Implement namespace isolation
- Create JWT-based access control
- Establish OwnerSpace/MessageSpace architecture

#### Tasks

**Orchestrator:**

1. **NATS Infrastructure** (`cdk/lib/nats-stack.ts`):
   ```typescript
   // ECS Fargate or EC2 cluster
   - NATS cluster (3 nodes minimum)
   - JetStream enabled
   - TLS termination
   - NLB for ingress
   - Operator key management
   ```

2. **NATS Account Management** (`cdk/lambda/handlers/nats/`):
   ```
   createMemberAccount.ts   # Create namespace
   generateMemberJwt.ts     # Issue scoped JWT
   generateAppToken.ts      # Token for mobile app
   generateControlToken.ts  # Token for Vault Services
   revokeToken.ts           # Revoke access
   ```

3. **Namespace Structure**:
   ```
   operator.vettid.dev (Operator level)
   └── OwnerSpace.{member_guid} (Account level)
       ├── forVault   (App → Vault)
       ├── forApp     (Vault → App)
       ├── eventTypes (Handler definitions)
       └── control    (System commands)

   └── MessageSpace.{member_guid} (Account level)
       ├── forOwner      (Connections → Vault)
       └── ownerProfile  (Public profile)
   ```

4. **API Endpoints**:
   ```
   POST /vault/nats/account      # Create member namespace
   POST /vault/nats/token        # Generate access token
   POST /vault/nats/token/revoke # Revoke token
   GET  /vault/nats/status       # Namespace status
   ```

**Testing Instance:**

1. **NATS Tests** (`cdk/tests/integration/nats/`):
   ```
   namespaceIsolation.test.ts
   jwtValidation.test.ts
   publishSubscribe.test.ts
   tokenRevocation.test.ts
   ```

2. **Security Tests**:
   ```
   crossNamespaceAccess.test.ts  # Verify isolation
   tokenScopeValidation.test.ts  # Verify permissions
   ```

**Android Instance:**

1. **NATS Client** (`android/app/src/main/kotlin/dev/vettid/nats/`):
   ```kotlin
   NatsClient.kt           # Connection management
   NatsCredentials.kt      # JWT storage
   OwnerSpaceClient.kt     # OwnerSpace operations
   MessageSpaceClient.kt   # MessageSpace operations
   ```

2. **Tests**:
   ```kotlin
   NatsClientTest.kt
   NatsIntegrationTest.kt
   ```

**iOS Instance:**

1. **NATS Client** (`ios/VettID/Sources/NATS/`):
   ```swift
   NatsClient.swift
   NatsCredentials.swift
   OwnerSpaceClient.swift
   MessageSpaceClient.swift
   ```

2. **Tests**:
   ```swift
   NatsClientTests.swift
   NatsIntegrationTests.swift
   ```

#### Validation
- [ ] NATS cluster deployed and healthy
- [ ] Namespace isolation verified
- [ ] JWT tokens grant correct permissions
- [ ] Mobile apps can connect to NATS
- [ ] Token revocation works
- [ ] Control topic only writable by Vault Services

#### Manual Testing
1. [ ] Connect mobile app to NATS
2. [ ] Publish message to forVault
3. [ ] Receive message on forApp
4. [ ] Verify cannot access other member's namespace

---

### Phase 5: Vault Instance (EC2)
**Duration:** 3 sprints
**Dependencies:** Phase 4

#### Objectives
- Create hardened AMI for vault instances
- Implement Vault Manager service
- Deploy local NATS on vault
- Implement basic health monitoring

#### Tasks

**Orchestrator:**

1. **AMI Creation** (`cdk/packer/vault-ami.pkr.hcl`):
   ```hcl
   source "amazon-ebs" "vault" {
     instance_type = "t4g.nano"
     ami_name      = "vettid-vault-{{timestamp}}"
     // ARM64, hardened Linux
   }

   provisioner "shell" {
     scripts = [
       "scripts/install-nats.sh",
       "scripts/install-wasmtime.sh",
       "scripts/install-vault-manager.sh",
       "scripts/harden-os.sh"
     ]
   }
   ```

2. **Vault Provisioning** (`cdk/lambda/handlers/vault/`):
   ```
   provisionVault.ts       # Spin up EC2 instance
   assignNamespaces.ts     # Assign OwnerSpace/MessageSpace
   initializeVault.ts      # Configure vault
   terminateVault.ts       # Graceful shutdown
   ```

3. **Vault Manager Service** (`vault-manager/`):
   ```
   vault-manager/
   ├── cmd/main.go                # Entry point
   ├── internal/
   │   ├── nats/                  # NATS client
   │   │   ├── local.go           # Local NATS
   │   │   └── central.go         # Central NATS
   │   ├── events/                # Event handling
   │   │   ├── processor.go       # Event processor
   │   │   └── control.go         # Control topic handler
   │   ├── handlers/              # Handler execution
   │   │   ├── wasm.go            # WASM runtime
   │   │   └── registry.go        # Handler registry
   │   └── health/                # Health monitoring
   │       └── monitor.go
   └── configs/
       └── config.yaml
   ```

4. **API Endpoints**:
   ```
   POST /vault/provision          # Provision vault
   POST /vault/initialize         # Initialize after provision
   POST /vault/stop               # Stop vault
   POST /vault/terminate          # Terminate vault
   GET  /vault/health             # Health check
   ```

**Testing Instance:**

1. **Vault Tests** (`cdk/tests/integration/vault/`):
   ```
   provisioning.test.ts
   initialization.test.ts
   healthCheck.test.ts
   gracefulShutdown.test.ts
   ```

2. **Vault Manager Tests** (`vault-manager/tests/`):
   ```
   event_processing_test.go
   control_topic_test.go
   health_monitoring_test.go
   ```

**Android/iOS Instances:**

1. **Vault Communication** (`{platform}/vault/`):
   - Implement event submission to vault
   - Implement response handling
   - Implement health status display

#### Validation
- [ ] AMI builds successfully
- [ ] Vault provisions in <2 minutes
- [ ] Local NATS starts correctly
- [ ] Vault connects to central NATS
- [ ] Health checks report correctly
- [ ] Graceful shutdown works
- [ ] Mobile apps can communicate with vault

---

### Phase 6: Handler System (WASM)
**Duration:** 2 sprints
**Dependencies:** Phase 5

#### Objectives
- Implement WASM runtime in Vault Manager
- Create handler package verification
- Implement first-party handlers
- Set up Service Registry

#### Tasks

**Orchestrator:**

1. **Service Registry** (`cdk/lib/registry-stack.ts`):
   ```typescript
   // S3 bucket for handler packages
   // DynamoDB for handler catalog
   // CloudFront for distribution
   ```

2. **Registry Handlers** (`cdk/lambda/handlers/registry/`):
   ```
   listHandlers.ts         # List available handlers
   getHandler.ts           # Get handler package URL
   uploadHandler.ts        # Upload new handler (admin)
   signHandler.ts          # Sign handler package
   revokeHandler.ts        # Revoke handler version
   ```

3. **First-Party Handlers** (`handlers/`):
   ```
   handlers/
   ├── messaging-send-text/
   │   ├── src/main.rs
   │   ├── Cargo.toml
   │   └── manifest.json
   ├── profile-update/
   │   └── ...
   └── connection-invite/
       └── ...
   ```

4. **Vault Manager WASM Integration**:
   ```go
   // internal/handlers/wasm.go
   - LoadHandler(wasmBytes)
   - ExecuteHandler(input) (output, error)
   - SetResourceLimits(memory, time)
   - ConfigureEgress(allowedHosts)
   ```

**Testing Instance:**

1. **Handler Tests**:
   ```
   handlerVerification.test.ts   # Signature verification
   handlerExecution.test.ts      # WASM execution
   handlerSandbox.test.ts        # Sandbox isolation
   egressControl.test.ts         # Network restrictions
   ```

2. **First-Party Handler Tests**:
   ```
   messagingSendText.test.ts
   profileUpdate.test.ts
   connectionInvite.test.ts
   ```

**Android/iOS Instances:**

1. **Handler Discovery UI**:
   - List available handlers
   - Install handler
   - Handler settings

2. **Handler Execution**:
   - Format events per handler schema
   - Display handler responses

#### Validation
- [ ] WASM runtime executes handlers correctly
- [ ] Handler signatures verified
- [ ] Sandbox prevents unauthorized access
- [ ] Egress restrictions enforced
- [ ] First-party handlers work correctly
- [ ] Mobile apps can trigger handlers

---

### Phase 7: Connections & Messaging
**Duration:** 2 sprints
**Dependencies:** Phase 6

#### Objectives
- Implement connection invitation flow
- Implement connection establishment
- Implement profile sharing
- Implement secure messaging

#### Tasks

**Orchestrator:**

1. **Connection Handlers** (`cdk/lambda/handlers/connections/`):
   ```
   createInvitation.ts     # Generate connection invite
   acceptInvitation.ts     # Accept connection
   revokeConnection.ts     # Revoke connection
   listConnections.ts      # List connections
   ```

2. **Connection Key Management**:
   - Per-connection key exchange
   - Key rotation
   - Key storage in local NATS

3. **Profile Management**:
   - Profile schema
   - Profile publishing
   - Profile retrieval

**Testing Instance:**

1. **Connection Tests**:
   ```
   connectionInvite.test.ts
   connectionEstablishment.test.ts
   connectionRevocation.test.ts
   profileSync.test.ts
   ```

**Android/iOS Instances:**

1. **Connections UI**:
   - Invite new connection
   - Accept connection
   - Connection list
   - Profile display

2. **Messaging UI**:
   - Send message
   - Receive message
   - Message history

#### Validation
- [ ] Connection invitation works
- [ ] Key exchange successful
- [ ] Profile sharing works
- [ ] Messaging works end-to-end
- [ ] Connection revocation works

---

### Phase 8: Backup System
**Duration:** 1 sprint
**Dependencies:** Phase 5

#### Objectives
- Implement automated backups
- Implement backup encryption
- Implement backup restoration
- Implement Credential Backup Service

#### Tasks

**Orchestrator:**

1. **Backup Handlers** (`cdk/lambda/handlers/backup/`):
   ```
   triggerBackup.ts        # Trigger manual backup
   listBackups.ts          # List available backups
   restoreBackup.ts        # Initiate restore
   uploadCredentialBackup.ts   # Credential backup
   downloadCredentialBackup.ts # Credential recovery
   ```

2. **S3 Backup Structure**:
   ```
   s3://vettid-vault-backups/
   └── {member_guid}/
       ├── vault/
       │   ├── 2025-01-01-backup.enc
       │   ├── 2025-01-02-backup.enc
       │   └── 2025-01-03-backup.enc
       └── credentials/
           └── credential-backup.enc
   ```

**Testing Instance:**

1. **Backup Tests**:
   ```
   backupCreation.test.ts
   backupEncryption.test.ts
   backupRestoration.test.ts
   credentialBackup.test.ts
   ```

**Android/iOS Instances:**

1. **Backup UI**:
   - Trigger backup
   - View backup history
   - Restore from backup

2. **Credential Backup**:
   - Enable credential backup
   - Recovery phrase generation
   - Credential recovery

#### Validation
- [ ] Automatic daily backups work
- [ ] Manual backup triggers work
- [ ] Backup encryption uses member's key
- [ ] Restore works correctly
- [ ] Credential backup/recovery works
- [ ] Old backups cleaned up (keep last 3)

---

### Phase 9: Security Hardening & Audit
**Duration:** 2 sprints
**Dependencies:** All previous phases

#### Objectives
- Security audit of all components
- Penetration testing
- Performance optimization
- Documentation completion

#### Tasks

**Orchestrator:**

1. **Security Audit**:
   - Review all Lambda handlers
   - Review cryptographic implementations
   - Review access control
   - Verify audit logging

2. **Performance Optimization**:
   - Lambda cold start optimization
   - NATS connection pooling
   - DynamoDB query optimization

3. **Documentation**:
   - API documentation
   - Deployment runbook
   - Incident response procedures

**Testing Instance:**

1. **Security Tests**:
   ```
   rateLimiting.test.ts
   inputValidation.test.ts
   authBypass.test.ts
   injectionAttacks.test.ts
   ```

2. **Penetration Testing**:
   - API endpoint testing
   - Authentication bypass attempts
   - Privilege escalation attempts

**Android/iOS Instances:**

1. **Security Review**:
   - Secure storage verification
   - Certificate pinning
   - Obfuscation

2. **App Store Preparation**:
   - Privacy policy
   - App descriptions
   - Screenshots

#### Validation
- [ ] All security tests pass
- [ ] No critical vulnerabilities found
- [ ] Performance meets requirements
- [ ] Documentation complete
- [ ] Apps ready for store submission

---

## Coordination Protocol

### Directory Structure

```
cdk/coordination/
├── README.md                    # Coordination instructions
├── status/
│   ├── orchestrator.json       # Orchestrator status
│   ├── testing.json            # Testing instance status
│   ├── android.json            # Android instance status
│   └── ios.json                # iOS instance status
├── tasks/
│   ├── testing/
│   │   └── current-task.md     # Current testing task
│   ├── android/
│   │   └── current-task.md     # Current Android task
│   └── ios/
│       └── current-task.md     # Current iOS task
├── specs/
│   ├── vault-services-api.yaml # OpenAPI spec
│   ├── nats-topics.md          # NATS topic structure
│   └── credential-format.md    # Credential blob format
├── results/
│   ├── test-results/           # Test output files
│   └── issues/                 # Discovered issues
└── handoffs/
    └── {date}-{phase}-handoff.md  # Phase completion handoffs
```

### Status File Format

```json
{
  "instance": "orchestrator|testing|android|ios",
  "phase": "current phase number",
  "task": "current task description",
  "status": "in_progress|blocked|completed",
  "blockers": ["list of blockers if any"],
  "lastUpdated": "ISO timestamp",
  "notes": "additional context"
}
```

### Task Assignment Format

```markdown
# Task: [Task Name]

## Phase
Phase X: [Phase Name]

## Assigned To
[Instance Name]

## Prerequisites
- [ ] Prerequisite 1
- [ ] Prerequisite 2

## Specifications
Link to relevant specs in `cdk/coordination/specs/`

## Deliverables
- [ ] Deliverable 1
- [ ] Deliverable 2

## Acceptance Criteria
- [ ] Criterion 1
- [ ] Criterion 2

## Notes
Additional context or instructions
```

### Handoff Protocol

When completing a phase:

1. **Orchestrator** updates `handoffs/{date}-{phase}-handoff.md`:
   ```markdown
   # Phase X Handoff

   ## Completed
   - List of completed items

   ## API Changes
   - New endpoints
   - Modified endpoints

   ## Testing Required
   - Test scenarios

   ## Known Issues
   - Issues to be aware of

   ## Next Phase Dependencies
   - What other instances need
   ```

2. **Other Instances** acknowledge by:
   - Reading handoff document
   - Updating their status file
   - Beginning assigned tasks

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| NATS complexity | Start with simple pub/sub, add JetStream later |
| WASM runtime issues | Use established Wasmtime, extensive testing |
| Device attestation failures | Fallback mode with additional verification |
| Performance issues | Early load testing, optimization sprints |
| Mobile platform differences | Parallel development with shared specs |

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Vault enrollment time | < 30 seconds |
| Message latency (app → vault) | < 100ms |
| Handler execution time | < 5 seconds (typical) |
| Backup completion | < 60 seconds |
| System uptime | 99.9% |
| Security audit | No critical vulnerabilities |

---

## Appendix: Technology Stack

### Backend
- **Runtime**: Node.js 22 (Lambda)
- **Infrastructure**: AWS CDK (TypeScript)
- **Database**: DynamoDB + Aurora PostgreSQL (Ledger)
- **Messaging**: NATS with JetStream
- **WASM Runtime**: Wasmtime

### Mobile
- **Android**: Kotlin, Jetpack Compose
- **iOS**: Swift, SwiftUI
- **Crypto**: X25519 (TweetNaCl/CryptoKit)
- **Storage**: EncryptedSharedPreferences/Keychain

### Vault Instance
- **OS**: Amazon Linux 2023 (ARM64)
- **Service**: Go (Vault Manager)
- **Local DB**: NATS with JetStream

---

*This plan is subject to revision based on discoveries during implementation.*
