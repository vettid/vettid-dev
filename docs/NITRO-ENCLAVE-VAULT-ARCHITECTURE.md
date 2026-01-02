# VettID Nitro Enclave Vault Architecture

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 Draft |
| Date | 2026-01-02 |
| Status | Proposal - Pending Review |
| Author | Architecture Team |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Architecture](#2-current-architecture)
3. [Proposed Architecture](#3-proposed-architecture)
4. [Security Model](#4-security-model)
5. [Component Design](#5-component-design)
6. [Data Storage & Encryption](#6-data-storage--encryption)
7. [Process Lifecycle Management](#7-process-lifecycle-management)
8. [Scaling & High Availability](#8-scaling--high-availability)
9. [Migration Strategy](#9-migration-strategy)
10. [Enclave Update & Key Migration](#10-enclave-update--key-migration)
11. [Cost Analysis](#11-cost-analysis)
12. [BYO Vault Considerations](#12-byo-vault-considerations)
13. [Implementation Phases](#13-implementation-phases)
14. [Risks & Mitigations](#14-risks--mitigations)
15. [Decision Log](#15-decision-log)

---

## 1. Executive Summary

### 1.1 Problem Statement

The current VettID vault architecture provisions a dedicated EC2 instance per user. While this provides strong isolation, it has significant drawbacks:

- **Cost**: ~$6/month per active vault (t4g.micro)
- **Resource waste**: Most vaults are idle most of the time
- **Scaling complexity**: Each vault is a separate infrastructure component
- **Startup latency**: 30-60 seconds to provision a new vault

### 1.2 Proposed Solution

Migrate to a multi-tenant vault architecture using AWS Nitro Enclaves:

- **Shared compute**: Multiple vault-manager processes run within a single Nitro Enclave
- **Per-user isolation**: Each vault has its own embedded NATS datastore with encrypted storage
- **Shared handlers**: WASM event handlers loaded once, executed in isolated contexts
- **Hardware attestation**: Users can cryptographically verify the code handling their data

### 1.3 Key Benefits

| Metric | Current | Proposed | Improvement |
|--------|---------|----------|-------------|
| Cost per vault (100 users) | $6.00/mo | $1.20/mo | **80% reduction** |
| Cost per vault (500 users) | $6.00/mo | $0.48/mo | **92% reduction** |
| Vault startup time | 30-60s | 300-500ms | **99% faster** |
| Security model | Trust VettID infra | Hardware attestation | **Stronger** |

### 1.4 Core Security Property Preserved

> **VettID has no access to user vault data.**

This property is preserved through:
- End-to-end encryption (user app ↔ enclave)
- Per-user encryption keys that never leave enclave memory
- Attestation proving exact code running in enclave
- Parent process only sees encrypted blobs

---

## 2. Current Architecture

### 2.1 Overview

```
┌─────────────┐                                    ┌─────────────────────┐
│  User App   │                                    │  User's EC2 Vault   │
│  (iOS/      │         NATS (E2E encrypted)       │  (t4g.micro)        │
│   Android)  │◄──────────────────────────────────►│                     │
│             │                                    │  ┌───────────────┐  │
│  Holds:     │                                    │  │vault-manager  │  │
│  • Vault    │                                    │  │               │  │
│    creds    │                                    │  │• NATS server  │  │
│  • Session  │                                    │  │• JetStream    │  │
│    keys     │                                    │  │• WASM runtime │  │
│             │                                    │  └───────────────┘  │
└─────────────┘                                    └─────────────────────┘
```

### 2.2 Current Components

| Component | Description | Per-User |
|-----------|-------------|----------|
| EC2 Instance | t4g.micro running vault-manager | Yes |
| Embedded NATS | Message handling + JetStream storage | Yes |
| WASM Runtime | Executes event handlers | Yes |
| EBS Volume | Persistent storage for vault data | Yes |
| Security Group | Network isolation | Yes |

### 2.3 Current Security Model

1. **Credential-based access**: User holds NATS credentials for their vault
2. **E2E encryption**: X25519 key exchange establishes session keys
3. **Physical isolation**: Separate EC2 instance per user
4. **VettID is blind**: Infrastructure routes encrypted messages only

### 2.4 Current Limitations

- **Idle resource waste**: Most vaults active <1% of time
- **No attestation**: Users must trust VettID deployed correct code
- **Slow provisioning**: EC2 launch + configuration takes 30-60 seconds
- **Complex operations**: Each vault is separate infrastructure

---

## 3. Proposed Architecture

### 3.1 High-Level Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                            Nitro Enclave                                  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                      Enclave Supervisor                             │  │
│  │  • Spawns/manages vault-manager processes                           │  │
│  │  • Routes vsock messages to correct vault                           │  │
│  │  • Manages shared WASM handler cache                                │  │
│  └──────────────────────────────────┬─────────────────────────────────┘  │
│                                     │                                     │
│         ┌───────────────────────────┼───────────────────────────┐        │
│         │                           │                           │        │
│         ▼                           ▼                           ▼        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐          │
│  │ vault-manager   │  │ vault-manager   │  │ vault-manager   │   ...    │
│  │ (User A)        │  │ (User B)        │  │ (User C)        │          │
│  │                 │  │                 │  │                 │          │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │          │
│  │ │ Embedded    │ │  │ │ Embedded    │ │  │ │ Embedded    │ │          │
│  │ │ NATS +      │ │  │ │ NATS +      │ │  │ │ NATS +      │ │          │
│  │ │ JetStream   │ │  │ │ JetStream   │ │  │ │ JetStream   │ │          │
│  │ └──────┬──────┘ │  │ └──────┬──────┘ │  │ └──────┬──────┘ │          │
│  │        │        │  │        │        │  │        │        │          │
│  │ ┌──────▼──────┐ │  │ ┌──────▼──────┐ │  │ ┌──────▼──────┐ │          │
│  │ │ Encrypted   │ │  │ │ Encrypted   │ │  │ │ Encrypted   │ │          │
│  │ │ Storage     │ │  │ │ Storage     │ │  │ │ Storage     │ │          │
│  │ │ Adapter     │ │  │ │ Adapter     │ │  │ │ Adapter     │ │          │
│  │ └──────┬──────┘ │  │ └──────┬──────┘ │  │ └──────┬──────┘ │          │
│  └────────┼────────┘  └────────┼────────┘  └────────┼────────┘          │
│           │                    │                    │                    │
│           └────────────────────┴────────────────────┘                    │
│                                │                                         │
│  ┌─────────────────────────────▼─────────────────────────────────────┐  │
│  │                    Shared WASM Handler Cache                       │  │
│  │  • Handlers loaded once, shared across all vaults (read-only)     │  │
│  │  • Each execution isolated with per-vault context                 │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│                              vsock                                        │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │
           ════════════════════════╪════════════════════════
                    Hardware isolation boundary
           ════════════════════════╪════════════════════════
                                   │
┌──────────────────────────────────▼───────────────────────────────────────┐
│                           Parent EC2 Instance                             │
│                                                                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐          │
│  │ NATS Client     │  │ S3 Client       │  │ vsock Router    │          │
│  │ (central        │  │ (encrypted blob │  │ (msg dispatch)  │          │
│  │  cluster)       │  │  I/O)           │  │                 │          │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘          │
│                                                                          │
│  CANNOT ACCESS: vault keys, plaintext data, session keys                │
│  CAN ACCESS: encrypted blobs (opaque), message routing metadata         │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Component Summary

| Component | Location | Shared/Per-User | Description |
|-----------|----------|-----------------|-------------|
| Enclave Supervisor | Enclave | Shared | Manages vault lifecycle, routes messages |
| vault-manager | Enclave | Per-user | Handles user's vault operations |
| Embedded NATS | Enclave | Per-user | Local message bus + JetStream storage |
| Encrypted Storage Adapter | Enclave | Per-user | Encrypts data before externalization |
| WASM Handler Cache | Enclave | Shared | Compiled handlers, read-only |
| Parent Process | EC2 Host | Shared | External I/O (NATS, S3), no key access |
| Central NATS | External | Shared | Routes messages from apps to enclaves |
| S3 Storage | External | Per-user prefix | Encrypted vault data blobs |

### 3.3 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   TRUST BOUNDARY: User's App + Nitro Enclave                           │
│                                                                         │
│   ┌─────────────┐                      ┌─────────────────────────────┐ │
│   │  User App   │◄────────────────────►│  Nitro Enclave              │ │
│   │             │  E2E Encrypted       │  (attestation verified)     │ │
│   │  • Holds    │                      │                             │ │
│   │    master   │                      │  • Vault DEK                │ │
│   │    secret   │                      │  • Session keys             │ │
│   │  • Verifies │                      │  • Plaintext processing     │ │
│   │    attesta- │                      │                             │ │
│   │    tion     │                      │                             │ │
│   └─────────────┘                      └─────────────────────────────┘ │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
          ══════════════════════════╪══════════════════════════
                      UNTRUSTED BOUNDARY
          ══════════════════════════╪══════════════════════════
                                    │
┌───────────────────────────────────▼─────────────────────────────────────┐
│                                                                         │
│   UNTRUSTED: VettID Infrastructure                                     │
│                                                                         │
│   • Parent EC2 process (routes encrypted blobs)                        │
│   • Central NATS cluster (routes encrypted messages)                   │
│   • S3 storage (stores encrypted blobs)                                │
│   • VettID operators                                                   │
│                                                                         │
│   CAN SEE: Ciphertext, metadata (user IDs, timestamps)                 │
│   CANNOT SEE: Plaintext data, encryption keys                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Security Model

### 4.1 Attestation Overview

AWS Nitro Enclaves provide hardware-backed attestation that cryptographically proves:

1. **Code identity**: Exact hash of code running in the enclave (PCR values)
2. **Isolation**: Code is running in a genuine Nitro Enclave
3. **Freshness**: Attestation document is recently generated

```
Attestation Document Contents:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  {                                                              │
│    "module_id": "enclave-abc123",                               │
│    "timestamp": 1704189600000,                                  │
│    "pcrs": {                                                    │
│      "0": "sha384-hash-of-enclave-image",                       │
│      "1": "sha384-hash-of-kernel",                              │
│      "2": "sha384-hash-of-application",                         │
│      "3": "sha384-hash-of-iam-role",                            │
│      ...                                                        │
│    },                                                           │
│    "public_key": "enclave-ephemeral-pubkey",                    │
│    "certificate": "aws-nitro-attestation-cert"                  │
│  }                                                              │
│                                                                 │
│  Signed by: AWS Nitro Attestation PKI                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Attestation Verification Flow

```
┌─────────────────┐                              ┌─────────────────────┐
│    User App     │                              │   Nitro Enclave     │
└────────┬────────┘                              └──────────┬──────────┘
         │                                                  │
         │  1. Bootstrap Request                            │
         │─────────────────────────────────────────────────►│
         │                                                  │
         │                                                  │ 2. Generate
         │                                                  │    attestation
         │                                                  │    document
         │                                                  │
         │  3. Attestation Document                         │
         │◄─────────────────────────────────────────────────│
         │     (signed by AWS Nitro)                        │
         │                                                  │
         │ 4. Verify:                                       │
         │    a. AWS signature valid                        │
         │    b. PCRs match expected                        │
         │       (published by VettID)                      │
         │    c. Timestamp recent                           │
         │                                                  │
         │ 5. If valid, encrypt session                     │
         │    key to enclave's pubkey                       │
         │                                                  │
         │  6. Encrypted Session Setup                      │
         │─────────────────────────────────────────────────►│
         │                                                  │
         │                                                  │ 7. Decrypt
         │                                                  │    (only this
         │                                                  │    enclave can)
         │                                                  │
         │  8. Session Established                          │
         │◄────────────────────────────────────────────────►│
         │     (E2E encrypted)                              │
         │                                                  │
```

### 4.3 PCR Publication

VettID publishes expected PCR values for each enclave release:

```
Published PCRs (example):
┌─────────────────────────────────────────────────────────────────┐
│  Release: v2.1.0                                                │
│  Date: 2026-01-15                                               │
│                                                                 │
│  PCR0: c7b2f3d8e9a1b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4  │
│  PCR1: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7  │
│  PCR2: d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0  │
│                                                                 │
│  Source: https://github.com/vettid/vault-enclave (auditable)   │
│  Signed: VettID Release Key                                     │
└─────────────────────────────────────────────────────────────────┘
```

User apps ship with:
- Expected PCR values for current release
- VettID's release signing key
- Ability to update PCRs via app update

### 4.4 What Attestation Guarantees

| Threat | Protected? | How |
|--------|------------|-----|
| VettID deploys malicious code | Yes | PCRs would differ, app rejects |
| VettID reads vault data | Yes | Keys only exist in enclave memory |
| AWS operator accesses data | Yes | Nitro hardware prevents memory access |
| Man-in-the-middle attack | Yes | Session encrypted to attested pubkey |
| Replay of old attestation | Yes | Timestamp + nonce validation |
| Compromised parent process | Yes | Parent never has keys, only ciphertext |

### 4.5 Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Key Hierarchy                                  │
│                                                                         │
│  User's Master Secret (held by user app only)                          │
│         │                                                               │
│         ▼                                                               │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Vault DEK = KDF(master_secret, vault_salt)                      │   │
│  │                                                                  │   │
│  │ Derived during bootstrap, stored sealed in S3                   │   │
│  │ Used to encrypt all vault data                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│         │                                                               │
│         ├──────────────────────┬──────────────────────┐                │
│         ▼                      ▼                      ▼                │
│  ┌─────────────┐       ┌─────────────┐       ┌─────────────┐          │
│  │ JetStream   │       │ Handler     │       │ Other vault │          │
│  │ data        │       │ state       │       │ data        │          │
│  │ (encrypted) │       │ (encrypted) │       │ (encrypted) │          │
│  └─────────────┘       └─────────────┘       └─────────────┘          │
│                                                                         │
│  Session Keys (per-connection, ephemeral)                              │
│         │                                                               │
│         ▼                                                               │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Session Key = X25519(app_ephemeral, enclave_ephemeral)          │   │
│  │                                                                  │   │
│  │ Established per-session via key exchange                        │   │
│  │ Used for E2E encryption of messages in transit                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.6 Sealed Storage

Vault DEKs must persist across enclave restarts. Nitro provides sealing:

```
Sealing (first bootstrap):

  vault_dek (32 bytes, plaintext)
       │
       ▼
  ┌────────────────────────────────────────────────────────────────┐
  │ NitroKMS.Seal(vault_dek, attestation_doc)                      │
  │                                                                 │
  │ Encryption bound to:                                           │
  │   • PCR0, PCR1, PCR2 (code identity)                           │
  │                                                                 │
  │ NOT bound to:                                                   │
  │   • Instance ID                                                 │
  │   • Hardware serial number                                      │
  │   • IP address                                                  │
  │   • Time                                                        │
  └────────────────────────────────────────────────────────────────┘
       │
       ▼
  sealed_dek (ciphertext) → stored in S3


Unsealing (vault load):

  sealed_dek (from S3)
       │
       ▼
  ┌────────────────────────────────────────────────────────────────┐
  │ NitroKMS.Unseal(sealed_dek)                                    │
  │                                                                 │
  │ Succeeds if and only if:                                       │
  │   • Running in genuine Nitro Enclave                           │
  │   • Current PCRs match sealed PCRs                             │
  │                                                                 │
  │ Fails if:                                                       │
  │   • Code has been modified (different PCRs)                    │
  │   • Running outside enclave                                     │
  │   • Running on non-Nitro hardware                               │
  └────────────────────────────────────────────────────────────────┘
       │
       ▼
  vault_dek (32 bytes, plaintext) → available in enclave memory
```

**Critical property**: Sealed data can be unsealed by ANY enclave running the SAME code, regardless of which physical machine or AWS account.

---

## 5. Component Design

### 5.1 Enclave Supervisor

The supervisor is the main process inside the enclave:

```go
type EnclaveSupervisor struct {
    // Active vault-manager processes
    vaults map[string]*VaultProcess

    // Shared resources
    handlerCache *WASMHandlerCache

    // Configuration
    maxActiveVaults int

    // Communication
    vsock *VsockListener
}

// Main entry point
func (s *EnclaveSupervisor) Run() {
    // Listen for messages from parent
    for msg := range s.vsock.Messages() {
        switch msg.Type {
        case "vault_message":
            s.routeToVault(msg.OwnerSpace, msg.Payload)
        case "handler_update":
            s.handlerCache.Update(msg.HandlerID, msg.WASMBytes)
        case "health_check":
            s.respondHealthCheck(msg)
        }
    }
}

func (s *EnclaveSupervisor) routeToVault(ownerSpace string, payload []byte) {
    vault, exists := s.vaults[ownerSpace]

    if !exists {
        // Start new vault-manager
        vault = s.startVault(ownerSpace)
    }

    vault.HandleMessage(payload)
}
```

### 5.2 Vault Manager Process

Each user has a dedicated vault-manager:

```go
type VaultManager struct {
    ownerSpace     string

    // Per-user keys (never leave enclave)
    vaultDEK       [32]byte
    sessionKey     [32]byte

    // Per-user embedded NATS
    natsServer     *nats.Server
    jetStream      nats.JetStreamContext

    // Encrypted storage (data leaves enclave encrypted)
    storage        *EncryptedStorageAdapter

    // Reference to shared handler cache
    handlerCache   *WASMHandlerCache
}

func (vm *VaultManager) HandleMessage(encrypted []byte) {
    // 1. Decrypt with session key
    plaintext := vm.decrypt(encrypted)

    // 2. Parse event
    var event Event
    json.Unmarshal(plaintext, &event)

    // 3. Process based on event type
    result := vm.processEvent(event)

    // 4. Encrypt response
    response := vm.encrypt(result)

    // 5. Send back via vsock
    vm.respond(response)
}

func (vm *VaultManager) processEvent(event Event) []byte {
    // Get handler from shared cache
    handler := vm.handlerCache.Get(event.Type)

    // Create isolated WASM instance for execution
    instance := handler.NewInstance(WASMConfig{
        MemoryLimit: 128 * 1024 * 1024,
        CPULimit:    time.Second,
    })

    // Inject vault context (this vault only)
    instance.SetContext(VaultContext{
        OwnerSpace: vm.ownerSpace,
        NATS:       vm.jetStream,
        Storage:    vm.storage,
    })

    // Execute handler
    return instance.Call("handle", event)
}
```

### 5.3 Encrypted Storage Adapter

Bridges JetStream to external storage:

```go
type EncryptedStorageAdapter struct {
    vaultDEK   [32]byte
    ownerSpace string

    // In-memory cache for hot data
    cache      *LRUCache

    // vsock for external I/O
    vsock      *VsockConn
}

// Called by JetStream to persist data
func (e *EncryptedStorageAdapter) Put(key string, data []byte) error {
    // 1. Generate random nonce
    nonce := make([]byte, 12)
    rand.Read(nonce)

    // 2. Encrypt with vault DEK
    aead, _ := chacha20poly1305.New(e.vaultDEK[:])
    ciphertext := aead.Seal(nil, nonce, data, []byte(key))

    // 3. Prepend nonce
    blob := append(nonce, ciphertext...)

    // 4. Update local cache
    e.cache.Set(key, data)

    // 5. Send to parent for S3 storage
    return e.vsock.Send(StorageRequest{
        Op:         "PUT",
        OwnerSpace: e.ownerSpace,
        Key:        key,
        Data:       blob,
    })
}

// Called by JetStream to retrieve data
func (e *EncryptedStorageAdapter) Get(key string) ([]byte, error) {
    // 1. Check cache
    if data, ok := e.cache.Get(key); ok {
        return data, nil
    }

    // 2. Request from parent
    resp, err := e.vsock.Request(StorageRequest{
        Op:         "GET",
        OwnerSpace: e.ownerSpace,
        Key:        key,
    })
    if err != nil {
        return nil, err
    }

    // 3. Decrypt
    nonce := resp.Data[:12]
    ciphertext := resp.Data[12:]

    aead, _ := chacha20poly1305.New(e.vaultDEK[:])
    plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(key))
    if err != nil {
        return nil, fmt.Errorf("decryption failed: %w", err)
    }

    // 4. Cache and return
    e.cache.Set(key, plaintext)
    return plaintext, nil
}
```

### 5.4 Shared WASM Handler Cache

```go
type WASMHandlerCache struct {
    handlers map[string]*CompiledHandler
    mu       sync.RWMutex
    runtime  wazero.Runtime
}

type CompiledHandler struct {
    HandlerID  string
    Module     wazero.CompiledModule
    Signature  []byte  // Verified before adding to cache
    LoadedAt   time.Time
}

func (c *WASMHandlerCache) Get(handlerID string) *CompiledHandler {
    c.mu.RLock()
    defer c.mu.RUnlock()
    return c.handlers[handlerID]
}

func (c *WASMHandlerCache) Update(handlerID string, wasmBytes []byte, signature []byte) error {
    // 1. Verify signature
    if !verifySignature(wasmBytes, signature, trustedSigningKey) {
        return errors.New("invalid handler signature")
    }

    // 2. Compile WASM module
    compiled, err := c.runtime.CompileModule(context.Background(), wasmBytes)
    if err != nil {
        return err
    }

    // 3. Add to cache
    c.mu.Lock()
    defer c.mu.Unlock()

    c.handlers[handlerID] = &CompiledHandler{
        HandlerID: handlerID,
        Module:    compiled,
        Signature: signature,
        LoadedAt:  time.Now(),
    }

    return nil
}

// NewInstance creates an isolated execution instance
func (h *CompiledHandler) NewInstance(config WASMConfig) *WASMInstance {
    // Each call gets isolated memory and state
    return &WASMInstance{
        module:      h.Module,
        memoryLimit: config.MemoryLimit,
        cpuLimit:    config.CPULimit,
    }
}
```

### 5.5 Parent Process

Runs on the EC2 host outside the enclave:

```go
type ParentProcess struct {
    // External connections
    natsConn    *nats.Conn     // To central NATS cluster
    s3Client    *s3.Client     // For blob storage

    // Enclave communication
    vsock       *VsockConn     // To enclave

    // Routing
    routingTable map[string]string  // ownerSpace → enclave vsock CID
}

func (p *ParentProcess) Run() {
    // Subscribe to vault messages from central NATS
    p.natsConn.Subscribe("vault.>", func(msg *nats.Msg) {
        // Extract owner space from subject
        ownerSpace := extractOwnerSpace(msg.Subject)

        // Forward to enclave (message is E2E encrypted, we can't read it)
        p.vsock.Send(EnclaveMessage{
            Type:       "vault_message",
            OwnerSpace: ownerSpace,
            Payload:    msg.Data,  // Opaque ciphertext
            ReplyTo:    msg.Reply,
        })
    })

    // Handle storage requests from enclave
    go p.handleStorageRequests()

    // Handle responses from enclave
    go p.handleEnclaveResponses()
}

func (p *ParentProcess) handleStorageRequests() {
    for req := range p.vsock.StorageRequests() {
        switch req.Op {
        case "PUT":
            // Store encrypted blob in S3
            key := fmt.Sprintf("vaults/%s/%s", req.OwnerSpace, req.Key)
            p.s3Client.PutObject(context.Background(), &s3.PutObjectInput{
                Bucket: aws.String("vettid-vault-data"),
                Key:    aws.String(key),
                Body:   bytes.NewReader(req.Data),  // Opaque ciphertext
            })
        case "GET":
            // Retrieve encrypted blob from S3
            key := fmt.Sprintf("vaults/%s/%s", req.OwnerSpace, req.Key)
            result, _ := p.s3Client.GetObject(context.Background(), &s3.GetObjectInput{
                Bucket: aws.String("vettid-vault-data"),
                Key:    aws.String(key),
            })
            data, _ := io.ReadAll(result.Body)
            p.vsock.SendStorageResponse(req.ID, data)  // Opaque ciphertext
        }
    }
}
```

---

## 6. Data Storage & Encryption

### 6.1 Storage Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            S3 Bucket                                     │
│                        vettid-vault-data                                 │
│                                                                         │
│  vaults/                                                                │
│  ├── user-ABC123/                                                       │
│  │   ├── sealed_dek.bin           # Sealed vault DEK                   │
│  │   ├── jetstream/                                                     │
│  │   │   ├── EVENTS/                                                    │
│  │   │   │   ├── 00000001.enc     # Encrypted stream data              │
│  │   │   │   ├── 00000002.enc                                          │
│  │   │   │   └── meta.enc         # Encrypted stream metadata          │
│  │   │   ├── VAULT_KV/                                                  │
│  │   │   │   ├── data.enc                                               │
│  │   │   │   └── meta.enc                                               │
│  │   │   └── HANDLERS/                                                  │
│  │   │       └── ...                                                    │
│  │   └── state/                                                         │
│  │       └── vault_state.enc      # Encrypted vault state              │
│  │                                                                      │
│  ├── user-DEF456/                                                       │
│  │   └── ...                                                            │
│  │                                                                      │
│  └── user-GHI789/                                                       │
│      └── ...                                                            │
│                                                                         │
│  handlers/                          # Shared, not encrypted             │
│  ├── backup.wasm                                                        │
│  ├── backup.wasm.sig                                                    │
│  ├── sync.wasm                                                          │
│  └── sync.wasm.sig                                                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Encryption Specification

| Data Type | Algorithm | Key | Nonce |
|-----------|-----------|-----|-------|
| Vault data (JetStream) | ChaCha20-Poly1305 | Vault DEK | Random 12 bytes per write |
| Sealed DEK | AWS Nitro KMS | Nitro Attestation | Internal |
| Session messages | ChaCha20-Poly1305 | Session Key | Random 12 bytes per message |

### 6.3 Blob Format

```
Encrypted Blob Format:
┌────────────────────────────────────────────────────────────────┐
│  Nonce (12 bytes)  │  Ciphertext (variable)  │  Tag (16 bytes) │
└────────────────────────────────────────────────────────────────┘

Additional Authenticated Data (AAD): Object key (path in S3)
```

### 6.4 S3 Configuration

```typescript
const vaultDataBucket = new s3.Bucket(this, 'VaultDataBucket', {
  bucketName: 'vettid-vault-data',

  // Server-side encryption (defense in depth, not primary protection)
  encryption: s3.BucketEncryption.S3_MANAGED,

  // Versioning for recovery
  versioned: true,

  // Lifecycle rules
  lifecycleRules: [
    {
      id: 'cleanup-old-versions',
      noncurrentVersionExpiration: Duration.days(30),
    },
  ],

  // Block public access
  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,

  // Access logging
  serverAccessLogsBucket: logBucket,
  serverAccessLogsPrefix: 'vault-data-access/',
});
```

---

## 7. Process Lifecycle Management

### 7.1 Vault Lifecycle States

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Vault Lifecycle                                   │
│                                                                         │
│                           ┌─────────┐                                   │
│                           │ INITIAL │                                   │
│                           └────┬────┘                                   │
│                                │                                        │
│                    First bootstrap request                              │
│                                │                                        │
│                                ▼                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                      BOOTSTRAPPING                              │   │
│   │                                                                 │   │
│   │  1. Generate vault DEK from master secret                      │   │
│   │  2. Seal DEK with Nitro attestation                            │   │
│   │  3. Store sealed DEK in S3                                     │   │
│   │  4. Initialize embedded NATS + JetStream                       │   │
│   │  5. Create initial streams                                     │   │
│   │  6. Establish session with app                                 │   │
│   └────────────────────────────────────────────────────────────────┘   │
│                                │                                        │
│                                ▼                                        │
│                          ┌──────────┐                                   │
│              ┌──────────►│  ACTIVE  │◄──────────┐                      │
│              │           └────┬─────┘           │                      │
│              │                │                 │                      │
│         Load from        Idle timeout      Message                    │
│         evicted          (optional)        received                   │
│              │                │                 │                      │
│              │                ▼                 │                      │
│              │          ┌──────────┐            │                      │
│              └──────────┤  EVICTED │────────────┘                      │
│                         └────┬─────┘                                   │
│                              │                                         │
│                         User deletes                                   │
│                           account                                      │
│                              │                                         │
│                              ▼                                         │
│                         ┌─────────┐                                    │
│                         │ DELETED │                                    │
│                         └─────────┘                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Active → Evicted Transition

```go
func (s *EnclaveSupervisor) evictVault(ownerSpace string) error {
    vault := s.vaults[ownerSpace]

    // 1. Stop accepting new messages
    vault.SetDraining(true)

    // 2. Wait for in-flight operations (with timeout)
    vault.WaitForDrain(5 * time.Second)

    // 3. Flush all pending writes to S3
    if err := vault.storage.Flush(); err != nil {
        return err
    }

    // 4. Shutdown embedded NATS gracefully
    vault.natsServer.Shutdown()

    // 5. Clear sensitive data from memory
    vault.ZeroizeKeys()

    // 6. Remove from active map
    delete(s.vaults, ownerSpace)

    log.Info().
        Str("owner_space", ownerSpace).
        Msg("Vault evicted successfully")

    return nil
}
```

### 7.3 Evicted → Active Transition (Cold Start)

```go
func (s *EnclaveSupervisor) loadVault(ownerSpace string) (*VaultManager, error) {
    startTime := time.Now()

    // 1. Load sealed DEK from S3 (via parent)
    sealedDEK, err := s.loadSealedDEK(ownerSpace)
    if err != nil {
        return nil, fmt.Errorf("failed to load sealed DEK: %w", err)
    }
    // Latency: ~50-100ms

    // 2. Unseal DEK using Nitro KMS
    vaultDEK, err := nitro.Unseal(sealedDEK)
    if err != nil {
        return nil, fmt.Errorf("failed to unseal DEK: %w", err)
    }
    // Latency: ~5-10ms

    // 3. Create encrypted storage adapter
    storage := NewEncryptedStorageAdapter(vaultDEK, ownerSpace, s.vsock)

    // 4. Start embedded NATS with custom storage backend
    natsServer, err := startEmbeddedNATS(storage)
    if err != nil {
        return nil, fmt.Errorf("failed to start NATS: %w", err)
    }
    // Latency: ~20-50ms

    // 5. Load JetStream metadata and indexes
    js, err := natsServer.JetStream()
    if err != nil {
        return nil, fmt.Errorf("failed to get JetStream context: %w", err)
    }
    // Latency: ~100-300ms (depends on stream count)

    // 6. Create vault manager
    vault := &VaultManager{
        ownerSpace:   ownerSpace,
        vaultDEK:     vaultDEK,
        natsServer:   natsServer,
        jetStream:    js,
        storage:      storage,
        handlerCache: s.handlerCache,
        lastActivity: time.Now(),
    }

    // 7. Add to active map
    s.vaults[ownerSpace] = vault

    log.Info().
        Str("owner_space", ownerSpace).
        Dur("cold_start_ms", time.Since(startTime)).
        Msg("Vault loaded successfully")

    return vault, nil
    // Total latency: ~300-500ms
}
```

### 7.4 Memory Management

```go
const (
    // Memory budget
    EnclaveMemory      = 12 * 1024 * 1024 * 1024  // 12 GB
    SupervisorOverhead = 200 * 1024 * 1024         // 200 MB
    HandlerCacheSize   = 500 * 1024 * 1024         // 500 MB
    PerVaultMemory     = 70 * 1024 * 1024          // 70 MB

    // Calculated max vaults
    AvailableForVaults = EnclaveMemory - SupervisorOverhead - HandlerCacheSize
    MaxActiveVaults    = AvailableForVaults / PerVaultMemory  // ~161
)

type MemoryManager struct {
    currentUsage   int64
    maxUsage       int64
    vaultSizes     map[string]int64
}

func (m *MemoryManager) CanLoadVault() bool {
    return m.currentUsage + PerVaultMemory < m.maxUsage
}

func (m *MemoryManager) ShouldEvict() bool {
    return m.currentUsage > m.maxUsage * 0.9  // 90% threshold
}
```

---

## 8. Scaling & High Availability

### 8.1 Multi-AZ Deployment

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         AWS Region (us-east-1)                          │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Network Load Balancer                         │   │
│  │                    (routes NATS connections)                     │   │
│  └──────────────────────────────┬──────────────────────────────────┘   │
│                                 │                                       │
│         ┌───────────────────────┼───────────────────────┐              │
│         │                       │                       │              │
│         ▼                       ▼                       ▼              │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐      │
│  │  us-east-1a     │   │  us-east-1b     │   │  us-east-1c     │      │
│  │                 │   │                 │   │                 │      │
│  │ ┌─────────────┐ │   │ ┌─────────────┐ │   │ ┌─────────────┐ │      │
│  │ │ Enclave ASG │ │   │ │ Enclave ASG │ │   │ │ Enclave ASG │ │      │
│  │ │ min: 1      │ │   │ │ min: 1      │ │   │ │ min: 1      │ │      │
│  │ │ max: 5      │ │   │ │ max: 5      │ │   │ │ max: 5      │ │      │
│  │ │             │ │   │ │             │ │   │ │             │ │      │
│  │ │ ┌─────────┐ │ │   │ │ ┌─────────┐ │ │   │ │ ┌─────────┐ │ │      │
│  │ │ │Enclave 1│ │ │   │ │ │Enclave 1│ │ │   │ │ │Enclave 1│ │ │      │
│  │ │ └─────────┘ │ │   │ │ └─────────┘ │ │   │ │ └─────────┘ │ │      │
│  │ │ ┌─────────┐ │ │   │ │ ┌─────────┐ │ │   │ │             │ │      │
│  │ │ │Enclave 2│ │ │   │ │ │Enclave 2│ │ │   │ │             │ │      │
│  │ │ └─────────┘ │ │   │ │ └─────────┘ │ │   │ │             │ │      │
│  │ └─────────────┘ │   │ └─────────────┘ │   │ └─────────────┘ │      │
│  └─────────────────┘   └─────────────────┘   └─────────────────┘      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Auto-Scaling Configuration

```typescript
const enclaveASG = new autoscaling.AutoScalingGroup(this, 'EnclaveASG', {
  vpc,
  instanceType: ec2.InstanceType.of(ec2.InstanceClass.C6A, ec2.InstanceSize.XLARGE2),
  machineImage: enclaveAMI,

  minCapacity: 3,  // One per AZ
  maxCapacity: 15,

  // Scaling based on active vault count
  healthCheck: autoscaling.HealthCheck.elb({
    grace: Duration.minutes(5),
  }),
});

// Scale based on vault count per enclave
enclaveASG.scaleOnMetric('VaultCountScaling', {
  metric: new cloudwatch.Metric({
    namespace: 'VettID/Enclave',
    metricName: 'ActiveVaultCount',
    statistic: 'Average',
  }),
  scalingSteps: [
    { upper: 50, change: -1 },   // Scale in if < 50 vaults
    { lower: 120, change: +1 },  // Scale out if > 120 vaults
    { lower: 140, change: +2 },  // Scale out faster if > 140 vaults
  ],
  adjustmentType: autoscaling.AdjustmentType.CHANGE_IN_CAPACITY,
});
```

### 8.3 Load Balancing Strategy

Since vaults can run on any enclave, use simple load balancing:

```go
type VaultRouter struct {
    enclaves []EnclaveEndpoint
    current  atomic.Int32
}

func (r *VaultRouter) RouteMessage(ownerSpace string, msg []byte) error {
    // Round-robin across healthy enclaves
    idx := r.current.Add(1) % int32(len(r.enclaves))
    enclave := r.enclaves[idx]

    // Forward to selected enclave
    return enclave.Send(ownerSpace, msg)
}
```

**No sticky sessions needed** - any enclave can load any vault.

### 8.4 Failover Behavior

```
Scenario: Enclave instance failure

Time 0:00 - Enclave A fails
          - Active vaults on A: 100
          - In-flight requests: lost (client retries)

Time 0:01 - Health check detects failure
          - NLB stops routing to A
          - ASG launches replacement

Time 0:02 - Client retries arrive at Enclave B
          - For each vault:
            - Cold start: ~300-500ms
            - Vault loaded from S3
            - Request processed

Time 0:05 - All traffic re-routed
          - Replacement enclave launching in background

Total user impact: ~500ms latency increase during failover
```

---

## 9. Migration Strategy

### 9.1 Migration Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Migration Timeline                                │
│                                                                         │
│  Phase 1          Phase 2          Phase 3          Phase 4            │
│  Preparation      Parallel Run     Gradual Migrate  Decommission       │
│                                                                         │
│  ┌─────────┐      ┌─────────┐      ┌─────────┐      ┌─────────┐       │
│  │ Build & │      │ Run both│      │ Migrate │      │ Shutdown│       │
│  │ Test    │      │ systems │      │ users   │      │ old EC2 │       │
│  │ Enclave │      │         │      │ in waves│      │ vaults  │       │
│  └─────────┘      └─────────┘      └─────────┘      └─────────┘       │
│                                                                         │
│  Duration:        Duration:        Duration:        Duration:          │
│  2-3 weeks        1-2 weeks        2-4 weeks        1 week             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.2 Phase 1: Preparation

**Objective**: Build and validate enclave infrastructure

Tasks:
1. Develop enclave vault-manager
2. Build enclave image and publish PCRs
3. Update mobile apps with attestation verification
4. Deploy enclave infrastructure to staging
5. End-to-end testing with test accounts

```bash
# Build enclave image
nitro-cli build-enclave \
  --docker-uri vettid/vault-enclave:v1.0.0 \
  --output-file vault-enclave.eif

# Get PCRs
nitro-cli describe-eif --eif-path vault-enclave.eif

# Publish PCRs
aws ssm put-parameter \
  --name /vettid/enclave/pcrs/v1.0.0 \
  --value '{"PCR0":"abc...","PCR1":"def...","PCR2":"ghi..."}' \
  --type SecureString
```

### 9.3 Phase 2: Parallel Run

**Objective**: Run both systems simultaneously, route new users to enclave

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Parallel Architecture                             │
│                                                                         │
│                    ┌───────────────────────────┐                        │
│                    │     Central NATS          │                        │
│                    │     (message router)      │                        │
│                    └─────────────┬─────────────┘                        │
│                                  │                                      │
│              ┌───────────────────┴───────────────────┐                 │
│              │                                       │                 │
│              ▼                                       ▼                 │
│  ┌───────────────────────┐           ┌───────────────────────┐        │
│  │   Enclave Fleet       │           │   Legacy EC2 Vaults   │        │
│  │   (new users)         │           │   (existing users)    │        │
│  │                       │           │                       │        │
│  │   Routes:             │           │   Routes:             │        │
│  │   vault.enclave.>     │           │   vault.ec2.>         │        │
│  └───────────────────────┘           └───────────────────────┘        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

Routing logic:
```go
func routeVaultMessage(ownerSpace string, msg []byte) {
    userConfig := getUserConfig(ownerSpace)

    if userConfig.VaultType == "enclave" {
        publishToEnclave(ownerSpace, msg)
    } else {
        publishToEC2(ownerSpace, msg)
    }
}
```

### 9.4 Phase 3: Gradual Migration

**Objective**: Migrate existing users from EC2 to enclave

Migration per user:
```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Per-User Migration Flow                               │
│                                                                         │
│  1. Mark user for migration                                             │
│     └─ Set flag in user config: migration_pending = true                │
│                                                                         │
│  2. Wait for user's next app session                                    │
│     └─ App detects migration flag                                       │
│                                                                         │
│  3. App initiates migration bootstrap                                   │
│     ├─ Connect to enclave                                               │
│     ├─ Verify attestation                                               │
│     ├─ Establish new session                                            │
│     └─ Provide master secret for DEK derivation                         │
│                                                                         │
│  4. Enclave creates new vault                                           │
│     ├─ Derive vault DEK                                                 │
│     ├─ Seal DEK with attestation                                        │
│     └─ Initialize empty JetStream                                       │
│                                                                         │
│  5. Data migration (user-initiated)                                     │
│     ├─ App reads data from EC2 vault (decrypts locally)                │
│     ├─ App writes data to enclave vault (encrypts locally)             │
│     └─ Progress tracked in app                                          │
│                                                                         │
│  6. Switchover                                                          │
│     ├─ Update routing to enclave                                        │
│     ├─ Mark migration complete                                          │
│     └─ Schedule EC2 vault for deletion                                  │
│                                                                         │
│  7. Cleanup                                                             │
│     └─ Terminate EC2 vault after 7-day grace period                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

Wave strategy:
```
Wave 1: Internal team accounts (10 users)
        Duration: 1 week

Wave 2: Beta users who opt-in (100 users)
        Duration: 1 week

Wave 3: 10% of remaining users
        Duration: 1 week

Wave 4: 50% of remaining users
        Duration: 1 week

Wave 5: All remaining users
        Duration: 1 week
```

### 9.5 Phase 4: Decommission

**Objective**: Shut down legacy EC2 vault infrastructure

Tasks:
1. Verify all users migrated
2. Final backup of any unmigrated data
3. Terminate EC2 vault instances
4. Delete EC2-related infrastructure
5. Update documentation

---

## 10. Enclave Update & Key Migration

### 10.1 The Challenge

When enclave code is updated, PCRs change. Sealed DEKs bound to old PCRs cannot be unsealed by new code.

```
Old Enclave (PCR: abc123)     New Enclave (PCR: def456)
├─ Can unseal old keys        ├─ CANNOT unseal old keys
└─ Running                    └─ Running

Problem: How to transition without losing access to user data?
```

### 10.2 Solution: Key Migration During Rolling Update

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Key Migration Process                                 │
│                                                                         │
│  Step 1: Deploy new enclave alongside old                               │
│  ─────────────────────────────────────────                              │
│                                                                         │
│      Old Enclave Fleet          New Enclave Fleet                       │
│      ┌───────────────┐          ┌───────────────┐                      │
│      │ PCR: abc123   │          │ PCR: def456   │                      │
│      │ Serving users │          │ Idle          │                      │
│      └───────────────┘          └───────────────┘                      │
│                                                                         │
│  Step 2: Migrate keys (in old enclave)                                  │
│  ─────────────────────────────────────                                  │
│                                                                         │
│      For each user vault:                                               │
│        a. Unseal DEK with old PCRs                                     │
│        b. Re-seal DEK with new PCRs                                    │
│           (Nitro KMS allows sealing for different PCRs)                │
│        c. Store new sealed DEK in S3 (keep old as backup)              │
│                                                                         │
│      S3:                                                                │
│      └── user-ABC123/                                                   │
│          ├── sealed_dek.bin         (old PCRs)                         │
│          └── sealed_dek.v2.bin      (new PCRs) ← NEW                   │
│                                                                         │
│  Step 3: Switch traffic to new enclave                                  │
│  ─────────────────────────────────────                                  │
│                                                                         │
│      Old Enclave Fleet          New Enclave Fleet                       │
│      ┌───────────────┐          ┌───────────────┐                      │
│      │ Draining      │   ───►   │ Serving users │                      │
│      └───────────────┘          └───────────────┘                      │
│                                                                         │
│  Step 4: Terminate old enclave, cleanup                                 │
│  ───────────────────────────────────────                                │
│                                                                         │
│      S3:                                                                │
│      └── user-ABC123/                                                   │
│          └── sealed_dek.bin      (new PCRs, renamed)                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 10.3 Key Migration Implementation

```go
// Run in OLD enclave during migration
func migrateKeysToNewPCRs(newPCRs PCRValues) error {
    // Get list of all users
    users, err := listAllUsers()
    if err != nil {
        return err
    }

    for _, userID := range users {
        // Load current sealed DEK
        sealedDEK, err := loadSealedDEK(userID)
        if err != nil {
            log.Error().Err(err).Str("user", userID).Msg("Failed to load sealed DEK")
            continue
        }

        // Unseal with current (old) attestation
        vaultDEK, err := nitro.Unseal(sealedDEK)
        if err != nil {
            log.Error().Err(err).Str("user", userID).Msg("Failed to unseal DEK")
            continue
        }

        // Re-seal for new PCRs
        newSealedDEK, err := nitro.SealForPCRs(vaultDEK, newPCRs)
        if err != nil {
            log.Error().Err(err).Str("user", userID).Msg("Failed to re-seal DEK")
            continue
        }

        // Store new sealed DEK (alongside old)
        err = storeSealedDEK(userID, "sealed_dek.v2.bin", newSealedDEK)
        if err != nil {
            log.Error().Err(err).Str("user", userID).Msg("Failed to store new sealed DEK")
            continue
        }

        // Zero out plaintext DEK from memory
        zeroize(vaultDEK)

        log.Info().Str("user", userID).Msg("Key migrated successfully")
    }

    return nil
}
```

### 10.4 Rollback Strategy

If issues are discovered after switching to new enclave:

```
Rollback Steps:
───────────────

1. Route traffic back to old enclave fleet
   (old enclave can still unseal old keys)

2. Investigate and fix issue in new enclave code

3. Build new enclave image with fix (PCR: ghi789)

4. Re-run key migration from old enclave
   (migrate from abc123 → ghi789)

5. Attempt switch again

Key insight: Keep old enclave running until new enclave is verified stable
```

### 10.5 Emergency Recovery

If both old and new enclaves are unavailable:

```
Emergency Recovery (requires user action):
─────────────────────────────────────────

1. User provides master secret via app

2. New enclave derives vault DEK from master secret
   (same derivation function as original bootstrap)

3. New enclave seals DEK with current PCRs

4. Vault data in S3 is still accessible
   (encrypted with vault DEK, which was just re-derived)

Note: This works because vault DEK is deterministically derived
from master secret + salt. The salt is stored unencrypted in S3.
```

---

## 11. Cost Analysis

### 11.1 Current Costs (EC2 Model)

| Component | Unit Cost | Quantity | Monthly Cost |
|-----------|-----------|----------|--------------|
| t4g.micro (vault) | $6.05/mo | 100 | $605 |
| EBS (10GB per vault) | $0.80/mo | 100 | $80 |
| Data transfer | ~$0.50/vault | 100 | $50 |
| **Total (100 users)** | | | **$735/mo** |
| **Per-vault cost** | | | **$7.35** |

### 11.2 Projected Costs (Enclave Model)

| Component | Unit Cost | Quantity | Monthly Cost |
|-----------|-----------|----------|--------------|
| c6a.2xlarge (enclave host) | $248/mo | 3 (multi-AZ) | $744 |
| S3 storage (1GB/vault) | $0.023/GB | 100 | $2.30 |
| S3 requests | ~$0.05/vault | 100 | $5 |
| Data transfer | ~$0.20/vault | 100 | $20 |
| **Total (100 users)** | | | **$771/mo** |
| **Per-vault cost** | | | **$7.71** |

**At 100 users**: Roughly equivalent cost (enclave has base cost overhead)

### 11.3 Cost at Scale

| Users | EC2 Model | Enclave Model | Savings |
|-------|-----------|---------------|---------|
| 100 | $735/mo | $771/mo | -5% |
| 200 | $1,470/mo | $790/mo | **46%** |
| 500 | $3,675/mo | $850/mo | **77%** |
| 1,000 | $7,350/mo | $1,500/mo | **80%** |
| 5,000 | $36,750/mo | $4,500/mo | **88%** |

### 11.4 Break-Even Analysis

```
Fixed costs (enclave): $744/mo (3 instances for HA)
Variable costs (enclave): ~$1.50/user

Fixed costs (EC2): $0
Variable costs (EC2): ~$7.35/user

Break-even point:
  744 + 1.50x = 7.35x
  744 = 5.85x
  x = 127 users

At 127+ users, enclave model is more cost-effective.
```

### 11.5 TCO Considerations

Beyond raw compute costs:

| Factor | EC2 Model | Enclave Model |
|--------|-----------|---------------|
| Operational complexity | High (manage 100s of instances) | Low (manage ~3-10 instances) |
| Provisioning time | 30-60s | 300-500ms |
| Security guarantees | Trust-based | Attestation-based |
| Scaling events | Slow (launch EC2) | Fast (load vault) |
| Backup/DR | Per-instance EBS snapshots | Centralized S3 |

---

## 12. BYO Vault Considerations

### 12.1 BYO Options

Users who want to run their own vault infrastructure have three options:

| Option | Description | Complexity | Security |
|--------|-------------|------------|----------|
| **Self-hosted EC2** | Current model, user's AWS account | Low | Trust user's infra |
| **Self-hosted Enclave** | Nitro enclave in user's AWS account | Medium | Attestation |
| **On-premises** | User's own hardware/datacenter | High | Trust user's infra |

### 12.2 Self-Hosted Enclave

Users can run their own enclave with the same code:

```bash
# User downloads official enclave image
aws s3 cp s3://vettid-public/enclave/vault-enclave-v1.0.0.eif ./

# User verifies image hash matches published PCRs
sha384sum vault-enclave-v1.0.0.eif
# Compare with published PCR0

# User runs enclave on their own EC2
nitro-cli run-enclave \
  --eif-path vault-enclave-v1.0.0.eif \
  --memory 8000 \
  --cpu-count 4

# User configures their app to connect to their enclave
# App verifies attestation against same published PCRs
```

Benefits:
- Complete data sovereignty
- Same security guarantees (attestation)
- Compatible with VettID ecosystem

### 12.3 Configuration for BYO

```typescript
// User's app configuration
interface VaultConfig {
  type: 'vettid-hosted' | 'self-hosted-enclave' | 'self-hosted-ec2';

  // For self-hosted
  endpoint?: string;

  // For enclave (self-hosted or VettID)
  expectedPCRs?: {
    pcr0: string;
    pcr1: string;
    pcr2: string;
  };
}
```

---

## 13. Implementation Phases

### 13.1 Phase Overview

| Phase | Duration | Focus | Deliverables |
|-------|----------|-------|--------------|
| 1 | 3-4 weeks | Core enclave | Working enclave vault-manager |
| 2 | 2-3 weeks | Integration | Parent process, S3, NATS |
| 3 | 2-3 weeks | Mobile apps | Attestation verification |
| 4 | 2-3 weeks | Operations | Deployment, monitoring, scaling |
| 5 | 3-4 weeks | Migration | User migration tooling |

### 13.2 Phase 1: Core Enclave

**Objective**: Port vault-manager to run inside Nitro Enclave

Tasks:
- [ ] Set up enclave development environment
- [ ] Create minimal enclave image with vault-manager
- [ ] Implement vsock communication layer
- [ ] Implement sealed storage for vault DEK
- [ ] Implement encrypted storage adapter
- [ ] Port embedded NATS to use custom storage backend
- [ ] Unit tests for all enclave components
- [ ] Generate and document PCRs

### 13.3 Phase 2: Integration

**Objective**: Connect enclave to external systems

Tasks:
- [ ] Implement parent process (vsock ↔ NATS ↔ S3)
- [ ] Set up S3 bucket structure
- [ ] Integrate with central NATS cluster
- [ ] Implement supervisor process
- [ ] Implement vault lifecycle management
- [ ] Integration tests with mock external services
- [ ] End-to-end tests with real infrastructure

### 13.4 Phase 3: Mobile Apps

**Objective**: Update iOS and Android apps to support attestation

Tasks:
- [ ] Implement attestation document parsing
- [ ] Implement PCR verification
- [ ] Update bootstrap flow for attestation
- [ ] Store expected PCRs in app configuration
- [ ] Support for PCR updates via app update
- [ ] Fallback handling for attestation failures
- [ ] QA testing on both platforms

### 13.5 Phase 4: Operations

**Objective**: Production-ready deployment and monitoring

Tasks:
- [ ] CDK stack for enclave infrastructure
- [ ] Auto-scaling configuration
- [ ] CloudWatch metrics and dashboards
- [ ] Alerting for enclave health
- [ ] Runbook for common operations
- [ ] Disaster recovery procedures
- [ ] Load testing and performance validation
- [ ] Security review

### 13.6 Phase 5: Migration

**Objective**: Migrate existing users from EC2 to enclave

Tasks:
- [ ] Migration flag infrastructure
- [ ] Mobile app migration flow
- [ ] Data migration tooling
- [ ] Rollback procedures
- [ ] Wave migration execution
- [ ] Monitoring during migration
- [ ] Post-migration validation
- [ ] EC2 decommission automation

---

## 14. Risks & Mitigations

### 14.1 Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Enclave memory insufficient | High | Low | Test with realistic vault counts; implement eviction |
| Cold start latency unacceptable | Medium | Low | Optimize loading; pre-warm predicted vaults |
| NATS JetStream incompatible with custom storage | High | Medium | Prototype early; have fallback storage design |
| Attestation verification complex on mobile | Medium | Medium | Use existing libraries; thorough testing |
| vsock throughput bottleneck | Medium | Low | Load test; optimize batching |

### 14.2 Operational Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Enclave update causes key inaccessibility | Critical | Low | Key migration process; keep old enclave running during transition |
| Multi-AZ failure | High | Very Low | Regional failover; S3 cross-region replication |
| S3 outage | High | Very Low | Local caching; graceful degradation |
| Migration causes data loss | Critical | Low | User-driven migration; keep EC2 until verified |

### 14.3 Security Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Attestation bypass | Critical | Very Low | Hardware-backed; AWS Nitro security |
| Side-channel attacks in shared enclave | High | Low | Process isolation; constant-time crypto |
| Compromised enclave build | Critical | Very Low | Reproducible builds; third-party audit |
| PCR collision | Critical | Very Low | SHA-384 collision-resistant |

---

## 15. Decision Log

### 15.1 Key Decisions

| # | Decision | Rationale | Date |
|---|----------|-----------|------|
| 1 | Use Nitro Enclaves over alternatives | Hardware attestation; AWS native; well-documented | 2026-01-02 |
| 2 | Per-user vault-manager process | Preserves current architecture; simpler migration | 2026-01-02 |
| 3 | Per-user embedded NATS + JetStream | Maintains data isolation; proven storage | 2026-01-02 |
| 4 | Shared WASM handler cache | Memory efficiency; consistent handler versions | 2026-01-02 |
| 5 | S3 for encrypted blob storage | Durability; cross-AZ replication; cost-effective | 2026-01-02 |
| 6 | User-driven data migration | User controls their data; no VettID access to plaintext | 2026-01-02 |

### 15.2 Open Questions

| # | Question | Status | Owner |
|---|----------|--------|-------|
| 1 | What is actual memory footprint per vault? | Needs profiling | TBD |
| 2 | Can NATS JetStream use custom storage backend? | Needs PoC | TBD |
| 3 | What is attestation verification latency on mobile? | Needs testing | TBD |
| 4 | How to handle vault during enclave restart? | Needs design | TBD |
| 5 | Cross-region DR strategy? | Needs design | TBD |

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **Attestation** | Cryptographic proof of code identity and enclave integrity |
| **DEK** | Data Encryption Key - symmetric key used to encrypt vault data |
| **Enclave** | Isolated compute environment with hardware-protected memory |
| **JetStream** | NATS persistence layer for message storage |
| **Nitro** | AWS hardware security platform for EC2 |
| **PCR** | Platform Configuration Register - hash of enclave components |
| **Sealed storage** | Encryption bound to specific enclave code identity |
| **vsock** | Virtual socket for enclave ↔ parent communication |
| **WASM** | WebAssembly - portable bytecode for event handlers |

---

## Appendix B: References

1. AWS Nitro Enclaves Documentation: https://docs.aws.amazon.com/enclaves/
2. NATS JetStream: https://docs.nats.io/nats-concepts/jetstream
3. Wazero (Go WASM runtime): https://wazero.io/
4. ChaCha20-Poly1305: RFC 8439
5. X25519 Key Exchange: RFC 7748

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-02 | Architecture Team | Initial draft |
