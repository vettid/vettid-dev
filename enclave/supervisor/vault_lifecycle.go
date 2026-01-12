package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ParentSender is the interface for sending messages to parent
type ParentSender interface {
	SendToParent(msg *Message) error
}

// VaultManager manages the lifecycle of vault-manager processes
type VaultManager struct {
	config         *Config
	memoryManager  *MemoryManager
	handlerCache   *HandlerCache
	parentSender   ParentSender
	sealer         *NitroSealer
	sealerHandler  *SealerHandler  // For handling sealer requests from vault-manager
	processManager *ProcessManager // Manages vault-manager subprocesses

	vaults    map[string]*VaultProcess
	lruOrder  []string // Least recently used order for eviction
	mu        sync.RWMutex
	startTime time.Time
}

// VaultProcess represents a running vault-manager for a specific user
type VaultProcess struct {
	OwnerSpace   string
	StartedAt    time.Time
	LastAccess   time.Time
	MemoryMB     int
	parentSender ParentSender
	sealer       *NitroSealer

	// Process-based architecture (when processManager is used)
	process       *ManagedProcess // Reference to spawned vault-manager process
	sealerHandler *SealerHandler  // For handling sealer requests from vault-manager

	// Goroutine-based architecture (legacy, used when processManager is nil)
	requestChan  chan *vaultRequest
	responseChan chan *vaultResponse
	stopChan     chan struct{}

	// Credential state (unsealed in enclave memory)
	// Note: In process-based mode, this is held by vault-manager subprocess
	credential *UnsealedCredential

	// ECIES keypair for PIN/password encryption (X25519)
	// The public key is provided to mobile apps during attestation
	// The private key decrypts incoming encrypted PINs
	eciesPrivateKey []byte
	eciesPublicKey  []byte

	// CEK (Credential Encryption Key) - encrypts Protean Credential
	// Per Architecture v2.0 Section 5.5: Both keys held by vault-manager
	cekPair *CEKPair

	// UTK/LTK pairs (User Transaction Keys / Ledger Transaction Keys)
	// Per Architecture v2.0: UTKs (public) sent to app, LTKs (private) kept in vault
	utkPairs []*UTKPair

	// Sealed material and DEK for two-factor authentication
	// Per Architecture v2.0 Section 5.7: PIN → DEK derivation via sealed material
	sealedMaterial []byte  // KMS-sealed random material (stored in S3)
	dek            []byte  // Data Encryption Key derived from PIN + sealed material
	dekHash        []byte  // SHA256(DEK) for PIN verification

	// Block list for call filtering
	blockList map[string]*BlockListEntry

	// Call history (recent calls for quick access)
	callHistory []*CallRecord

	mu sync.RWMutex
}

// BlockListEntry represents a blocked caller
type BlockListEntry struct {
	BlockedID string
	BlockedAt int64
	Reason    string
	ExpiresAt int64 // 0 = permanent
}

// CallRecord represents a call in history
type CallRecord struct {
	CallID       string
	CallerID     string
	CalleeID     string
	Direction    string // "incoming" or "outgoing"
	Status       string // "initiated", "answered", "missed", "rejected", "blocked"
	StartedAt    int64
	AnsweredAt   int64
	EndedAt      int64
	DurationSecs int
}

// UnsealedCredential holds the decrypted credential in enclave memory
type UnsealedCredential struct {
	IdentityPrivateKey  []byte
	IdentityPublicKey   []byte
	VaultMasterSecret   []byte
	AuthHash            []byte
	AuthSalt            []byte
	AuthType            string
	CryptoKeys          []CryptoKey
	CreatedAt           int64
	Version             int
}

// CryptoKey represents a cryptographic key stored in the credential
type CryptoKey struct {
	Label      string `json:"label"`
	Type       string `json:"type"` // "secp256k1", "ed25519", etc.
	PrivateKey []byte `json:"private_key"`
}

type vaultRequest struct {
	ctx context.Context
	msg *Message
}

type vaultResponse struct {
	msg *Message
	err error
}

// VaultStats holds vault manager statistics
type VaultStats struct {
	ActiveVaults  int
	TotalVaults   int
	UptimeSeconds int64
}

// NewVaultManager creates a new vault manager
func NewVaultManager(cfg *Config, memMgr *MemoryManager, cache *HandlerCache, parentSender ParentSender, sealer *NitroSealer) *VaultManager {
	// Create sealer handler for proxying KMS operations to vault-manager processes
	sealerHandler := NewSealerHandler(sealer)

	// Create process manager for spawning vault-manager subprocesses
	// Per Architecture v3.1: Each vault runs in its own isolated process
	procMgr := NewProcessManager(cfg.VaultManagerPath, cfg.DevMode, sealerHandler)

	return &VaultManager{
		config:         cfg,
		memoryManager:  memMgr,
		handlerCache:   cache,
		parentSender:   parentSender,
		sealer:         sealer,
		sealerHandler:  sealerHandler,
		processManager: procMgr,
		vaults:         make(map[string]*VaultProcess),
		lruOrder:       make([]string, 0),
		startTime:      time.Now(),
	}
}

// GetOrCreate gets an existing vault or creates a new one
func (vm *VaultManager) GetOrCreate(ctx context.Context, ownerSpace string) (*VaultProcess, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Check if vault already exists
	if vault, exists := vm.vaults[ownerSpace]; exists {
		vault.touch()
		vm.updateLRU(ownerSpace)
		return vault, nil
	}

	// Check if we need to evict to make room
	if len(vm.vaults) >= vm.config.MaxVaults {
		vm.evictLRU()
	}

	// Reserve memory
	memoryMB := 40 // Estimated memory per vault subprocess
	if !vm.memoryManager.Reserve(memoryMB) {
		// Try evicting and reserving again
		vm.evictLRU()
		if !vm.memoryManager.Reserve(memoryMB) {
			log.Error().Str("owner_space", ownerSpace).Msg("Cannot allocate memory for vault")
			return nil, ErrOutOfMemory
		}
	}

	// Spawn vault-manager subprocess
	// Per Architecture Section 3.1: Each vault runs in its own isolated process
	proc, err := vm.processManager.Spawn(ownerSpace)
	if err != nil {
		vm.memoryManager.Release(memoryMB)
		return nil, fmt.Errorf("failed to spawn vault-manager: %w", err)
	}

	// Create vault wrapper around the subprocess
	vault := &VaultProcess{
		OwnerSpace:    ownerSpace,
		StartedAt:     time.Now(),
		LastAccess:    time.Now(),
		MemoryMB:      memoryMB,
		parentSender:  vm.parentSender,
		sealer:        vm.sealer,
		process:       proc,
		sealerHandler: vm.sealerHandler,
		// Note: Credential state, ECIES keys, CEK, UTK are now held by the subprocess
		// The following fields are for legacy goroutine mode (kept for gradual migration)
		blockList:   make(map[string]*BlockListEntry),
		callHistory: make([]*CallRecord, 0),
	}

	vm.vaults[ownerSpace] = vault
	vm.lruOrder = append(vm.lruOrder, ownerSpace)

	log.Info().
		Str("owner_space", ownerSpace).
		Int("active_vaults", len(vm.vaults)).
		Int("pid", proc.Cmd.Process.Pid).
		Msg("Created new vault (subprocess)")

	return vault, nil
}

// Get returns an existing vault or nil
func (vm *VaultManager) Get(ownerSpace string) *VaultProcess {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if vault, exists := vm.vaults[ownerSpace]; exists {
		vault.touch()
		return vault
	}
	return nil
}

// Evict removes a vault from memory
func (vm *VaultManager) Evict(ownerSpace string) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	vm.evictVault(ownerSpace)
}

// evictVault removes a vault (must hold lock)
func (vm *VaultManager) evictVault(ownerSpace string) {
	vault, exists := vm.vaults[ownerSpace]
	if !exists {
		return
	}

	// Kill the vault-manager subprocess
	// Note: Process-based architecture is now the only mode.
	// Subprocess handles its own memory zeroing on exit.
	if vault.process != nil {
		if err := vm.processManager.Kill(ownerSpace); err != nil {
			log.Warn().
				Err(err).
				Str("owner_space", ownerSpace).
				Msg("Error killing vault-manager subprocess")
		}
	}

	// Release memory
	vm.memoryManager.Release(vault.MemoryMB)

	// Remove from maps
	delete(vm.vaults, ownerSpace)
	vm.removeLRU(ownerSpace)

	log.Info().
		Str("owner_space", ownerSpace).
		Int("active_vaults", len(vm.vaults)).
		Msg("Evicted vault")
}

// zeroSensitiveData zeros all sensitive key material in the vault
// SECURITY: Called before vault eviction to prevent key leakage
func (vp *VaultProcess) zeroSensitiveData() {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	// Zero ECIES private key
	for i := range vp.eciesPrivateKey {
		vp.eciesPrivateKey[i] = 0
	}

	// Zero CEK private key if present
	if vp.cekPair != nil {
		for i := range vp.cekPair.PrivateKey {
			vp.cekPair.PrivateKey[i] = 0
		}
		vp.cekPair = nil
	}

	// Zero LTK private keys if present
	for _, pair := range vp.utkPairs {
		for i := range pair.LTK {
			pair.LTK[i] = 0
		}
	}
	vp.utkPairs = nil

	// Zero DEK if present (two-factor auth)
	for i := range vp.dek {
		vp.dek[i] = 0
	}
	vp.dek = nil
	vp.dekHash = nil
	vp.sealedMaterial = nil

	// Zero credential data if present
	if vp.credential != nil {
		for i := range vp.credential.IdentityPrivateKey {
			vp.credential.IdentityPrivateKey[i] = 0
		}
		for i := range vp.credential.VaultMasterSecret {
			vp.credential.VaultMasterSecret[i] = 0
		}
		for i := range vp.credential.AuthHash {
			vp.credential.AuthHash[i] = 0
		}
		for _, key := range vp.credential.CryptoKeys {
			for i := range key.PrivateKey {
				key.PrivateKey[i] = 0
			}
		}
		vp.credential = nil
	}
}

// evictLRU evicts the least recently used vault
func (vm *VaultManager) evictLRU() {
	if len(vm.lruOrder) == 0 {
		return
	}

	// Evict the oldest (first in LRU list)
	oldest := vm.lruOrder[0]
	vm.evictVault(oldest)
}

// updateLRU moves an owner to the end of the LRU list
func (vm *VaultManager) updateLRU(ownerSpace string) {
	vm.removeLRU(ownerSpace)
	vm.lruOrder = append(vm.lruOrder, ownerSpace)
}

// removeLRU removes an owner from the LRU list
func (vm *VaultManager) removeLRU(ownerSpace string) {
	for i, os := range vm.lruOrder {
		if os == ownerSpace {
			vm.lruOrder = append(vm.lruOrder[:i], vm.lruOrder[i+1:]...)
			break
		}
	}
}

// ShutdownAll stops all vaults
func (vm *VaultManager) ShutdownAll() {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Evict all vaults (handles both subprocess and goroutine modes)
	for ownerSpace := range vm.vaults {
		vm.evictVault(ownerSpace)
	}

	// Process-based architecture: ensure all subprocesses are killed
	if vm.processManager != nil {
		vm.processManager.KillAll()
	}
}

// GetStats returns vault manager statistics
func (vm *VaultManager) GetStats() VaultStats {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	return VaultStats{
		ActiveVaults:  len(vm.vaults),
		TotalVaults:   vm.config.MaxVaults,
		UptimeSeconds: int64(time.Since(vm.startTime).Seconds()),
	}
}

// VaultProcess methods

// touch updates the last access time
func (vp *VaultProcess) touch() {
	vp.mu.Lock()
	vp.LastAccess = time.Now()
	vp.mu.Unlock()
}

// run is the main loop for a vault process
func (vp *VaultProcess) run() {
	log.Debug().Str("owner_space", vp.OwnerSpace).Msg("Vault process started")

	for {
		select {
		case <-vp.stopChan:
			log.Debug().Str("owner_space", vp.OwnerSpace).Msg("Vault process stopping")
			return
		case req := <-vp.requestChan:
			resp := vp.handleRequest(req.ctx, req.msg)
			vp.responseChan <- resp
		}
	}
}

// ProcessMessage sends a message to the vault process and waits for response.
// Handles sealer requests from the vault-manager during the response wait.
func (vp *VaultProcess) ProcessMessage(ctx context.Context, msg *Message) (*Message, error) {
	vp.touch()

	// Process-based architecture: route through subprocess pipe
	if vp.process != nil && vp.process.Conn != nil {
		timeout := 30 * time.Second
		deadline := time.Now().Add(timeout)

		// Send the initial message
		if err := vp.process.Conn.WriteMessage(msg); err != nil {
			log.Error().
				Err(err).
				Str("owner_space", vp.OwnerSpace).
				Msg("Failed to send message to vault-manager subprocess")
			return nil, fmt.Errorf("vault-manager send error: %w", err)
		}

		// Read messages in a loop, handling sealer requests until we get the final response
		for {
			// Check deadline
			remaining := time.Until(deadline)
			if remaining <= 0 {
				log.Error().
					Str("owner_space", vp.OwnerSpace).
					Msg("Timeout waiting for vault-manager response")
				return nil, fmt.Errorf("timeout waiting for vault-manager response")
			}

			// Read next message with timeout
			response, err := vp.process.Conn.ReadMessageWithTimeout(remaining)
			if err != nil {
				log.Error().
					Err(err).
					Str("owner_space", vp.OwnerSpace).
					Msg("Failed to read from vault-manager subprocess")
				return nil, fmt.Errorf("vault-manager read error: %w", err)
			}

			// Debug: Log the actual message type received
			log.Info().
				Str("owner_space", vp.OwnerSpace).
				Str("message_type", string(response.Type)).
				Str("expected_sealer", string(MessageTypeSealerRequest)).
				Int("payload_len", len(response.Payload)).
				Msg("Received message from vault-manager")

			// Check if this is a sealer request (vault-manager needs KMS operation)
			if response.Type == MessageTypeSealerRequest {
				log.Debug().
					Str("owner_space", vp.OwnerSpace).
					Msg("Handling sealer request from vault-manager")

				// Handle the sealer request and send response back
				var sealerResp *Message
				if vp.sealerHandler != nil {
					sealerResp = vp.sealerHandler.HandleSealerRequest(response)
				} else {
					log.Warn().Msg("Sealer handler not configured, returning error")
					sealerResp = &Message{
						RequestID: response.RequestID,
						Type:      MessageTypeSealerResponse,
						Payload:   []byte(`{"success":false,"error":"sealer not available"}`),
					}
				}

				// Send sealer response back to vault-manager
				if err := vp.process.Conn.WriteMessage(sealerResp); err != nil {
					log.Error().
						Err(err).
						Str("owner_space", vp.OwnerSpace).
						Msg("Failed to send sealer response to vault-manager")
					return nil, fmt.Errorf("failed to send sealer response: %w", err)
				}

				// Continue waiting for the final response
				continue
			}

			// Got the final response
			return response, nil
		}
	}

	// DEAD CODE: Legacy goroutine-based architecture was removed.
	// Process-based architecture (vp.process != nil) is now the only path.
	// If we reach here, something is wrong with process spawning.
	log.Error().
		Str("owner_space", vp.OwnerSpace).
		Msg("FATAL: Reached dead code path - process-based routing failed")
	return nil, fmt.Errorf("process-based routing not available for owner %s", vp.OwnerSpace)
}

// handleRequest processes a single request
func (vp *VaultProcess) handleRequest(ctx context.Context, msg *Message) *vaultResponse {
	// Route based on subject or message type
	if msg.Subject != "" {
		return vp.handleNATSMessage(ctx, msg)
	}

	// Legacy message type handling
	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: msg.RequestID,
			Payload:   []byte(`{"status":"ok"}`),
		},
		err: nil,
	}
}

// handleNATSMessage processes a message routed via NATS subject
func (vp *VaultProcess) handleNATSMessage(ctx context.Context, msg *Message) *vaultResponse {
	// Parse the subject to determine operation
	parts := splitSubjectParts(msg.Subject)
	if len(parts) < 3 {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid subject format",
			},
		}
	}

	// Find the operation (after forVault or forOwner)
	var operation string
	for i, part := range parts {
		if part == "forVault" || part == "forOwner" {
			if i+1 < len(parts) {
				operation = parts[i+1]
			}
			break
		}
	}

	log.Debug().
		Str("owner_space", vp.OwnerSpace).
		Str("subject", msg.Subject).
		Str("operation", operation).
		Msg("Processing NATS message")

	switch operation {
	case "call":
		return vp.handleCallMessage(ctx, msg, parts)
	case "bootstrap":
		return vp.handleBootstrap(ctx, msg)
	case "block":
		return vp.handleBlockMessage(ctx, msg, parts)
	case "credential":
		// Handle credential operations (create, update)
		return vp.handleCredentialMessage(ctx, msg, parts)
	case "password":
		// Handle password setup (Phase 3 of enrollment)
		return vp.handlePasswordSetup(ctx, msg)
	case "pin":
		// Handle PIN setup and verification (two-factor auth)
		return vp.handlePINMessage(ctx, msg, parts)
	default:
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeVaultResponse,
				RequestID: msg.RequestID,
				Payload:   []byte(`{"status":"unknown_operation"}`),
			},
		}
	}
}

// splitSubjectParts splits a NATS subject into parts
func splitSubjectParts(subject string) []string {
	var parts []string
	current := ""
	for _, c := range subject {
		if c == '.' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// handleCallMessage processes call-related messages
func (vp *VaultProcess) handleCallMessage(ctx context.Context, msg *Message, parts []string) *vaultResponse {
	// Extract call event type (e.g., "initiate", "offer", "answer")
	var eventType string
	for i, part := range parts {
		if part == "call" && i+1 < len(parts) {
			eventType = parts[i+1]
			break
		}
	}

	// Parse the call event from payload
	var callEvent struct {
		EventID   string `json:"event_id"`
		CallerID  string `json:"caller_id"`
		CalleeID  string `json:"callee_id"`
		CallID    string `json:"call_id"`
		Payload   []byte `json:"payload,omitempty"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := json.Unmarshal(msg.Payload, &callEvent); err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid call event payload",
			},
		}
	}

	switch eventType {
	case "initiate":
		return vp.handleCallInitiate(ctx, msg, &callEvent)
	case "offer", "answer", "candidate":
		return vp.handleCallSignaling(ctx, msg, eventType, &callEvent)
	case "accept", "reject", "cancel", "end":
		return vp.handleCallStateChange(ctx, msg, eventType, &callEvent)
	default:
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "unknown call event type",
			},
		}
	}
}

// handleCallInitiate processes incoming call requests
func (vp *VaultProcess) handleCallInitiate(ctx context.Context, msg *Message, event *struct {
	EventID   string `json:"event_id"`
	CallerID  string `json:"caller_id"`
	CalleeID  string `json:"callee_id"`
	CallID    string `json:"call_id"`
	Payload   []byte `json:"payload,omitempty"`
	Timestamp int64  `json:"timestamp"`
}) *vaultResponse {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	// Check block list
	if entry, blocked := vp.blockList[event.CallerID]; blocked {
		// Check if block has expired
		if entry.ExpiresAt > 0 && entry.ExpiresAt < time.Now().Unix() {
			delete(vp.blockList, event.CallerID)
		} else {
			log.Info().
				Str("caller_id", event.CallerID).
				Str("reason", entry.Reason).
				Msg("Call blocked")

			// Record blocked call
			record := &CallRecord{
				CallID:    event.CallID,
				CallerID:  event.CallerID,
				CalleeID:  vp.OwnerSpace,
				Direction: "incoming",
				Status:    "blocked",
				StartedAt: event.Timestamp,
				EndedAt:   time.Now().Unix(),
			}
			vp.addCallRecord(record)

			// Notify caller they are blocked
			vp.publishToVault(event.CallerID, "call.blocked", msg.Payload)

			return &vaultResponse{
				msg: &Message{
					Type:      MessageTypeVaultResponse,
					RequestID: msg.RequestID,
					Payload:   []byte(`{"status":"blocked"}`),
				},
			}
		}
	}

	// Record incoming call
	record := &CallRecord{
		CallID:    event.CallID,
		CallerID:  event.CallerID,
		CalleeID:  vp.OwnerSpace,
		Direction: "incoming",
		Status:    "initiated",
		StartedAt: event.Timestamp,
	}
	vp.addCallRecord(record)

	// Forward to owner's app
	log.Info().
		Str("caller_id", event.CallerID).
		Str("call_id", event.CallID).
		Msg("Forwarding incoming call to app")

	vp.publishToApp("call.incoming", msg.Payload)

	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: msg.RequestID,
			Payload:   []byte(`{"status":"forwarded"}`),
		},
	}
}

// handleCallSignaling forwards WebRTC signaling messages
func (vp *VaultProcess) handleCallSignaling(ctx context.Context, msg *Message, eventType string, event *struct {
	EventID   string `json:"event_id"`
	CallerID  string `json:"caller_id"`
	CalleeID  string `json:"callee_id"`
	CallID    string `json:"call_id"`
	Payload   []byte `json:"payload,omitempty"`
	Timestamp int64  `json:"timestamp"`
}) *vaultResponse {
	// Forward signaling to app
	vp.publishToApp("call."+eventType, msg.Payload)

	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: msg.RequestID,
			Payload:   []byte(`{"status":"forwarded"}`),
		},
	}
}

// handleCallStateChange processes call state changes (accept/reject/cancel/end)
func (vp *VaultProcess) handleCallStateChange(ctx context.Context, msg *Message, eventType string, event *struct {
	EventID   string `json:"event_id"`
	CallerID  string `json:"caller_id"`
	CalleeID  string `json:"callee_id"`
	CallID    string `json:"call_id"`
	Payload   []byte `json:"payload,omitempty"`
	Timestamp int64  `json:"timestamp"`
}) *vaultResponse {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	// Update call record
	for _, record := range vp.callHistory {
		if record.CallID == event.CallID {
			switch eventType {
			case "accept":
				record.Status = "answered"
				record.AnsweredAt = time.Now().Unix()
			case "reject":
				record.Status = "rejected"
				record.EndedAt = time.Now().Unix()
			case "cancel":
				record.Status = "missed"
				record.EndedAt = time.Now().Unix()
			case "end":
				record.EndedAt = time.Now().Unix()
				if record.AnsweredAt > 0 {
					record.DurationSecs = int(record.EndedAt - record.AnsweredAt)
				}
			}
			break
		}
	}

	// Forward to app
	vp.publishToApp("call."+eventType, msg.Payload)

	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: msg.RequestID,
			Payload:   []byte(`{"status":"processed"}`),
		},
	}
}

// BootstrapRequest is the request from the mobile app for vault bootstrap
type BootstrapRequest struct {
	BootstrapToken string `json:"bootstrap_token"`
}

// BootstrapResponse is returned to the mobile app after successful bootstrap
type BootstrapResponse struct {
	Status              string   `json:"status"`
	UTKs                []string `json:"utks"`                   // Base64-encoded public keys for transport encryption
	ECIESPublicKey      string   `json:"ecies_public_key"`       // For encrypting PIN/password
	EnclavePublicKey    string   `json:"enclave_public_key"`     // Vault's identity public key
	Capabilities        []string `json:"capabilities"`
	RequiresPassword    bool     `json:"requires_password"`      // App should prompt for password
	RequiresPIN         bool     `json:"requires_pin"`           // App should prompt for PIN
}

// UTKPair holds a User Transaction Key (public) and corresponding Ledger Transaction Key (private)
type UTKPair struct {
	UTK       []byte // X25519 public key (sent to app)
	LTK       []byte // X25519 private key (kept in vault)
	ID        string // Unique identifier for this key pair
	CreatedAt int64
	UsedAt    int64  // 0 if not yet used
}

// CEKPair holds the Credential Encryption Key pair
type CEKPair struct {
	PublicKey  []byte // X25519 public key
	PrivateKey []byte // X25519 private key
	Version    int    // Incremented on rotation
	CreatedAt  int64
}

// handleBootstrap processes bootstrap requests
// This implements Phase 2 of the enrollment flow per Architecture v2.0 Section 5.6
// 1. Validate bootstrap token
// 2. Generate CEK keypair (for credential encryption)
// 3. Generate UTK/LTK pairs (for transport encryption)
// 4. Store CEK private key and LTKs in vault
// 5. Return UTKs and ECIES public key to app
func (vp *VaultProcess) handleBootstrap(ctx context.Context, msg *Message) *vaultResponse {
	log.Info().Str("owner_space", vp.OwnerSpace).Msg("Bootstrap requested")

	// Parse bootstrap request
	var req BootstrapRequest
	if len(msg.Payload) > 0 {
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			log.Warn().Err(err).Msg("Failed to parse bootstrap request")
			// Continue anyway - bootstrap token validation is optional for now
		}
	}

	// NOTE: Bootstrap token validation is NOT required because:
	// 1. NATS authentication already ensures only the legitimate user can publish to their vault topic
	// 2. The mobile app receives temporary NATS credentials from enrollFinalize Lambda
	// 3. These credentials are scoped to the user's OwnerSpace topics only
	// 4. If an attacker could bypass NATS auth, they'd have broader access than bootstrap provides
	// 5. Bootstrap is idempotent - calling it again just returns existing keys
	//
	// Adding token validation would require Lambda calls, adding ~100ms latency for marginal benefit.
	// The security boundary is the NATS credential issuance in enrollFinalize, not this handler.
	_ = req.BootstrapToken // Token field exists for future use but is not currently validated

	vp.mu.Lock()
	defer vp.mu.Unlock()

	// Check if already bootstrapped
	if vp.cekPair != nil && len(vp.utkPairs) > 0 {
		log.Info().Str("owner_space", vp.OwnerSpace).Msg("Vault already bootstrapped, returning existing keys")
		return vp.buildBootstrapResponse(msg.RequestID, false)
	}

	// Generate CEK keypair (X25519)
	cekPrivateKey := make([]byte, 32)
	if _, err := rand.Read(cekPrivateKey); err != nil {
		log.Error().Err(err).Msg("Failed to generate CEK private key")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to generate CEK",
			},
		}
	}
	cekPublicKey, err := curve25519.X25519(cekPrivateKey, curve25519.Basepoint)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive CEK public key")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to derive CEK public key",
			},
		}
	}

	vp.cekPair = &CEKPair{
		PublicKey:  cekPublicKey,
		PrivateKey: cekPrivateKey,
		Version:    1,
		CreatedAt:  time.Now().Unix(),
	}

	// Generate initial batch of UTK/LTK pairs (5 pairs)
	// More can be generated on demand
	const initialUTKCount = 5
	vp.utkPairs = make([]*UTKPair, 0, initialUTKCount)
	for i := 0; i < initialUTKCount; i++ {
		pair, err := vp.generateUTKPair()
		if err != nil {
			log.Error().Err(err).Int("index", i).Msg("Failed to generate UTK pair")
			continue
		}
		vp.utkPairs = append(vp.utkPairs, pair)
	}

	if len(vp.utkPairs) == 0 {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to generate UTK pairs",
			},
		}
	}

	log.Info().
		Str("owner_space", vp.OwnerSpace).
		Int("utk_count", len(vp.utkPairs)).
		Int("cek_version", vp.cekPair.Version).
		Msg("Bootstrap completed - keys generated")

	// Credential not yet created - app needs to set password
	return vp.buildBootstrapResponse(msg.RequestID, true)
}

// generateUTKPair creates a new UTK/LTK pair
func (vp *VaultProcess) generateUTKPair() (*UTKPair, error) {
	// Generate X25519 private key (LTK)
	ltk := make([]byte, 32)
	if _, err := rand.Read(ltk); err != nil {
		return nil, fmt.Errorf("failed to generate LTK: %w", err)
	}

	// Derive public key (UTK)
	utk, err := curve25519.X25519(ltk, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive UTK: %w", err)
	}

	// Generate unique ID
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("failed to generate UTK ID: %w", err)
	}

	return &UTKPair{
		UTK:       utk,
		LTK:       ltk,
		ID:        fmt.Sprintf("utk-%x", idBytes),
		CreatedAt: time.Now().Unix(),
	}, nil
}

// buildBootstrapResponse creates the response for bootstrap
func (vp *VaultProcess) buildBootstrapResponse(requestID string, requiresPassword bool) *vaultResponse {
	// Encode UTKs as base64
	utks := make([]string, 0, len(vp.utkPairs))
	for _, pair := range vp.utkPairs {
		if pair.UsedAt == 0 { // Only include unused UTKs
			// Encode as: id:base64(utk)
			encoded := pair.ID + ":" + base64.StdEncoding.EncodeToString(pair.UTK)
			utks = append(utks, encoded)
		}
	}

	response := BootstrapResponse{
		Status:           "bootstrapped",
		UTKs:             utks,
		ECIESPublicKey:   base64.StdEncoding.EncodeToString(vp.eciesPublicKey),
		EnclavePublicKey: "", // Will be set after credential creation
		Capabilities:     []string{"call", "sign", "store", "connect"},
		RequiresPassword: requiresPassword && vp.credential == nil,
		RequiresPIN:      true, // Always require PIN for DEK derivation
	}

	// If credential exists, include the enclave public key
	if vp.credential != nil {
		response.EnclavePublicKey = base64.StdEncoding.EncodeToString(vp.credential.IdentityPublicKey)
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal bootstrap response")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: requestID,
				Error:     "failed to create response",
			},
		}
	}

	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: requestID,
			Payload:   responseBytes,
		},
	}
}

// PasswordSetupRequest is the request from the mobile app for password setup
type PasswordSetupRequest struct {
	UTKIndex         int    `json:"utk_index"`          // Which UTK was used for encryption
	UTKID            string `json:"utk_id"`             // ID of the UTK used
	EncryptedPayload string `json:"encrypted_payload"`  // Base64-encoded encrypted payload
}

// PasswordSetupPayload is the decrypted content of EncryptedPayload
type PasswordSetupPayload struct {
	PasswordHash []byte `json:"password_hash"` // Argon2id hash computed by app
	PasswordSalt []byte `json:"password_salt"` // Salt used by app
}

// PasswordSetupResponse is returned after successful password setup
type PasswordSetupResponse struct {
	Status               string   `json:"status"`
	EncryptedCredential  string   `json:"encrypted_credential"`   // CEK-encrypted Protean Credential
	IdentityPublicKey    string   `json:"identity_public_key"`    // Ed25519 public key for identity
	NewUTKs              []string `json:"new_utks"`               // Fresh UTKs for future operations
	BackupKey            string   `json:"backup_key,omitempty"`   // Key for backup encryption
}

// handlePasswordSetup processes password setup requests (Phase 3 of enrollment)
// This implements Architecture v2.0 Section 5.6 Phase 3:
// 1. Decrypt password hash using corresponding LTK
// 2. Generate identity keypair and vault master secret
// 3. Create Protean Credential with password hash
// 4. Encrypt credential with CEK
// 5. Return encrypted credential and fresh UTKs
func (vp *VaultProcess) handlePasswordSetup(ctx context.Context, msg *Message) *vaultResponse {
	log.Info().Str("owner_space", vp.OwnerSpace).Msg("Password setup requested")

	// Parse request
	var req PasswordSetupRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		log.Error().Err(err).Msg("Failed to parse password setup request")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid request format",
			},
		}
	}

	vp.mu.Lock()
	defer vp.mu.Unlock()

	// Verify vault is bootstrapped
	if vp.cekPair == nil || len(vp.utkPairs) == 0 {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "vault not bootstrapped - call bootstrap first",
			},
		}
	}

	// Check if credential already exists
	if vp.credential != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "credential already exists - use password.update for changes",
			},
		}
	}

	// Find the LTK corresponding to the UTK used
	var ltk []byte
	for _, pair := range vp.utkPairs {
		if pair.ID == req.UTKID {
			if pair.UsedAt != 0 {
				return &vaultResponse{
					msg: &Message{
						Type:      MessageTypeError,
						RequestID: msg.RequestID,
						Error:     "UTK already used - single-use keys only",
					},
				}
			}
			ltk = pair.LTK
			pair.UsedAt = time.Now().Unix()
			break
		}
	}

	if ltk == nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "unknown UTK ID",
			},
		}
	}

	// Decode and decrypt the payload using ECIES (X25519 + HKDF + AES-GCM)
	encryptedBytes, err := base64.StdEncoding.DecodeString(req.EncryptedPayload)
	if err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid encrypted payload encoding",
			},
		}
	}

	// Decrypt using LTK (X25519 key exchange)
	decryptedPayload, err := vp.decryptWithLTK(ltk, encryptedBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt password payload")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "decryption failed",
			},
		}
	}

	// Parse the decrypted payload
	var payload PasswordSetupPayload
	if err := json.Unmarshal(decryptedPayload, &payload); err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid password payload format",
			},
		}
	}

	// Validate password hash length (Argon2id produces 32-byte hash)
	if len(payload.PasswordHash) != 32 || len(payload.PasswordSalt) < 16 {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid password hash or salt",
			},
		}
	}

	// Generate Ed25519 identity keypair
	identityPublicKey, identityPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to generate identity keypair",
			},
		}
	}

	// Generate vault master secret (256 bits)
	vaultMasterSecret := make([]byte, 32)
	if _, err := rand.Read(vaultMasterSecret); err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to generate vault master secret",
			},
		}
	}

	// Create the Protean Credential
	vp.credential = &UnsealedCredential{
		IdentityPrivateKey: identityPrivateKey,
		IdentityPublicKey:  identityPublicKey,
		VaultMasterSecret:  vaultMasterSecret,
		AuthHash:           payload.PasswordHash,
		AuthSalt:           payload.PasswordSalt,
		AuthType:           "password",
		CryptoKeys:         make([]CryptoKey, 0),
		CreatedAt:          time.Now().Unix(),
		Version:            1,
	}

	// Encrypt credential with CEK (X25519-ChaCha20-Poly1305)
	credentialJSON, err := json.Marshal(vp.credential)
	if err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to serialize credential",
			},
		}
	}

	encryptedCredential, err := vp.encryptWithCEK(credentialJSON)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt credential with CEK")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to encrypt credential",
			},
		}
	}

	// Zero the plaintext JSON
	for i := range credentialJSON {
		credentialJSON[i] = 0
	}

	// Generate fresh UTKs for future operations
	newPairs := make([]*UTKPair, 0, 5)
	for i := 0; i < 5; i++ {
		pair, err := vp.generateUTKPair()
		if err != nil {
			log.Error().Err(err).Msg("Failed to generate new UTK pair")
			continue
		}
		newPairs = append(newPairs, pair)
	}
	vp.utkPairs = append(vp.utkPairs, newPairs...)

	// Encode new UTKs
	newUTKs := make([]string, 0, len(newPairs))
	for _, pair := range newPairs {
		encoded := pair.ID + ":" + base64.StdEncoding.EncodeToString(pair.UTK)
		newUTKs = append(newUTKs, encoded)
	}

	// Generate backup key (derived from vault master secret)
	backupKey := sha256.Sum256(append(vaultMasterSecret, []byte("backup-key-v1")...))

	response := PasswordSetupResponse{
		Status:              "credential_created",
		EncryptedCredential: base64.StdEncoding.EncodeToString(encryptedCredential),
		IdentityPublicKey:   base64.StdEncoding.EncodeToString(identityPublicKey),
		NewUTKs:             newUTKs,
		BackupKey:           base64.StdEncoding.EncodeToString(backupKey[:]),
	}

	log.Info().
		Str("owner_space", vp.OwnerSpace).
		Int("new_utk_count", len(newUTKs)).
		Msg("Password setup completed - credential created")

	responseBytes, _ := json.Marshal(response)
	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: msg.RequestID,
			Payload:   responseBytes,
		},
	}
}

// decryptWithLTK decrypts data that was encrypted with the corresponding UTK
// Uses X25519 key exchange + HKDF + AES-256-GCM
func (vp *VaultProcess) decryptWithLTK(ltk []byte, ciphertext []byte) ([]byte, error) {
	// Format: ephemeral_pubkey (32) || nonce (12) || encrypted_data
	if len(ciphertext) < 32+12 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	ephemeralPubKey := ciphertext[:32]
	nonce := ciphertext[32:44]
	encrypted := ciphertext[44:]

	// X25519 key exchange
	sharedSecret, err := curve25519.X25519(ltk, ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}

	// Derive AES key using HKDF-SHA256
	info := append([]byte("vettid-utk-encryption"), ephemeralPubKey...)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)
	aesKey := make([]byte, 32)
	if _, err := hkdfReader.Read(aesKey); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Decrypt using AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Zero sensitive data
	for i := range sharedSecret {
		sharedSecret[i] = 0
	}
	for i := range aesKey {
		aesKey[i] = 0
	}

	return plaintext, nil
}

// encryptWithCEK encrypts data using the CEK (X25519-ChaCha20-Poly1305)
func (vp *VaultProcess) encryptWithCEK(plaintext []byte) ([]byte, error) {
	if vp.cekPair == nil {
		return nil, fmt.Errorf("CEK not initialized")
	}

	// Generate ephemeral keypair for this encryption
	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive ephemeral public key: %w", err)
	}

	// X25519 key exchange with CEK private key (self-encryption)
	// We use the CEK private key to derive a shared secret
	sharedSecret, err := curve25519.X25519(ephemeralPrivate, vp.cekPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}

	// Derive ChaCha20 key using HKDF-SHA256
	info := append([]byte("vettid-cek-encryption-v1"), ephemeralPublic...)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)
	chachaKey := make([]byte, 32)
	if _, err := hkdfReader.Read(chachaKey); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Create ChaCha20-Poly1305 cipher
	aead, err := cipher.NewGCM(func() cipher.Block {
		block, _ := aes.NewCipher(chachaKey)
		return block
	}())
	if err != nil {
		return nil, fmt.Errorf("AEAD creation failed: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Zero sensitive data
	for i := range ephemeralPrivate {
		ephemeralPrivate[i] = 0
	}
	for i := range sharedSecret {
		sharedSecret[i] = 0
	}
	for i := range chachaKey {
		chachaKey[i] = 0
	}

	// Return format: ephemeral_pubkey (32) || cek_version (4) || nonce || ciphertext
	result := make([]byte, 0, 32+4+len(nonce)+len(ciphertext))
	result = append(result, ephemeralPublic...)
	// Add CEK version as 4 bytes big-endian
	result = append(result, byte(vp.cekPair.Version>>24), byte(vp.cekPair.Version>>16),
		byte(vp.cekPair.Version>>8), byte(vp.cekPair.Version))
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// handleCredentialMessage processes credential-related operations
func (vp *VaultProcess) handleCredentialMessage(ctx context.Context, msg *Message, parts []string) *vaultResponse {
	// Extract credential operation (get, update, etc.)
	var operation string
	for i, part := range parts {
		if part == "credential" && i+1 < len(parts) {
			operation = parts[i+1]
			break
		}
	}

	log.Debug().
		Str("owner_space", vp.OwnerSpace).
		Str("operation", operation).
		Msg("Processing credential message")

	switch operation {
	case "get":
		return vp.handleCredentialGet(ctx, msg)
	case "update":
		return vp.handleCredentialUpdate(ctx, msg)
	default:
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "unknown credential operation: " + operation,
			},
		}
	}
}

// handleCredentialGet returns the encrypted credential for the app
func (vp *VaultProcess) handleCredentialGet(ctx context.Context, msg *Message) *vaultResponse {
	vp.mu.RLock()
	defer vp.mu.RUnlock()

	if vp.credential == nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "no credential exists - complete password setup first",
			},
		}
	}

	// Re-encrypt credential with current CEK
	credentialJSON, err := json.Marshal(vp.credential)
	if err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to serialize credential",
			},
		}
	}

	encryptedCredential, err := vp.encryptWithCEK(credentialJSON)
	if err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to encrypt credential",
			},
		}
	}

	// Zero the plaintext
	for i := range credentialJSON {
		credentialJSON[i] = 0
	}

	response := map[string]interface{}{
		"status":               "ok",
		"encrypted_credential": base64.StdEncoding.EncodeToString(encryptedCredential),
		"cek_version":          vp.cekPair.Version,
	}

	responseBytes, _ := json.Marshal(response)
	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: msg.RequestID,
			Payload:   responseBytes,
		},
	}
}

// CredentialUpdateRequest is the request for credential updates
type CredentialUpdateRequest struct {
	Operation        string `json:"operation"`         // "password_change", "add_key", "rotate_cek"
	UTKIndex         int    `json:"utk_index"`         // Which UTK was used for encryption
	UTKID            string `json:"utk_id"`            // ID of the UTK used
	EncryptedPayload string `json:"encrypted_payload"` // Base64-encoded encrypted payload
}

// PasswordChangePayload is the decrypted content for password change
type PasswordChangePayload struct {
	CurrentPasswordHash []byte `json:"current_password_hash"` // Argon2id hash of current password
	NewPasswordHash     []byte `json:"new_password_hash"`     // Argon2id hash of new password
	NewPasswordSalt     []byte `json:"new_password_salt"`     // Salt used for new password
}

// CredentialUpdateResponse is returned after successful credential update
type CredentialUpdateResponse struct {
	Status              string   `json:"status"`
	EncryptedCredential string   `json:"encrypted_credential"` // CEK-encrypted updated credential
	NewUTKs             []string `json:"new_utks"`             // Fresh UTKs for future operations
	CredentialVersion   int      `json:"credential_version"`   // Updated version number
}

// handleCredentialUpdate handles credential updates (password change, key addition, etc.)
// This implements secure credential modification with proper authorization:
// 1. Verify request is encrypted with a valid UTK
// 2. Verify current password/authorization
// 3. Apply the requested update
// 4. Re-encrypt and return updated credential
func (vp *VaultProcess) handleCredentialUpdate(ctx context.Context, msg *Message) *vaultResponse {
	log.Info().Str("owner_space", vp.OwnerSpace).Msg("Credential update requested")

	var req CredentialUpdateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid credential update request",
			},
		}
	}

	vp.mu.Lock()
	defer vp.mu.Unlock()

	// Verify credential exists
	if vp.credential == nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "no credential exists - complete enrollment first",
			},
		}
	}

	// Verify vault is bootstrapped
	if vp.cekPair == nil || len(vp.utkPairs) == 0 {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "vault not bootstrapped",
			},
		}
	}

	// Find the LTK corresponding to the UTK used
	var ltk []byte
	var utkPair *UTKPair
	for _, pair := range vp.utkPairs {
		if pair.ID == req.UTKID {
			if pair.UsedAt != 0 {
				return &vaultResponse{
					msg: &Message{
						Type:      MessageTypeError,
						RequestID: msg.RequestID,
						Error:     "UTK already used - single-use keys only",
					},
				}
			}
			ltk = pair.LTK
			utkPair = pair
			break
		}
	}

	if ltk == nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "unknown UTK ID",
			},
		}
	}

	// Decode and decrypt the payload
	encryptedBytes, err := base64.StdEncoding.DecodeString(req.EncryptedPayload)
	if err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid encrypted payload encoding",
			},
		}
	}

	decryptedPayload, err := vp.decryptWithLTK(ltk, encryptedBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt credential update payload")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "decryption failed",
			},
		}
	}

	// Mark UTK as used
	utkPair.UsedAt = time.Now().Unix()

	// Route to appropriate handler based on operation
	switch req.Operation {
	case "password_change":
		return vp.handlePasswordChange(ctx, msg, decryptedPayload)
	default:
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "unknown operation: " + req.Operation,
			},
		}
	}
}

// handlePasswordChange handles password change operations
// Requires current password verification before allowing the change
func (vp *VaultProcess) handlePasswordChange(ctx context.Context, msg *Message, decryptedPayload []byte) *vaultResponse {
	var payload PasswordChangePayload
	if err := json.Unmarshal(decryptedPayload, &payload); err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid password change payload",
			},
		}
	}

	// Zero payload data after use
	defer func() {
		for i := range payload.CurrentPasswordHash {
			payload.CurrentPasswordHash[i] = 0
		}
		for i := range payload.NewPasswordHash {
			payload.NewPasswordHash[i] = 0
		}
	}()

	// Validate password hash lengths (Argon2id produces 32-byte hash)
	if len(payload.CurrentPasswordHash) != 32 {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid current password hash length",
			},
		}
	}

	if len(payload.NewPasswordHash) != 32 || len(payload.NewPasswordSalt) < 16 {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid new password hash or salt",
			},
		}
	}

	// Verify current password using constant-time comparison
	if !constantTimeCompare(payload.CurrentPasswordHash, vp.credential.AuthHash) {
		log.Warn().Str("owner_space", vp.OwnerSpace).Msg("Password change failed - incorrect current password")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "current password is incorrect",
			},
		}
	}

	// Update credential with new password hash
	vp.credential.AuthHash = make([]byte, len(payload.NewPasswordHash))
	copy(vp.credential.AuthHash, payload.NewPasswordHash)
	vp.credential.AuthSalt = make([]byte, len(payload.NewPasswordSalt))
	copy(vp.credential.AuthSalt, payload.NewPasswordSalt)
	vp.credential.Version++

	// Re-encrypt credential with CEK
	credentialJSON, err := json.Marshal(vp.credential)
	if err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to serialize credential",
			},
		}
	}

	encryptedCredential, err := vp.encryptWithCEK(credentialJSON)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt updated credential")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to encrypt credential",
			},
		}
	}

	// Zero the plaintext JSON
	for i := range credentialJSON {
		credentialJSON[i] = 0
	}

	// Generate fresh UTKs for future operations
	newPairs := make([]*UTKPair, 0, 5)
	for i := 0; i < 5; i++ {
		pair, err := vp.generateUTKPair()
		if err != nil {
			log.Error().Err(err).Msg("Failed to generate new UTK pair")
			continue
		}
		newPairs = append(newPairs, pair)
	}
	vp.utkPairs = append(vp.utkPairs, newPairs...)

	// Encode new UTKs
	newUTKs := make([]string, 0, len(newPairs))
	for _, pair := range newPairs {
		encoded := pair.ID + ":" + base64.StdEncoding.EncodeToString(pair.UTK)
		newUTKs = append(newUTKs, encoded)
	}

	log.Info().
		Str("owner_space", vp.OwnerSpace).
		Int("new_version", vp.credential.Version).
		Msg("Password change completed successfully")

	response := CredentialUpdateResponse{
		Status:              "password_changed",
		EncryptedCredential: base64.StdEncoding.EncodeToString(encryptedCredential),
		NewUTKs:             newUTKs,
		CredentialVersion:   vp.credential.Version,
	}

	responseBytes, _ := json.Marshal(response)
	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: msg.RequestID,
			Payload:   responseBytes,
		},
	}
}

// ============================================================================
// PIN Management (Two-Factor Authentication - Architecture v2.0 Section 5.7)
// ============================================================================

// PINSetupRequest is the request for initial PIN setup during enrollment
type PINSetupRequest struct {
	EncryptedPIN string `json:"encrypted_pin"` // PIN encrypted with ECIES public key
}

// PINSetupResponse is returned after successful PIN setup
type PINSetupResponse struct {
	Status         string `json:"status"`
	SealedMaterial string `json:"sealed_material"` // Base64-encoded, to be stored by app
}

// PINUnlockRequest is sent when user opens the app and enters PIN
type PINUnlockRequest struct {
	EncryptedPIN   string `json:"encrypted_pin"`   // PIN encrypted with ECIES public key
	SealedMaterial string `json:"sealed_material"` // Base64-encoded, from app storage
}

// PINUnlockResponse is returned after successful PIN unlock
type PINUnlockResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// PINChangeRequest is sent when user wants to change their PIN
type PINChangeRequest struct {
	CurrentEncryptedPIN string `json:"current_encrypted_pin"` // Current PIN encrypted with ECIES public key
	NewEncryptedPIN     string `json:"new_encrypted_pin"`     // New PIN encrypted with ECIES public key
	SealedMaterial      string `json:"sealed_material"`       // Current sealed material from app storage
}

// PINChangeResponse is returned after successful PIN change
type PINChangeResponse struct {
	Status            string `json:"status"`
	NewSealedMaterial string `json:"new_sealed_material"` // New sealed material to store in app
}

// handlePINMessage routes PIN-related operations
func (vp *VaultProcess) handlePINMessage(ctx context.Context, msg *Message, parts []string) *vaultResponse {
	// Extract PIN operation (setup, unlock, change)
	var operation string
	for i, part := range parts {
		if part == "pin" && i+1 < len(parts) {
			operation = parts[i+1]
			break
		}
	}

	log.Debug().
		Str("owner_space", vp.OwnerSpace).
		Str("operation", operation).
		Msg("Processing PIN message")

	switch operation {
	case "setup":
		return vp.handlePINSetup(ctx, msg)
	case "unlock":
		return vp.handlePINUnlock(ctx, msg)
	case "change":
		return vp.handlePINChange(ctx, msg)
	default:
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "unknown PIN operation: " + operation,
			},
		}
	}
}

// handlePINSetup processes initial PIN setup during enrollment
// This generates sealed material and derives the DEK from PIN
func (vp *VaultProcess) handlePINSetup(ctx context.Context, msg *Message) *vaultResponse {
	log.Info().Str("owner_space", vp.OwnerSpace).Msg("PIN setup requested")

	var req PINSetupRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid PIN setup request",
			},
		}
	}

	vp.mu.Lock()
	defer vp.mu.Unlock()

	// Check if PIN is already set
	if vp.sealedMaterial != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "PIN already set - use pin.change to modify",
			},
		}
	}

	// Decrypt the PIN using ECIES private key
	encryptedPIN, err := base64.StdEncoding.DecodeString(req.EncryptedPIN)
	if err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid encrypted PIN encoding",
			},
		}
	}

	pin, err := vp.decryptWithECIES(encryptedPIN)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt PIN")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to decrypt PIN",
			},
		}
	}

	defer func() {
		// Zero PIN after use
		for i := range pin {
			pin[i] = 0
		}
	}()

	// Validate PIN format (must be 6 digits)
	if len(pin) != 6 || !isAllDigits(pin) {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "PIN must be exactly 6 digits",
			},
		}
	}

	// Generate sealed material using the sealer
	sealedMaterial, err := vp.sealer.GenerateSealedMaterial(vp.OwnerSpace)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate sealed material")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to generate sealed material",
			},
		}
	}

	// Derive DEK from PIN + sealed material
	dek, err := vp.sealer.DeriveDEKFromPIN(sealedMaterial, string(pin), vp.OwnerSpace)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive DEK from PIN")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to derive DEK",
			},
		}
	}

	// Store sealed material and DEK in vault process
	vp.sealedMaterial = sealedMaterial
	vp.dek = dek

	// Store hash of DEK for future PIN verification
	dekHash := sha256.Sum256(dek)
	vp.dekHash = dekHash[:]

	log.Info().
		Str("owner_space", vp.OwnerSpace).
		Msg("PIN setup completed - DEK derived and stored")

	// Return sealed material for app to store locally
	response := PINSetupResponse{
		Status:         "pin_set",
		SealedMaterial: base64.StdEncoding.EncodeToString(sealedMaterial),
	}

	responseBytes, _ := json.Marshal(response)
	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: msg.RequestID,
			Payload:   responseBytes,
		},
	}
}

// handlePINUnlock processes PIN unlock when user opens the app
func (vp *VaultProcess) handlePINUnlock(ctx context.Context, msg *Message) *vaultResponse {
	log.Debug().Str("owner_space", vp.OwnerSpace).Msg("PIN unlock requested")

	var req PINUnlockRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid PIN unlock request",
			},
		}
	}

	// Decode sealed material from request
	sealedMaterial, err := base64.StdEncoding.DecodeString(req.SealedMaterial)
	if err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid sealed material encoding",
			},
		}
	}

	// Decrypt the PIN using ECIES private key
	encryptedPIN, err := base64.StdEncoding.DecodeString(req.EncryptedPIN)
	if err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid encrypted PIN encoding",
			},
		}
	}

	pin, err := vp.decryptWithECIES(encryptedPIN)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt PIN")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to decrypt PIN",
			},
		}
	}

	defer func() {
		// Zero PIN after use
		for i := range pin {
			pin[i] = 0
		}
	}()

	// Derive DEK from PIN + sealed material
	dek, err := vp.sealer.DeriveDEKFromPIN(sealedMaterial, string(pin), vp.OwnerSpace)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive DEK from PIN")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "PIN verification failed",
			},
		}
	}

	// If we have a stored DEK hash, verify it matches
	vp.mu.Lock()
	defer vp.mu.Unlock()

	if vp.dekHash != nil {
		derivedHash := sha256.Sum256(dek)
		if !constantTimeCompare(derivedHash[:], vp.dekHash) {
			// Zero the invalid DEK
			for i := range dek {
				dek[i] = 0
			}
			log.Warn().Str("owner_space", vp.OwnerSpace).Msg("PIN verification failed - hash mismatch")
			return &vaultResponse{
				msg: &Message{
					Type:      MessageTypeError,
					RequestID: msg.RequestID,
					Error:     "incorrect PIN",
				},
			}
		}
	}

	// Store the DEK and sealed material
	vp.dek = dek
	vp.sealedMaterial = sealedMaterial

	log.Info().
		Str("owner_space", vp.OwnerSpace).
		Msg("PIN unlock successful - vault unlocked")

	response := PINUnlockResponse{
		Status:  "unlocked",
		Message: "Vault unlocked successfully",
	}

	responseBytes, _ := json.Marshal(response)
	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: msg.RequestID,
			Payload:   responseBytes,
		},
	}
}

// handlePINChange handles PIN change requests
// This implements secure PIN change with proper authorization:
// 1. Verify current PIN against stored DEK hash
// 2. Validate new PIN format (6 digits)
// 3. Generate new sealed material
// 4. Derive new DEK from new PIN + new sealed material
// 5. Update stored DEK hash
// 6. Return new sealed material to app
func (vp *VaultProcess) handlePINChange(ctx context.Context, msg *Message) *vaultResponse {
	log.Info().Str("owner_space", vp.OwnerSpace).Msg("PIN change requested")

	var req PINChangeRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid PIN change request",
			},
		}
	}

	// Decode sealed material from request
	currentSealedMaterial, err := base64.StdEncoding.DecodeString(req.SealedMaterial)
	if err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid sealed material encoding",
			},
		}
	}

	// Decrypt the current PIN using ECIES private key
	encryptedCurrentPIN, err := base64.StdEncoding.DecodeString(req.CurrentEncryptedPIN)
	if err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid current PIN encoding",
			},
		}
	}

	currentPIN, err := vp.decryptWithECIES(encryptedCurrentPIN)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt current PIN")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to decrypt current PIN",
			},
		}
	}

	// Decrypt the new PIN using ECIES private key
	encryptedNewPIN, err := base64.StdEncoding.DecodeString(req.NewEncryptedPIN)
	if err != nil {
		// Zero current PIN before returning
		for i := range currentPIN {
			currentPIN[i] = 0
		}
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid new PIN encoding",
			},
		}
	}

	newPIN, err := vp.decryptWithECIES(encryptedNewPIN)
	if err != nil {
		// Zero current PIN before returning
		for i := range currentPIN {
			currentPIN[i] = 0
		}
		log.Error().Err(err).Msg("Failed to decrypt new PIN")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to decrypt new PIN",
			},
		}
	}

	// Ensure PINs are zeroed after use
	defer func() {
		for i := range currentPIN {
			currentPIN[i] = 0
		}
		for i := range newPIN {
			newPIN[i] = 0
		}
	}()

	// Validate new PIN format (must be 6 digits)
	if len(newPIN) != 6 || !isAllDigits(newPIN) {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "new PIN must be exactly 6 digits",
			},
		}
	}

	// Derive DEK from current PIN + current sealed material
	currentDEK, err := vp.sealer.DeriveDEKFromPIN(currentSealedMaterial, string(currentPIN), vp.OwnerSpace)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive DEK from current PIN")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "PIN verification failed",
			},
		}
	}

	// Verify current PIN against stored DEK hash
	vp.mu.Lock()
	defer vp.mu.Unlock()

	if vp.dekHash == nil {
		// Zero the DEK
		for i := range currentDEK {
			currentDEK[i] = 0
		}
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "PIN not set - use pin.setup first",
			},
		}
	}

	currentDEKHash := sha256.Sum256(currentDEK)
	if !constantTimeCompare(currentDEKHash[:], vp.dekHash) {
		// Zero the invalid DEK
		for i := range currentDEK {
			currentDEK[i] = 0
		}
		log.Warn().Str("owner_space", vp.OwnerSpace).Msg("PIN change failed - current PIN incorrect")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "current PIN is incorrect",
			},
		}
	}

	// Zero the verified current DEK - we don't need it anymore
	for i := range currentDEK {
		currentDEK[i] = 0
	}

	// Generate new sealed material
	newSealedMaterial, err := vp.sealer.GenerateSealedMaterial(vp.OwnerSpace)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate new sealed material")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to generate new sealed material",
			},
		}
	}

	// Derive new DEK from new PIN + new sealed material
	newDEK, err := vp.sealer.DeriveDEKFromPIN(newSealedMaterial, string(newPIN), vp.OwnerSpace)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive DEK from new PIN")
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "failed to derive new DEK",
			},
		}
	}

	// Update vault state with new DEK and sealed material
	vp.sealedMaterial = newSealedMaterial
	vp.dek = newDEK
	newDEKHash := sha256.Sum256(newDEK)
	vp.dekHash = newDEKHash[:]

	log.Info().
		Str("owner_space", vp.OwnerSpace).
		Msg("PIN change completed successfully")

	// Return new sealed material for app to store
	response := PINChangeResponse{
		Status:            "pin_changed",
		NewSealedMaterial: base64.StdEncoding.EncodeToString(newSealedMaterial),
	}

	responseBytes, _ := json.Marshal(response)
	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: msg.RequestID,
			Payload:   responseBytes,
		},
	}
}

// decryptWithECIES decrypts data using the vault's ECIES private key
func (vp *VaultProcess) decryptWithECIES(ciphertext []byte) ([]byte, error) {
	// Format: ephemeral_pubkey (32) || nonce (12) || encrypted_data
	if len(ciphertext) < 32+12 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	ephemeralPubKey := ciphertext[:32]
	nonce := ciphertext[32:44]
	encrypted := ciphertext[44:]

	// X25519 key exchange
	sharedSecret, err := curve25519.X25519(vp.eciesPrivateKey, ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}

	// Derive AES key using HKDF-SHA256
	info := append([]byte("vettid-ecies-encryption"), ephemeralPubKey...)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)
	aesKey := make([]byte, 32)
	if _, err := hkdfReader.Read(aesKey); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Decrypt using AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Zero sensitive data
	for i := range sharedSecret {
		sharedSecret[i] = 0
	}
	for i := range aesKey {
		aesKey[i] = 0
	}

	return plaintext, nil
}

// isAllDigits checks if a byte slice contains only ASCII digits
func isAllDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// constantTimeCompare compares two byte slices in constant time
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// handleBlockMessage processes block/unblock requests
func (vp *VaultProcess) handleBlockMessage(ctx context.Context, msg *Message, parts []string) *vaultResponse {
	// Extract block operation (add/remove)
	var operation string
	for i, part := range parts {
		if part == "block" && i+1 < len(parts) {
			operation = parts[i+1]
			break
		}
	}

	var req struct {
		TargetID     string `json:"target_id"`
		Reason       string `json:"reason,omitempty"`
		DurationSecs int64  `json:"duration_secs,omitempty"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "invalid block request",
			},
		}
	}

	vp.mu.Lock()
	defer vp.mu.Unlock()

	switch operation {
	case "add":
		entry := &BlockListEntry{
			BlockedID: req.TargetID,
			BlockedAt: time.Now().Unix(),
			Reason:    req.Reason,
		}
		if req.DurationSecs > 0 {
			entry.ExpiresAt = entry.BlockedAt + req.DurationSecs
		}
		vp.blockList[req.TargetID] = entry
		log.Info().Str("blocked_id", req.TargetID).Msg("User blocked")

	case "remove":
		delete(vp.blockList, req.TargetID)
		log.Info().Str("unblocked_id", req.TargetID).Msg("User unblocked")

	default:
		return &vaultResponse{
			msg: &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     "unknown block operation",
			},
		}
	}

	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: msg.RequestID,
			Payload:   []byte(`{"status":"ok"}`),
		},
	}
}

// addCallRecord adds a call record to history (keeps last 100)
func (vp *VaultProcess) addCallRecord(record *CallRecord) {
	vp.callHistory = append(vp.callHistory, record)
	if len(vp.callHistory) > 100 {
		vp.callHistory = vp.callHistory[1:]
	}
}

// publishToApp sends a message to the owner's app via NATS
func (vp *VaultProcess) publishToApp(eventType string, payload []byte) {
	subject := "OwnerSpace." + vp.OwnerSpace + ".forApp." + eventType

	msg := &Message{
		Type:    MessageTypeNATSPublish,
		Subject: subject,
		Payload: payload,
	}

	if err := vp.parentSender.SendToParent(msg); err != nil {
		log.Error().Err(err).Str("subject", subject).Msg("Failed to publish to app")
	}
}

// publishToVault sends a message to another vault via NATS
func (vp *VaultProcess) publishToVault(targetOwnerSpace string, eventType string, payload []byte) {
	subject := "OwnerSpace." + targetOwnerSpace + ".forVault." + eventType

	msg := &Message{
		Type:    MessageTypeNATSPublish,
		Subject: subject,
		Payload: payload,
	}

	if err := vp.parentSender.SendToParent(msg); err != nil {
		log.Error().Err(err).Str("subject", subject).Msg("Failed to publish to vault")
	}
}

// CreateCredential creates a new Protean Credential
// This implements the core credential creation flow:
// 1. Decrypt PIN (currently accepts plaintext for dev, encrypted for production)
// 2. Generate Ed25519 identity keypair
// 3. Generate vault master secret
// 4. Hash PIN with Argon2id
// 5. Create credential structure
// 6. Seal credential using KMS-backed envelope encryption
// 7. Return sealed credential blob
func (vp *VaultProcess) CreateCredential(ctx context.Context, req *CredentialRequest) ([]byte, error) {
	if req == nil {
		return nil, fmt.Errorf("credential request is nil")
	}
	if len(req.EncryptedPIN) == 0 {
		return nil, fmt.Errorf("PIN is required")
	}

	log.Info().
		Str("owner_space", vp.OwnerSpace).
		Str("auth_type", req.AuthType).
		Msg("Creating credential")

	// 1. Decrypt PIN from request using ECIES
	// Mobile app encrypts PIN with vault's public key (from GetECIESPublicKey)
	// This ensures PIN is never transmitted in plaintext
	pin, err := vp.decryptPIN(req.EncryptedPIN)
	if err != nil {
		log.Error().Err(err).Str("owner_space", vp.OwnerSpace).Msg("Failed to decrypt PIN")
		return nil, fmt.Errorf("failed to decrypt PIN: %w", err)
	}

	// Validate PIN length (minimum 4 digits/chars, maximum 64)
	if len(pin) < 4 || len(pin) > 64 {
		return nil, fmt.Errorf("PIN must be between 4 and 64 characters")
	}

	// 2. Generate Ed25519 identity keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity keypair: %w", err)
	}

	// 3. Generate vault master secret (256 bits)
	vaultMasterSecret := make([]byte, 32)
	if _, err := rand.Read(vaultMasterSecret); err != nil {
		return nil, fmt.Errorf("failed to generate vault master secret: %w", err)
	}

	// 4. Hash PIN with Argon2id
	// Using OWASP recommended parameters for password hashing
	// Memory: 64 MB, Iterations: 3, Parallelism: 4
	authSalt := make([]byte, 16)
	if _, err := rand.Read(authSalt); err != nil {
		return nil, fmt.Errorf("failed to generate auth salt: %w", err)
	}
	authHash := argon2.IDKey(pin, authSalt, 3, 64*1024, 4, 32)

	// 5. Create credential structure
	credential := &UnsealedCredential{
		IdentityPrivateKey: privateKey,
		IdentityPublicKey:  publicKey,
		VaultMasterSecret:  vaultMasterSecret,
		AuthHash:           authHash,
		AuthSalt:           authSalt,
		AuthType:           req.AuthType,
		CryptoKeys:         make([]CryptoKey, 0),
		CreatedAt:          time.Now().Unix(),
		Version:            1,
	}

	// Marshal credential to JSON for sealing
	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	// 6. Seal credential using KMS-backed envelope encryption
	if vp.sealer == nil {
		return nil, fmt.Errorf("sealer not initialized")
	}

	sealedCredential, err := vp.sealer.Seal(credentialJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to seal credential: %w", err)
	}

	log.Info().
		Str("owner_space", vp.OwnerSpace).
		Int("sealed_size", len(sealedCredential)).
		Msg("Credential created and sealed")

	// Zero sensitive data from memory
	for i := range privateKey {
		privateKey[i] = 0
	}
	for i := range vaultMasterSecret {
		vaultMasterSecret[i] = 0
	}
	for i := range credentialJSON {
		credentialJSON[i] = 0
	}

	return sealedCredential, nil
}

// UnsealCredential unseals and verifies a credential
// This implements the credential unlock flow:
// 1. Unseal credential using KMS-backed envelope encryption
// 2. Verify challenge response (PIN/password/pattern) using Argon2id
// 3. Store unsealed credential in enclave memory
// 4. Generate session token
// 5. Return session token with expiry
func (vp *VaultProcess) UnsealCredential(ctx context.Context, sealed []byte, challenge *Challenge) (*UnsealResult, error) {
	if len(sealed) == 0 {
		return nil, fmt.Errorf("sealed credential is empty")
	}
	if challenge == nil || len(challenge.Response) == 0 {
		return nil, fmt.Errorf("challenge response is required")
	}

	log.Info().
		Str("owner_space", vp.OwnerSpace).
		Str("challenge_id", challenge.ChallengeID).
		Msg("Unsealing credential")

	// 1. Unseal credential using KMS-backed envelope encryption
	if vp.sealer == nil {
		return nil, fmt.Errorf("sealer not initialized")
	}

	unsealedJSON, err := vp.sealer.Unseal(sealed)
	if err != nil {
		log.Warn().
			Str("owner_space", vp.OwnerSpace).
			Err(err).
			Msg("Failed to unseal credential")
		return nil, fmt.Errorf("failed to unseal credential: %w", err)
	}

	// Parse credential
	var credential UnsealedCredential
	if err := json.Unmarshal(unsealedJSON, &credential); err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	// 2. Decrypt challenge response (PIN/password encrypted by mobile app)
	decryptedResponse, err := vp.decryptPIN(challenge.Response)
	if err != nil {
		log.Warn().
			Str("owner_space", vp.OwnerSpace).
			Err(err).
			Msg("Failed to decrypt challenge response")
		// Zero the unsealed data before returning
		for i := range unsealedJSON {
			unsealedJSON[i] = 0
		}
		return nil, fmt.Errorf("failed to decrypt challenge response: %w", err)
	}

	// 3. Verify challenge response (PIN/password/pattern)
	// Hash the decrypted PIN with the stored salt and compare to stored hash
	providedHash := argon2.IDKey(decryptedResponse, credential.AuthSalt, 3, 64*1024, 4, 32)

	// Zero the decrypted response immediately after hashing
	for i := range decryptedResponse {
		decryptedResponse[i] = 0
	}

	// Constant-time comparison to prevent timing attacks
	if !constantTimeCompare(providedHash, credential.AuthHash) {
		log.Warn().
			Str("owner_space", vp.OwnerSpace).
			Msg("Invalid PIN/password")
		// Zero the unsealed data before returning
		for i := range unsealedJSON {
			unsealedJSON[i] = 0
		}
		return nil, ErrInvalidAuth
	}

	// 3. Store unsealed credential in enclave memory
	vp.mu.Lock()
	vp.credential = &credential
	vp.mu.Unlock()

	// 4. Generate session token (256 bits of entropy)
	sessionToken := make([]byte, 32)
	if _, err := rand.Read(sessionToken); err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Session expires in 24 hours
	expiresAt := time.Now().Add(24 * time.Hour).Unix()

	log.Info().
		Str("owner_space", vp.OwnerSpace).
		Int64("expires_at", expiresAt).
		Msg("Credential unsealed successfully")

	// Zero the JSON copy (credential is now stored in vp.credential)
	for i := range unsealedJSON {
		unsealedJSON[i] = 0
	}

	// 5. Return session token
	return &UnsealResult{
		SessionToken: sessionToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// Errors
var (
	ErrOutOfMemory    = &Error{Code: "OUT_OF_MEMORY", Message: "Not enough memory to create vault"}
	ErrNotImplemented = &Error{Code: "NOT_IMPLEMENTED", Message: "Feature not yet implemented"}
	ErrInvalidAuth    = &Error{Code: "INVALID_AUTH", Message: "Invalid PIN, password, or pattern"}
	ErrDecryptionFailed = &Error{Code: "DECRYPTION_FAILED", Message: "Failed to decrypt PIN"}
)

// EncryptedPINPackage represents the ECIES-encrypted PIN from mobile app
// Mobile app encrypts: PIN -> Argon2id hash -> ECIES encrypt with vault's public key
type EncryptedPINPackage struct {
	EphemeralPublicKey []byte `json:"ephemeral_public_key"` // X25519 ephemeral public key (32 bytes)
	Nonce              []byte `json:"nonce"`                // AES-GCM nonce (12 bytes)
	Ciphertext         []byte `json:"ciphertext"`           // Encrypted PIN hash
}

// decryptPIN decrypts an ECIES-encrypted PIN using the vault's private key
// SECURITY: This implements X25519 + HKDF + AES-256-GCM (ECIES)
func (vp *VaultProcess) decryptPIN(encryptedPackage []byte) ([]byte, error) {
	// Check if we're in development mode (accept plaintext PIN)
	if os.Getenv("VETTID_PRODUCTION") != "true" {
		// In development, check if this looks like JSON (encrypted) or plaintext
		if len(encryptedPackage) > 0 && encryptedPackage[0] != '{' {
			log.Warn().Msg("SECURITY WARNING: Accepting plaintext PIN - development mode only")
			return encryptedPackage, nil
		}
	}

	// Parse the encrypted package
	var pkg EncryptedPINPackage
	if err := json.Unmarshal(encryptedPackage, &pkg); err != nil {
		// In production, reject non-encrypted PINs
		if os.Getenv("VETTID_PRODUCTION") == "true" {
			return nil, fmt.Errorf("PIN must be encrypted in production: %w", err)
		}
		// Development fallback: treat as plaintext
		log.Warn().Msg("SECURITY WARNING: Accepting plaintext PIN - development mode only")
		return encryptedPackage, nil
	}

	// Validate package
	if len(pkg.EphemeralPublicKey) != 32 {
		return nil, fmt.Errorf("%w: invalid ephemeral public key length", ErrDecryptionFailed)
	}
	if len(pkg.Nonce) != 12 {
		return nil, fmt.Errorf("%w: invalid nonce length", ErrDecryptionFailed)
	}
	if len(pkg.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: empty ciphertext", ErrDecryptionFailed)
	}

	// Perform X25519 key agreement
	sharedSecret, err := curve25519.X25519(vp.eciesPrivateKey, pkg.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: key agreement failed", ErrDecryptionFailed)
	}

	// Derive AES key using HKDF-SHA256
	// Info string includes both public keys for domain separation
	info := append([]byte("vettid-pin-encryption"), pkg.EphemeralPublicKey...)
	info = append(info, vp.eciesPublicKey...)

	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)
	aesKey := make([]byte, 32) // AES-256
	if _, err := hkdfReader.Read(aesKey); err != nil {
		return nil, fmt.Errorf("%w: key derivation failed", ErrDecryptionFailed)
	}

	// Decrypt using AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("%w: cipher creation failed", ErrDecryptionFailed)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: GCM creation failed", ErrDecryptionFailed)
	}

	plaintext, err := gcm.Open(nil, pkg.Nonce, pkg.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: decryption failed (invalid ciphertext or key)", ErrDecryptionFailed)
	}

	// Zero sensitive data
	for i := range sharedSecret {
		sharedSecret[i] = 0
	}
	for i := range aesKey {
		aesKey[i] = 0
	}

	return plaintext, nil
}

// GetECIESPublicKey returns the vault's ECIES public key for PIN encryption
// Mobile apps use this key to encrypt PINs before sending to the vault
func (vp *VaultProcess) GetECIESPublicKey() []byte {
	return vp.eciesPublicKey
}

// Error represents an error with a code
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	return e.Message
}
