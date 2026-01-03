package main

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ParentSender is the interface for sending messages to parent
type ParentSender interface {
	SendToParent(msg *Message) error
}

// VaultManager manages the lifecycle of vault-manager processes
type VaultManager struct {
	config        *Config
	memoryManager *MemoryManager
	handlerCache  *HandlerCache
	parentSender  ParentSender

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

	// Communication channels
	requestChan  chan *vaultRequest
	responseChan chan *vaultResponse
	stopChan     chan struct{}

	// Credential state (unsealed in enclave memory)
	credential *UnsealedCredential

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
func NewVaultManager(cfg *Config, memMgr *MemoryManager, cache *HandlerCache, parentSender ParentSender) *VaultManager {
	return &VaultManager{
		config:        cfg,
		memoryManager: memMgr,
		handlerCache:  cache,
		parentSender:  parentSender,
		vaults:        make(map[string]*VaultProcess),
		lruOrder:      make([]string, 0),
		startTime:     time.Now(),
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

	// Create new vault
	vault := &VaultProcess{
		OwnerSpace:   ownerSpace,
		StartedAt:    time.Now(),
		LastAccess:   time.Now(),
		MemoryMB:     40, // Estimated memory per vault
		parentSender: vm.parentSender,
		requestChan:  make(chan *vaultRequest, 10),
		responseChan: make(chan *vaultResponse, 10),
		stopChan:     make(chan struct{}),
		blockList:    make(map[string]*BlockListEntry),
		callHistory:  make([]*CallRecord, 0),
	}

	// Reserve memory
	if !vm.memoryManager.Reserve(vault.MemoryMB) {
		// Try evicting and reserving again
		vm.evictLRU()
		if !vm.memoryManager.Reserve(vault.MemoryMB) {
			log.Error().Str("owner_space", ownerSpace).Msg("Cannot allocate memory for vault")
			return nil, ErrOutOfMemory
		}
	}

	// Start vault process goroutine
	go vault.run()

	vm.vaults[ownerSpace] = vault
	vm.lruOrder = append(vm.lruOrder, ownerSpace)

	log.Info().
		Str("owner_space", ownerSpace).
		Int("active_vaults", len(vm.vaults)).
		Msg("Created new vault")

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

	// Stop the vault
	close(vault.stopChan)

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

	for ownerSpace := range vm.vaults {
		vm.evictVault(ownerSpace)
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

// ProcessMessage sends a message to the vault process and waits for response
func (vp *VaultProcess) ProcessMessage(ctx context.Context, msg *Message) (*Message, error) {
	vp.touch()

	req := &vaultRequest{ctx: ctx, msg: msg}
	select {
	case vp.requestChan <- req:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case resp := <-vp.responseChan:
		return resp.msg, resp.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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

// handleBootstrap processes bootstrap requests
func (vp *VaultProcess) handleBootstrap(ctx context.Context, msg *Message) *vaultResponse {
	log.Info().Str("owner_space", vp.OwnerSpace).Msg("Bootstrap requested")

	// TODO: Return vault capabilities and state
	return &vaultResponse{
		msg: &Message{
			Type:      MessageTypeVaultResponse,
			RequestID: msg.RequestID,
			Payload:   []byte(`{"status":"ready","capabilities":["call","sign","store"]}`),
		},
	}
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
func (vp *VaultProcess) CreateCredential(ctx context.Context, req *CredentialRequest) ([]byte, error) {
	// TODO: Implement credential creation
	// 1. Decrypt PIN using enclave's private key
	// 2. Generate identity keypair (Ed25519)
	// 3. Generate vault master secret
	// 4. Hash PIN with Argon2id
	// 5. Create credential structure
	// 6. Seal credential to PCRs
	// 7. Return sealed credential blob

	return nil, ErrNotImplemented
}

// UnsealCredential unseals and verifies a credential
func (vp *VaultProcess) UnsealCredential(ctx context.Context, sealed []byte, challenge *Challenge) (*UnsealResult, error) {
	// TODO: Implement credential unsealing
	// 1. Unseal credential using PCR-bound key
	// 2. Verify challenge response (PIN/password/pattern)
	// 3. Store unsealed credential in enclave memory
	// 4. Generate session token
	// 5. Return session token

	return nil, ErrNotImplemented
}

// Errors
var (
	ErrOutOfMemory    = &Error{Code: "OUT_OF_MEMORY", Message: "Not enough memory to create vault"}
	ErrNotImplemented = &Error{Code: "NOT_IMPLEMENTED", Message: "Feature not yet implemented"}
)

// Error represents an error with a code
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	return e.Message
}
