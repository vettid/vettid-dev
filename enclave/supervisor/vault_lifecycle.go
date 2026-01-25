package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SECURITY: Constants for timing side-channel mitigation
const (
	// Random jitter range for eviction operations (0-100ms)
	// This prevents timing attacks that could infer vault activity
	evictionJitterMaxMs = 100
)

// ParentSender is the interface for sending messages to parent
type ParentSender interface {
	SendToParent(msg *Message) error
}

// VaultManager manages the lifecycle of vault-manager processes
type VaultManager struct {
	config         *Config
	memoryManager  *MemoryManager
	parentSender   ParentSender
	sealer         *NitroSealer
	sealerHandler  *SealerHandler  // For handling sealer requests from vault-manager
	processManager *ProcessManager // Manages vault-manager subprocesses

	vaults    map[string]*VaultProcess
	lruOrder  []string // Least recently used order for eviction
	mu        sync.RWMutex
	startTime time.Time
}

// VaultProcess represents a running vault-manager subprocess for a specific user.
// All credential state is held by the subprocess, not the supervisor.
type VaultProcess struct {
	OwnerSpace   string
	StartedAt    time.Time
	LastAccess   time.Time
	MemoryMB     int
	parentSender ParentSender

	// Process-based architecture
	process       *ManagedProcess // Reference to spawned vault-manager process
	sealerHandler *SealerHandler  // For handling sealer requests from vault-manager

	mu sync.RWMutex
}

// VaultStats holds vault manager statistics
type VaultStats struct {
	ActiveVaults  int
	TotalVaults   int
	UptimeSeconds int64
}

// NewVaultManager creates a new vault manager
func NewVaultManager(cfg *Config, memMgr *MemoryManager, parentSender ParentSender, sealer *NitroSealer, logForwarder LogForwarder) *VaultManager {
	// Create sealer handler for proxying KMS operations to vault-manager processes
	sealerHandler := NewSealerHandler(sealer)

	// Create process manager for spawning vault-manager subprocesses
	// Per Architecture v3.1: Each vault runs in its own isolated process
	procMgr := NewProcessManager(cfg.VaultManagerPath, cfg.DevMode, sealerHandler, logForwarder)

	return &VaultManager{
		config:         cfg,
		memoryManager:  memMgr,
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
	// Note: All credential state (ECIES keys, CEK, UTK, PIN, blocklist, etc.)
	// is held by the subprocess, not the supervisor.
	vault := &VaultProcess{
		OwnerSpace:    ownerSpace,
		StartedAt:     time.Now(),
		LastAccess:    time.Now(),
		MemoryMB:      memoryMB,
		parentSender:  vm.parentSender,
		process:       proc,
		sealerHandler: vm.sealerHandler,
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

// evictLRU evicts the least recently used vault
// SECURITY: Uses random jitter to prevent timing side-channel attacks
func (vm *VaultManager) evictLRU() {
	if len(vm.lruOrder) == 0 {
		return
	}

	// SECURITY: Add random jitter to prevent timing inference
	// An attacker observing eviction timing could infer vault activity patterns
	addEvictionJitter()

	// Evict the oldest (first in LRU list)
	oldest := vm.lruOrder[0]
	vm.evictVault(oldest)
}

// addEvictionJitter adds a random delay to eviction operations
// SECURITY: This prevents timing attacks that could infer which vaults are active
func addEvictionJitter() {
	// Generate cryptographically random jitter
	jitterMs, err := rand.Int(rand.Reader, big.NewInt(evictionJitterMaxMs))
	if err != nil {
		// Fallback to no jitter if random fails (shouldn't happen)
		log.Warn().Err(err).Msg("Failed to generate eviction jitter")
		return
	}

	jitter := time.Duration(jitterMs.Int64()) * time.Millisecond
	if jitter > 0 {
		time.Sleep(jitter)
	}
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

	// Evict all vaults
	for ownerSpace := range vm.vaults {
		vm.evictVault(ownerSpace)
	}

	// Ensure all subprocesses are killed
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

	// Process-based architecture is the only path.
	// If we reach here, something is wrong with process spawning.
	log.Error().
		Str("owner_space", vp.OwnerSpace).
		Msg("FATAL: No subprocess connection available")
	return nil, fmt.Errorf("process-based routing not available for owner %s", vp.OwnerSpace)
}

// Error represents an error with a code
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

// Common errors
var (
	ErrOutOfMemory = &Error{Code: "OUT_OF_MEMORY", Message: "insufficient memory to create vault"}
)
