package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os/exec"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SECURITY: Constants for timing side-channel mitigation
const (
	// Random jitter range for process eviction (0-100ms)
	processEvictionJitterMaxMs = 100
)

// ProcessManager handles spawning and managing vault-manager processes.
// Each user vault runs in its own isolated process for security.
type ProcessManager struct {
	binaryPath    string
	devMode       bool
	processes     map[string]*ManagedProcess
	mu            sync.RWMutex
	sealerHandler *SealerHandler
}

// ManagedProcess represents a spawned vault-manager process
type ManagedProcess struct {
	OwnerSpace string
	Cmd        *exec.Cmd
	Conn       *PipeConnection
	StartedAt  time.Time
	LastAccess time.Time
}

// NewProcessManager creates a new process manager
func NewProcessManager(binaryPath string, devMode bool, sealerHandler *SealerHandler) *ProcessManager {
	return &ProcessManager{
		binaryPath:    binaryPath,
		devMode:       devMode,
		processes:     make(map[string]*ManagedProcess),
		sealerHandler: sealerHandler,
	}
}

// Spawn creates a new vault-manager process for the given owner space.
// Returns an existing process if one is already running.
func (pm *ProcessManager) Spawn(ownerSpace string) (*ManagedProcess, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if process already exists
	if proc, exists := pm.processes[ownerSpace]; exists {
		proc.LastAccess = time.Now()
		return proc, nil
	}

	// Create the command
	cmd := exec.Command(
		pm.binaryPath,
		"--owner-space", ownerSpace,
	)

	if pm.devMode {
		cmd.Args = append(cmd.Args, "--dev-mode")
	}

	// Set up pipes for communication
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Capture stderr for logging
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("failed to start vault-manager: %w", err)
	}

	// Log stderr from the child process
	go pm.logStderr(ownerSpace, stderr)

	// Create managed process
	proc := &ManagedProcess{
		OwnerSpace: ownerSpace,
		Cmd:        cmd,
		Conn:       NewPipeConnection(stdin, stdout),
		StartedAt:  time.Now(),
		LastAccess: time.Now(),
	}

	pm.processes[ownerSpace] = proc

	log.Info().
		Str("owner_space", ownerSpace).
		Int("pid", cmd.Process.Pid).
		Str("binary", pm.binaryPath).
		Msg("Spawned vault-manager process")

	// Start goroutine to handle process exit
	go pm.waitForExit(ownerSpace, cmd)

	return proc, nil
}

// logStderr logs stderr output from the child process
func (pm *ProcessManager) logStderr(ownerSpace string, stderr interface{ Read([]byte) (int, error) }) {
	buf := make([]byte, 4096)
	for {
		n, err := stderr.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			log.Debug().
				Str("owner_space", ownerSpace).
				Str("stderr", string(buf[:n])).
				Msg("vault-manager stderr")
		}
	}
}

// waitForExit waits for a process to exit and cleans up
func (pm *ProcessManager) waitForExit(ownerSpace string, cmd *exec.Cmd) {
	err := cmd.Wait()

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if proc, exists := pm.processes[ownerSpace]; exists {
		proc.Conn.Close()
		delete(pm.processes, ownerSpace)
	}

	if err != nil {
		log.Warn().
			Str("owner_space", ownerSpace).
			Err(err).
			Msg("vault-manager process exited with error")
	} else {
		log.Info().
			Str("owner_space", ownerSpace).
			Msg("vault-manager process exited normally")
	}
}

// Get returns an existing process or nil if not found
func (pm *ProcessManager) Get(ownerSpace string) *ManagedProcess {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if proc, exists := pm.processes[ownerSpace]; exists {
		proc.LastAccess = time.Now()
		return proc
	}
	return nil
}

// Kill terminates a vault-manager process
func (pm *ProcessManager) Kill(ownerSpace string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	proc, exists := pm.processes[ownerSpace]
	if !exists {
		return nil // Already gone
	}

	// Close pipes first to signal shutdown
	proc.Conn.Close()

	// Send SIGTERM
	if err := proc.Cmd.Process.Kill(); err != nil {
		log.Warn().
			Str("owner_space", ownerSpace).
			Err(err).
			Msg("Failed to kill vault-manager process")
	}

	delete(pm.processes, ownerSpace)

	log.Info().
		Str("owner_space", ownerSpace).
		Msg("Killed vault-manager process")

	return nil
}

// Send sends a message to a vault-manager process and waits for response.
// Spawns the process if it doesn't exist.
// Handles sealer requests from the vault-manager during the response wait.
func (pm *ProcessManager) Send(ctx context.Context, ownerSpace string, msg *Message, timeout time.Duration) (*Message, error) {
	// Get or spawn process
	proc, err := pm.Spawn(ownerSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to get/spawn process: %w", err)
	}

	// Send the initial message
	if err := proc.Conn.WriteMessage(msg); err != nil {
		pm.Kill(ownerSpace)
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	// Read messages in a loop, handling sealer requests until we get the final response
	deadline := time.Now().Add(timeout)
	for {
		// Check deadline
		remaining := time.Until(deadline)
		if remaining <= 0 {
			pm.Kill(ownerSpace)
			return nil, fmt.Errorf("timeout waiting for response")
		}

		// Read next message with timeout
		response, err := proc.Conn.ReadMessageWithTimeout(remaining)
		if err != nil {
			pm.Kill(ownerSpace)
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		// Check if this is a sealer request
		if response.Type == MessageTypeSealerRequest {
			// Handle sealer request and send response back
			sealerResp := pm.handleSealerRequest(response)
			if err := proc.Conn.WriteMessage(sealerResp); err != nil {
				pm.Kill(ownerSpace)
				return nil, fmt.Errorf("failed to send sealer response: %w", err)
			}
			// Continue waiting for the final response
			continue
		}

		// Got the final response
		return response, nil
	}
}

// handleSealerRequest processes a sealer request from vault-manager
func (pm *ProcessManager) handleSealerRequest(msg *Message) *Message {
	if pm.sealerHandler == nil {
		log.Warn().Msg("Sealer handler not configured, returning mock response")
		return &Message{
			RequestID: msg.RequestID,
			Type:      MessageTypeSealerResponse,
			Payload:   []byte(`{"success":false,"error":"sealer not available"}`),
		}
	}
	return pm.sealerHandler.HandleSealerRequest(msg)
}

// GetOrSpawn gets an existing process or spawns a new one
func (pm *ProcessManager) GetOrSpawn(ownerSpace string) (*ManagedProcess, error) {
	return pm.Spawn(ownerSpace)
}

// Count returns the number of active processes
func (pm *ProcessManager) Count() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.processes)
}

// List returns a list of active owner spaces
func (pm *ProcessManager) List() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	result := make([]string, 0, len(pm.processes))
	for ownerSpace := range pm.processes {
		result = append(result, ownerSpace)
	}
	return result
}

// KillAll terminates all vault-manager processes
func (pm *ProcessManager) KillAll() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for ownerSpace, proc := range pm.processes {
		proc.Conn.Close()
		proc.Cmd.Process.Kill()
		log.Info().Str("owner_space", ownerSpace).Msg("Killed vault-manager process")
	}

	pm.processes = make(map[string]*ManagedProcess)
}

// GetLRU returns the least recently used process
func (pm *ProcessManager) GetLRU() *ManagedProcess {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var oldest *ManagedProcess
	for _, proc := range pm.processes {
		if oldest == nil || proc.LastAccess.Before(oldest.LastAccess) {
			oldest = proc
		}
	}
	return oldest
}

// EvictLRU kills the least recently used process
// SECURITY: Uses random jitter to prevent timing side-channel attacks
func (pm *ProcessManager) EvictLRU() error {
	oldest := pm.GetLRU()
	if oldest == nil {
		return nil
	}

	// SECURITY: Add random jitter to prevent timing inference
	addProcessEvictionJitter()

	return pm.Kill(oldest.OwnerSpace)
}

// addProcessEvictionJitter adds a random delay to process eviction
// SECURITY: This prevents timing attacks that could infer which vaults are active
func addProcessEvictionJitter() {
	jitterMs, err := rand.Int(rand.Reader, big.NewInt(processEvictionJitterMaxMs))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate process eviction jitter")
		return
	}

	jitter := time.Duration(jitterMs.Int64()) * time.Millisecond
	if jitter > 0 {
		time.Sleep(jitter)
	}
}
