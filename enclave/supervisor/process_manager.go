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

// LogForwarder is a function that forwards logs to the parent
type LogForwarder func(level, source, message string)

// ProcessManager handles spawning and managing vault-manager processes.
// Each user vault runs in its own isolated process for security.
type ProcessManager struct {
	binaryPath    string
	devMode       bool
	processes     map[string]*ManagedProcess
	mu            sync.RWMutex
	sealerHandler *SealerHandler
	logForwarder  LogForwarder // Optional callback to forward logs to parent
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
func NewProcessManager(binaryPath string, devMode bool, sealerHandler *SealerHandler, logForwarder LogForwarder) *ProcessManager {
	return &ProcessManager{
		binaryPath:    binaryPath,
		devMode:       devMode,
		processes:     make(map[string]*ManagedProcess),
		sealerHandler: sealerHandler,
		logForwarder:  logForwarder,
	}
}

// Spawn creates a new vault-manager process for the given owner space.
// Returns an existing process if one is already running.
func (pm *ProcessManager) Spawn(ownerSpace string) (*ManagedProcess, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if process already exists AND is still alive. A
	// subprocess that self-evicted (D3 split-brain self-heal) or
	// crashed may still be in the map for the brief window before
	// waitForExit's cmd.Wait() returns. ProcessState is non-nil once
	// the process has exited — treat such a stale entry as absent and
	// fall through to spawn a genuinely fresh one. (The race window
	// where the process has exited but ProcessState isn't set yet is
	// covered by Send's retry-once-on-write-failure.)
	if proc, exists := pm.processes[ownerSpace]; exists {
		if proc.Cmd.ProcessState == nil {
			proc.LastAccess = time.Now()
			return proc, nil
		}
		log.Info().
			Str("owner_space", ownerSpace).
			Msg("Spawn: existing subprocess has exited — replacing with a fresh one")
		proc.Conn.Close()
		delete(pm.processes, ownerSpace)
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

// logStderr logs stderr output from the child process and forwards to parent
func (pm *ProcessManager) logStderr(ownerSpace string, stderr interface{ Read([]byte) (int, error) }) {
	buf := make([]byte, 4096)
	for {
		n, err := stderr.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			logMsg := string(buf[:n])

			// Log locally at Info level (was Debug)
			log.Info().
				Str("owner_space", ownerSpace).
				Str("stderr", logMsg).
				Msg("vault-manager stderr")

			// Forward to parent for CloudWatch if forwarder is configured
			if pm.logForwarder != nil {
				pm.logForwarder("info", "vault-manager:"+ownerSpace, logMsg)
			}
		}
	}
}

// waitForExit waits for a process to exit and cleans up.
//
// Ownership check: only reap the map entry if it still points at OUR
// cmd. A subprocess can self-evict (D3 split-brain self-heal) and be
// immediately replaced by a fresh Spawn before this goroutine's
// cmd.Wait() returns. Without the `proc.Cmd == cmd` guard, the OLD
// process's waitForExit would close + delete the brand-new
// REPLACEMENT, leaving the map empty and the live subprocess
// orphaned (pipe closed under it). Common now that D3 self-eviction
// makes deliberate subprocess exit a routine event.
func (pm *ProcessManager) waitForExit(ownerSpace string, cmd *exec.Cmd) {
	err := cmd.Wait()

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if proc, exists := pm.processes[ownerSpace]; exists && proc.Cmd == cmd {
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

	// Send the initial message. If the write fails, the subprocess is
	// gone — it self-evicted (D3 split-brain self-heal), crashed, or
	// was reaped in the race window between Spawn returning a cached
	// handle and this write. The subprocess never received the
	// message, so retrying is clean: kill the stale entry, spawn a
	// genuinely fresh subprocess (which cold-loads current S3 state),
	// and write once more. Without this retry, every op that raced a
	// self-eviction surfaced to the user as
	// "failed to write length prefix: file already closed".
	if err := proc.Conn.WriteMessage(msg); err != nil {
		log.Warn().
			Str("owner_space", ownerSpace).
			Err(err).
			Msg("vault-manager send: initial write failed (subprocess gone) — respawning and retrying once")
		pm.Kill(ownerSpace)
		proc, err = pm.Spawn(ownerSpace)
		if err != nil {
			return nil, fmt.Errorf("failed to respawn process after write failure: %w", err)
		}
		if err := proc.Conn.WriteMessage(msg); err != nil {
			pm.Kill(ownerSpace)
			return nil, fmt.Errorf("failed to send message after respawn: %w", err)
		}
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

		// Handle different message types from vault-manager
		switch response.Type {
		case MessageTypeSealerRequest:
			// Handle sealer request and send response back
			sealerResp := pm.handleSealerRequest(response)
			if err := proc.Conn.WriteMessage(sealerResp); err != nil {
				pm.Kill(ownerSpace)
				return nil, fmt.Errorf("failed to send sealer response: %w", err)
			}
			// Continue waiting for the final response
			continue

		case MessageTypeHTTPRequest:
			// Handle HTTP proxy request: forward to parent and send response back
			httpResp := pm.handleHTTPRequest(response)
			if err := proc.Conn.WriteMessage(httpResp); err != nil {
				pm.Kill(ownerSpace)
				return nil, fmt.Errorf("failed to send HTTP response: %w", err)
			}
			// Continue waiting for the final response
			continue

		case MessageTypeNATSPublish, MessageTypeLog, MessageTypeRoutingHandoff:
			// These messages should be forwarded to parent, not returned as the response.
			// In the process_manager context, we don't have direct access to forward them,
			// so we log a warning and continue waiting for the actual response.
			log.Warn().
				Str("owner_space", ownerSpace).
				Str("message_type", string(response.Type)).
				Msg("Received intermediate message from vault-manager, waiting for actual response")
			continue

		default:
			// Got the final response (response, error, etc.)
			return response, nil
		}
	}
}

// handleHTTPRequest forwards an HTTP proxy request from vault-manager to the parent
func (pm *ProcessManager) handleHTTPRequest(msg *Message) *Message {
	if pm.sealerHandler == nil {
		log.Warn().Msg("Sealer handler not configured for HTTP proxy, returning error")
		return &Message{
			RequestID: msg.RequestID,
			Type:      MessageTypeHTTPResponse,
			Payload:   []byte(`{"error":"HTTP proxy not available"}`),
		}
	}
	return pm.sealerHandler.ForwardHTTPRequest(msg)
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
