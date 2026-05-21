package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
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
	// covered by handleVaultOp's retry-once on a subprocess-gone
	// write error.)
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

// Signal sends an OS signal to a managed subprocess by owner space.
// DIAG: used by the stall watchdog to request a SIGUSR1 goroutine dump
// from a subprocess whose op has stalled. Non-fatal: a missing entry
// just means the subprocess isn't tracked here (e.g. an org vault).
func (pm *ProcessManager) Signal(ownerSpace string, sig os.Signal) error {
	pm.mu.RLock()
	proc, exists := pm.processes[ownerSpace]
	pm.mu.RUnlock()
	if !exists {
		return fmt.Errorf("no managed subprocess for owner %s", ownerSpace)
	}
	if proc.Cmd == nil || proc.Cmd.Process == nil {
		return fmt.Errorf("subprocess for owner %s has no process handle", ownerSpace)
	}
	return proc.Cmd.Process.Signal(sig)
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
