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

// ProcessManager spawns vault-manager subprocesses. It is a stateless
// factory: it holds NO per-owner state and keeps NO reference to the
// processes it spawns. Each Spawn hands a fresh, independent
// ManagedProcess to its caller, and that caller — the VaultProcess — is
// the single owner of the subprocess for its whole life.
//
// This one-owner rule is load-bearing. The earlier design kept a second
// owner-keyed map here; an op write, a kill, and a signal each
// re-resolved "the subprocess for this owner" by key, independently of
// the VaultProcess. The two views could drift, and a vault op would be
// written into an orphaned subprocess's stdin pipe — the write
// succeeded into a kernel buffer nobody drained — while a fresh
// subprocess sat idle. That was the 2026-05-22 ~30s device-approval
// stall (docs/DEVICE-APPROVAL-27S-STALL.md). With no second map there is
// nothing to drift against.
type ProcessManager struct {
	binaryPath    string
	devMode       bool
	sealerHandler *SealerHandler
	logForwarder  LogForwarder // Optional callback to forward logs to parent
}

// ManagedProcess is a single spawned vault-manager subprocess. It is
// owned solely by the VaultProcess that Spawn handed it to; every
// lifecycle operation (op write, signal, kill) acts on THIS handle —
// never on a re-resolved owner-keyed lookup.
type ManagedProcess struct {
	OwnerSpace string
	Cmd        *exec.Cmd
	Conn       *PipeConnection
	StartedAt  time.Time

	// killOnce makes kill() idempotent: a double evict (e.g. a
	// heartbeat CAS-fail followed by a watcher event for the same user)
	// is harmless.
	killOnce sync.Once
}

// NewProcessManager creates a new process manager
func NewProcessManager(binaryPath string, devMode bool, sealerHandler *SealerHandler, logForwarder LogForwarder) *ProcessManager {
	return &ProcessManager{
		binaryPath:    binaryPath,
		devMode:       devMode,
		sealerHandler: sealerHandler,
		logForwarder:  logForwarder,
	}
}

// Spawn starts a fresh vault-manager subprocess for the given owner
// space and returns its handle. It is a pure factory — it stores no
// reference to the returned process. Every call produces a brand-new
// subprocess; there is deliberately no reuse-by-key path (that path was
// the divergence engine behind the device-approval stall). The caller
// owns the returned ManagedProcess and is responsible for kill()ing it.
func (pm *ProcessManager) Spawn(ownerSpace string) (*ManagedProcess, error) {
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

	proc := &ManagedProcess{
		OwnerSpace: ownerSpace,
		Cmd:        cmd,
		Conn:       NewPipeConnection(stdin, stdout),
		StartedAt:  time.Now(),
	}

	// Reap the OS process when it exits so a self-evicted / crashed
	// subprocess does not linger as a zombie. There is no map to clean
	// up: the VaultProcess that owns this handle detects the death
	// independently, the instant its pipe reader sees EOF (failAllPending).
	go func() {
		if waitErr := cmd.Wait(); waitErr != nil {
			log.Warn().
				Str("owner_space", ownerSpace).
				Err(waitErr).
				Msg("vault-manager process exited with error")
		} else {
			log.Info().
				Str("owner_space", ownerSpace).
				Msg("vault-manager process exited normally")
		}
	}()

	log.Info().
		Str("owner_space", ownerSpace).
		Int("pid", cmd.Process.Pid).
		Str("binary", pm.binaryPath).
		Msg("Spawned vault-manager process")

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

// kill closes the subprocess pipes and terminates the process. It acts
// on THIS exact handle — there is no owner-keyed lookup that could
// resolve to a different subprocess. Idempotent via killOnce.
//
// Closing Conn first makes the owning VaultProcess's pipe reader see
// EOF and exit (which fails any in-flight op via failAllPending); the
// SIGKILL then drops the subprocess and its in-memory credential state.
func (mp *ManagedProcess) kill() {
	mp.killOnce.Do(func() {
		if mp.Conn != nil {
			mp.Conn.Close()
		}
		if mp.Cmd != nil && mp.Cmd.Process != nil {
			if err := mp.Cmd.Process.Kill(); err != nil {
				// Already gone (self-evicted / crashed) — expected, not fatal.
				log.Debug().
					Str("owner_space", mp.OwnerSpace).
					Err(err).
					Msg("kill: vault-manager process already gone")
			}
		}
		log.Info().
			Str("owner_space", mp.OwnerSpace).
			Msg("Killed vault-manager process")
	})
}

// signal sends an OS signal to this subprocess. Used by the stall
// watchdog to request a SIGUSR1 goroutine dump from a subprocess whose
// op has stalled.
func (mp *ManagedProcess) signal(sig os.Signal) error {
	if mp.Cmd == nil || mp.Cmd.Process == nil {
		return fmt.Errorf("subprocess for owner %s has no process handle", mp.OwnerSpace)
	}
	return mp.Cmd.Process.Signal(sig)
}
