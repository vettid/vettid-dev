package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
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

	mu sync.RWMutex // Guards struct fields (LastAccess etc.)

	// procMu serializes ProcessMessage for this user. Ops for one user
	// share a single subprocess that processes them serially, so the
	// supervisor writes them one at a time. Different users hold
	// different procMu, so cross-user concurrency is unaffected. The
	// pipe READER (below) is independent of procMu — it always runs.
	procMu sync.Mutex

	// Pipe reader correlation. A single persistent goroutine
	// (startPipeReader) drains the subprocess stdout pipe for the life
	// of the subprocess and demuxes every frame: an op response goes to
	// the ProcessMessage waiting on its PipeID via `pending`; a sealer
	// or http request is serviced on a worker; nats / log / audit /
	// routing messages are forwarded to the parent. Always draining the
	// pipe is the point of this design — a subprocess-initiated message
	// (notably the ~1MB store_vault_state persist) is serviced the
	// instant it lands, instead of stalling up to 30s until the next
	// op's read window. See docs/SUPERVISOR-ALWAYS-DRAIN-PLAN.md.
	pendingMu    sync.Mutex
	pending      map[string]chan *Message
	readerClosed bool // set once the reader goroutine has exited
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
	// SECURITY (#74): wire devMode so production (cfg.DevMode=false)
	// fails-closed on missing parent connection instead of silently
	// pretending S3 PUTs succeeded.
	sealerHandler.SetDevMode(cfg.DevMode)

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

	// Check if vault already exists AND its subprocess is still alive.
	// A vault-manager subprocess that self-evicted (D3 split-brain
	// self-heal) or crashed leaves a stale VaultProcess cached here
	// with a dead pipe. Liveness is read from isAlive() — the pipe
	// reader sets readerClosed (under pendingMu) the instant the pipe
	// dies, so it is a properly synchronized signal. (The old check
	// read vault.process.Cmd.ProcessState, which is written by the
	// reaper goroutine with no happens-before to this read — a data
	// race that could also report "alive" during the post-exit window
	// before cmd.Wait() returned.) A dead wrapper is evicted here and
	// replaced with a genuinely fresh subprocess; without this,
	// GetOrCreate would hand back the dead wrapper and ProcessMessage's
	// write would fail with "file already closed".
	if vault, exists := vm.vaults[ownerSpace]; exists {
		if vault.isAlive() {
			vault.touch()
			vm.updateLRU(ownerSpace)
			return vault, nil
		}
		log.Info().
			Str("owner_space", ownerSpace).
			Msg("GetOrCreate: cached vault subprocess has exited — replacing with a fresh one")
		vm.evictVault(ownerSpace) // holds vm.mu — caller already locked
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

	// Wrap the subprocess. newVaultProcess inits the pending map and
	// starts the single persistent pipe reader — the VaultProcess is
	// now the sole owner of this subprocess handle.
	vault := newVaultProcess(ownerSpace, proc, vm.parentSender, vm.sealerHandler, memoryMB)

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

// SignalSubprocess sends an OS signal to a user's vault-manager
// subprocess, resolved through the one authoritative VaultProcess
// handle. Used by the stall watchdog to request a SIGUSR1 goroutine
// dump. A missing entry just means no resident vault for that owner.
func (vm *VaultManager) SignalSubprocess(ownerSpace string, sig os.Signal) error {
	vm.mu.RLock()
	vault, exists := vm.vaults[ownerSpace]
	vm.mu.RUnlock()
	if !exists || vault.process == nil {
		return fmt.Errorf("no resident vault subprocess for owner %s", ownerSpace)
	}
	return vault.process.signal(sig)
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

	// Kill the vault-manager subprocess by its exact handle. This is
	// the one process the evicted VaultProcess wrapped — never a
	// re-resolved owner-keyed lookup that could land on a different
	// subprocess and leave this one orphaned-but-alive.
	if vault.process != nil {
		vault.process.kill()
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

	// Evict every vault — evictVault kills each subprocess by its own
	// handle, so no separate process sweep is needed.
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

// SetMux wires the multiplexed parent transport into the SealerHandler
// so vault-manager S3/KMS proxy requests reach the parent.
func (vm *VaultManager) SetMux(mux *MuxConn) {
	if vm.sealerHandler != nil {
		vm.sealerHandler.SetMux(mux)
	}
}

// VaultProcess methods

// newVaultProcess wraps a freshly spawned subprocess. It initialises
// the pending-op map and starts the single persistent pipe reader, so
// every VaultProcess — whether for a user vault or an org vault — is
// fully wired before it is handed out. (The org path previously built
// the struct inline and skipped both, which left pending nil and
// ProcessMessage panicking on the first op.)
func newVaultProcess(ownerSpace string, proc *ManagedProcess, parentSender ParentSender, sealerHandler *SealerHandler, memoryMB int) *VaultProcess {
	vp := &VaultProcess{
		OwnerSpace:    ownerSpace,
		StartedAt:     time.Now(),
		LastAccess:    time.Now(),
		MemoryMB:      memoryMB,
		parentSender:  parentSender,
		process:       proc,
		sealerHandler: sealerHandler,
		pending:       make(map[string]chan *Message),
	}
	// Start the persistent pipe reader. It runs until the subprocess
	// dies (eviction kills it → pipe EOF → reader exits → readerClosed),
	// so it needs no explicit stop. Exactly one reader per subprocess:
	// startPipeReader is called only here, only once per VaultProcess.
	vp.startPipeReader()
	return vp
}

// touch updates the last access time
func (vp *VaultProcess) touch() {
	vp.mu.Lock()
	vp.LastAccess = time.Now()
	vp.mu.Unlock()
}

// isAlive reports whether the subprocess pipe is still open. It reads
// readerClosed under pendingMu — the same lock the pipe reader takes in
// failAllPending when the pipe dies — so it is a properly synchronized
// liveness signal (unlike a racy read of Cmd.ProcessState).
func (vp *VaultProcess) isAlive() bool {
	if vp.process == nil {
		return false
	}
	vp.pendingMu.Lock()
	defer vp.pendingMu.Unlock()
	return !vp.readerClosed
}

// PipeConn returns the subprocess pipe connection, or nil if the
// process isn't running. Used by handleEvictVault to forward a
// revoke_ownership message into the subprocess before killing it.
// PipeConnection.WriteMessage has a dedicated writeMu, so a write here
// is framing-safe even with concurrent writers (ProcessMessage, the
// pipe reader's sealer/http workers).
func (vp *VaultProcess) PipeConn() *PipeConnection {
	vp.mu.RLock()
	defer vp.mu.RUnlock()
	if vp.process == nil {
		return nil
	}
	return vp.process.Conn
}

// WaitIdle blocks until any in-flight ProcessMessage on this
// subprocess has returned, then returns immediately. Eviction calls
// this before killing the subprocess: killing it mid-op closes the
// pipe under ProcessMessage and fails the op. During a migration
// handoff the in-flight op IS the migration that emitted the
// routing_handoff which triggered the eviction — it must be allowed
// to finish and send its response. (The subprocess's tail-end
// vault_state flush is already fenced by the revoke_ownership message
// the evictor sends first, so letting the op complete is safe.)
func (vp *VaultProcess) WaitIdle() {
	// Acquiring then immediately releasing procMu waits out whatever
	// op currently holds it; ProcessMessage holds procMu for its whole
	// duration.
	vp.procMu.Lock()
	vp.procMu.Unlock() //nolint:staticcheck // intentional: barrier wait, not a guarded section
}

// newPipeID returns a fresh supervisor↔subprocess pipe-correlation
// token — the pipe-layer analog of newMuxID. 16 random bytes make a
// collision a 2^-128 event.
func newPipeID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure means the host RNG is gone — the process
		// is doomed anyway; a zero token avoids a panic in a hot path.
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// ProcessMessage writes an op to the vault-manager subprocess and
// blocks until the subprocess's response — correlated by a fresh
// PipeID and routed back by the persistent pipe reader — arrives, or
// the deadline / ctx fires.
//
// procMu is held for the whole call: ops for one user share a single
// subprocess that processes them serially, so the supervisor sends
// them one at a time. The pipe READER runs independently and always —
// that is what lets a between-ops sealer request (the persist) be
// serviced without stalling. Ops for other users use other
// VaultProcess instances and run fully in parallel.
func (vp *VaultProcess) ProcessMessage(ctx context.Context, msg *Message) (*Message, error) {
	procMuWaitStart := time.Now() // DIAG: measure per-user procMu contention
	vp.procMu.Lock()
	defer vp.procMu.Unlock()
	if waited := time.Since(procMuWaitStart); waited > 100*time.Millisecond { // DIAG
		log.Debug().
			Str("owner_space", vp.OwnerSpace).
			Dur("procmu_wait", waited).
			Msg("DIAG: ProcessMessage acquired procMu after contention")
	}

	vp.touch()

	conn := vp.PipeConn()
	if conn == nil {
		log.Error().
			Str("owner_space", vp.OwnerSpace).
			Msg("FATAL: No subprocess connection available")
		return nil, fmt.Errorf("process-based routing not available for owner %s", vp.OwnerSpace)
	}

	// Stamp a fresh pipe-correlation token. The subprocess echoes it on
	// the response; the persistent reader routes the response here by
	// it. RequestID is NOT usable for this — it is set inconsistently
	// across handlers (see Message.PipeID).
	pipeID := newPipeID()
	msg.PipeID = pipeID
	respCh := make(chan *Message, 1)

	vp.pendingMu.Lock()
	if vp.readerClosed {
		vp.pendingMu.Unlock()
		return nil, fmt.Errorf("vault-manager read error: subprocess pipe closed")
	}
	vp.pending[pipeID] = respCh
	vp.pendingMu.Unlock()

	// Always clear the pending entry — on response, timeout, ctx
	// cancel, or pipe loss — so a slow/abandoned op can't leak the map.
	defer func() {
		vp.pendingMu.Lock()
		delete(vp.pending, pipeID)
		vp.pendingMu.Unlock()
	}()

	writeStart := time.Now() // DIAG
	if err := conn.WriteMessage(msg); err != nil {
		log.Error().
			Err(err).
			Str("owner_space", vp.OwnerSpace).
			Msg("Failed to send message to vault-manager subprocess")
		return nil, fmt.Errorf("vault-manager send error: %w", err)
	}
	log.Debug(). // DIAG: op handed to the subprocess; the gap from here to
		// the response is in-subprocess time (covered by the vault-manager
		// watchdog); a long gap before here is supervisor-side.
		Str("owner_space", vp.OwnerSpace).
		Str("pipe_id", pipeID).
		Str("subject", msg.Subject).
		Dur("write_dur", time.Since(writeStart)).
		Msg("DIAG: ProcessMessage wrote op to subprocess; awaiting response")

	const opTimeout = 30 * time.Second
	select {
	case resp, ok := <-respCh:
		if !ok {
			// failAllPending closed the channel — the subprocess pipe
			// died while this op was in flight. "pipe closed" makes
			// handleVaultOp's isSubprocessGone retry on a fresh one.
			return nil, fmt.Errorf("vault-manager read error: subprocess pipe closed")
		}
		return resp, nil
	case <-time.After(opTimeout):
		log.Error().
			Str("owner_space", vp.OwnerSpace).
			Msg("Timeout waiting for vault-manager response")
		return nil, fmt.Errorf("vault-manager read error: timeout waiting for response")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startPipeReader launches the persistent goroutine that drains this
// subprocess's stdout pipe for the life of the subprocess. It is the
// single reader of the pipe; ProcessMessage no longer reads.
func (vp *VaultProcess) startPipeReader() {
	conn := vp.PipeConn()
	if conn == nil {
		log.Error().Str("owner_space", vp.OwnerSpace).
			Msg("startPipeReader: no subprocess connection")
		return
	}
	go func() {
		for {
			msg, err := conn.ReadMessage()
			if err != nil {
				vp.failAllPending(err)
				return
			}
			switch msg.Type {
			case MessageTypeSealerRequest:
				// Service off the reader goroutine so a slow S3/KMS
				// round-trip never blocks draining the pipe.
				go vp.handlePipeSealer(msg)
			case MessageTypeHTTPRequest:
				go vp.handlePipeHTTP(msg)
			case MessageTypeNATSPublish, MessageTypeRoutingHandoff,
				MessageTypeLog, MessageTypeAuditEvent:
				vp.forwardToParent(msg)
			default:
				// Op response/error — route to the waiting ProcessMessage.
				vp.deliverResponse(msg)
			}
		}
	}()
}

// deliverResponse routes an op response to the ProcessMessage waiting
// on its PipeID. A response with no waiter (the op already timed out
// or was cancelled, or a stale PipeID) is dropped — the old design's
// silent desync after a timeout is impossible here.
func (vp *VaultProcess) deliverResponse(msg *Message) {
	vp.pendingMu.Lock()
	ch, ok := vp.pending[msg.PipeID]
	if ok {
		delete(vp.pending, msg.PipeID)
	}
	vp.pendingMu.Unlock()

	if !ok {
		log.Warn().
			Str("owner_space", vp.OwnerSpace).
			Str("type", string(msg.Type)).
			Str("pipe_id", msg.PipeID).
			Msg("Pipe response with no pending op — dropping (timed-out / stale)")
		return
	}
	ch <- msg // respCh is buffered cap-1 — never blocks the reader
}

// failAllPending is called when the reader goroutine exits (the
// subprocess pipe is dead). It marks the VaultProcess closed and wakes
// every in-flight ProcessMessage by closing its response channel.
func (vp *VaultProcess) failAllPending(cause error) {
	vp.pendingMu.Lock()
	vp.readerClosed = true
	pending := vp.pending
	vp.pending = make(map[string]chan *Message)
	vp.pendingMu.Unlock()

	for _, ch := range pending {
		close(ch) // wakes ProcessMessage's select with ok=false
	}
	log.Info().
		Err(cause).
		Str("owner_space", vp.OwnerSpace).
		Int("failed_ops", len(pending)).
		Msg("Vault-manager pipe reader exited — failed in-flight ops")
}

// handlePipeSealer services a sealer (S3/KMS) request emitted by the
// subprocess and writes the response back down the pipe.
func (vp *VaultProcess) handlePipeSealer(msg *Message) {
	var resp *Message
	if vp.sealerHandler != nil {
		resp = vp.sealerHandler.HandleSealerRequest(msg)
	} else {
		log.Warn().Str("owner_space", vp.OwnerSpace).
			Msg("Sealer handler not configured, returning error")
		resp = &Message{
			RequestID: msg.RequestID,
			Type:      MessageTypeSealerResponse,
			Payload:   []byte(`{"success":false,"error":"sealer not available"}`),
		}
	}
	conn := vp.PipeConn()
	if conn == nil {
		return
	}
	if err := conn.WriteMessage(resp); err != nil {
		log.Error().
			Err(err).
			Str("owner_space", vp.OwnerSpace).
			Msg("Failed to send sealer response to vault-manager")
	}
}

// handlePipeHTTP services an HTTP-proxy request emitted by the
// subprocess and writes the response back down the pipe.
func (vp *VaultProcess) handlePipeHTTP(msg *Message) {
	var resp *Message
	if vp.sealerHandler != nil {
		resp = vp.sealerHandler.ForwardHTTPRequest(msg)
	} else {
		log.Warn().Str("owner_space", vp.OwnerSpace).
			Msg("Sealer handler not configured for HTTP proxy, returning error")
		resp = &Message{
			RequestID: msg.RequestID,
			Type:      MessageTypeHTTPResponse,
			Payload:   []byte(`{"error":"HTTP proxy not available"}`),
		}
	}
	conn := vp.PipeConn()
	if conn == nil {
		return
	}
	if err := conn.WriteMessage(resp); err != nil {
		log.Error().
			Err(err).
			Str("owner_space", vp.OwnerSpace).
			Msg("Failed to send HTTP response to vault-manager")
	}
}

// forwardToParent relays a subprocess-emitted nats_publish /
// routing_handoff / log / audit_event up to the parent.
func (vp *VaultProcess) forwardToParent(msg *Message) {
	if vp.parentSender == nil {
		return
	}
	if err := vp.parentSender.SendToParent(msg); err != nil {
		log.Warn().
			Err(err).
			Str("owner_space", vp.OwnerSpace).
			Str("type", string(msg.Type)).
			Msg("Failed to forward subprocess message to parent (non-fatal)")
	}
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
