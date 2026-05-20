package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// AttestationKeyEntry stores an X25519 private key for PIN decryption
// SECURITY: Keys are ephemeral and expire after attestation validity period
type AttestationKeyEntry struct {
	PrivateKey []byte    // X25519 private key (32 bytes)
	ExpiresAt  time.Time // When this key expires
}

// Supervisor manages vault-manager processes inside the Nitro Enclave.
// It receives messages from the parent process via vsock and routes them
// to the appropriate vault-manager process.
type Supervisor struct {
	config        *Config
	vaults        *VaultManager
	orgVaults     *OrgVaultManager // Org vault manager for OrgSpace.* subjects
	memoryManager *MemoryManager
	sealer        *NitroSealer
	vsock         Listener

	// Multiplexed transport to the parent. The single I/O goroutine
	// inside MuxConn owns the fd; vault ops for different users overlap
	// instead of serializing through one read loop. Used for both the
	// inbound request path and vault-initiated sends (nats_publish,
	// audit_event, log forwarding).
	parentMux    *MuxConn
	parentConnMu sync.RWMutex

	// Attestation private keys for PIN decryption
	// SECURITY: Keys are ephemeral X25519 keys, one per attestation request
	// They are used to decrypt PINs encrypted by clients using the attestation public key
	attestationKeys   map[string]*AttestationKeyEntry
	attestationKeysMu sync.RWMutex

	mu sync.RWMutex
}

// NewSupervisor creates a new enclave supervisor
func NewSupervisor(cfg *Config) (*Supervisor, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Create memory manager
	memMgr := NewMemoryManager(cfg.MaxMemoryMB, cfg.MaxVaults)

	// Create sealer (parent transport is wired when the parent connects)
	sealer := NewNitroSealer()

	s := &Supervisor{
		config:          cfg,
		memoryManager:   memMgr,
		sealer:          sealer,
		attestationKeys: make(map[string]*AttestationKeyEntry),
	}

	// Create vault manager with reference to supervisor for outbound messages
	// Pass log forwarder to enable CloudWatch log streaming
	s.vaults = NewVaultManager(cfg, memMgr, s, sealer, s.SendLog)

	// Create org vault manager for OrgSpace.* subjects
	s.orgVaults = NewOrgVaultManager(cfg, memMgr, s, sealer, s.SendLog)

	return s, nil
}

// Run starts the supervisor and blocks until the context is cancelled
func (s *Supervisor) Run(ctx context.Context) error {
	// Create vsock listener
	var err error
	if s.config.DevMode {
		s.vsock, err = NewTCPListener(s.config.TCPPort)
	} else {
		s.vsock, err = NewVsockListener(s.config.VsockPort)
	}
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	defer s.vsock.Close()

	log.Info().
		Bool("dev_mode", s.config.DevMode).
		Uint32("port", s.config.VsockPort).
		Msg("Supervisor listening")

	// Accept connections in a loop
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Supervisor shutting down")
			s.shutdown()
			return nil
		default:
		}

		conn, err := s.vsock.Accept()
		if err != nil {
			log.Error().Err(err).Msg("Accept error")
			continue
		}

		// Handle connection in goroutine
		go s.handleConnection(ctx, conn)
	}
}

// handleConnection processes messages from a vsock connection
// SECURITY: All connections must complete mutual authentication before processing messages
func (s *Supervisor) handleConnection(ctx context.Context, rawConn Connection) {
	// Generate a connection ID for rate limiting
	connID := fmt.Sprintf("conn-%d", time.Now().UnixNano())

	// SECURITY: Wrap connection with authentication
	authConn := NewAuthenticatedConnection(rawConn, connID)
	defer authConn.Close()

	// SECURITY: Perform mutual authentication handshake before accepting any messages
	// The server side (enclave) doesn't verify PCRs (it IS the enclave)
	// PCR verification happens on the client side (parent verifying enclave)
	log.Debug().Str("conn_id", connID).Msg("Starting mutual authentication handshake")
	if err := authConn.PerformServerHandshake(nil); err != nil {
		log.Error().Err(err).Str("conn_id", connID).Msg("SECURITY: Handshake failed, rejecting connection")
		return
	}
	log.Info().Str("conn_id", connID).Msg("Mutual authentication successful")

	// Post-handshake the multiplexed transport takes exclusive
	// ownership of the fd. MuxConn's single I/O goroutine does every
	// read and write, so concurrent vault ops never trigger the Nitro
	// vsock concurrent-read/write corruption — and they overlap
	// instead of funnelling through one serial loop.
	mux := NewMuxConn(authConn.RawConn())

	s.parentConnMu.Lock()
	s.parentMux = mux
	s.parentConnMu.Unlock()
	s.sealer.SetMux(mux)
	s.vaults.SetMux(mux)
	if s.orgVaults != nil {
		s.orgVaults.SetMux(mux)
	}

	defer func() {
		s.parentConnMu.Lock()
		s.parentMux = nil
		s.parentConnMu.Unlock()
		s.sealer.SetMux(nil)
		s.vaults.SetMux(nil)
		if s.orgVaults != nil {
			s.orgVaults.SetMux(nil)
		}
	}()

	// Closing the connection on ctx cancel unblocks the mux reader so
	// a supervisor shutdown is graceful instead of hanging on a read.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			authConn.Close()
		case <-stop:
		}
	}()

	log.Debug().Msg("New authenticated connection from parent process")

	// Run the single reader. Each peer-initiated request is handed to
	// its own goroutine so the reader never blocks on op processing
	// (including nested S3/KMS round-trips) — that is the whole point
	// of the multiplex.
	mux.Run(func(msg *Message) {
		go s.handleMuxRequest(ctx, mux, msg)
	})
	log.Debug().Str("conn_id", connID).Msg("Parent connection closed")
}

// handleMuxRequest processes one parent-initiated request on its own
// goroutine and writes the response back through the mux, echoing the
// transport MuxID so the parent's demux routes it to the right waiter.
func (s *Supervisor) handleMuxRequest(ctx context.Context, mux *MuxConn, msg *Message) {
	response, err := s.processMessage(ctx, msg)
	if err != nil {
		log.Error().Err(err).Str("type", string(msg.Type)).Msg("Error processing message")
		response = &Message{
			Type:      MessageTypeError,
			RequestID: msg.RequestID,
			Error:     err.Error(),
		}
	}
	if response == nil {
		// Fire-and-forget request (evict_vault) or a stray storage/KMS
		// response with no matching pending entry — nothing to send.
		return
	}
	response.MuxID = msg.MuxID
	if response.RequestID == "" {
		response.RequestID = msg.RequestID
	}
	if err := mux.Send(response); err != nil {
		log.Error().Err(err).Str("type", string(response.Type)).Msg("mux: failed to send response")
	}
}

// SendToParent sends a message to the parent process (for vault-initiated messages)
func (s *Supervisor) SendToParent(msg *Message) error {
	s.parentConnMu.RLock()
	mux := s.parentMux
	s.parentConnMu.RUnlock()

	if mux == nil {
		return fmt.Errorf("no parent connection available")
	}

	return mux.Send(msg)
}

// processMessage routes a message to the appropriate handler
func (s *Supervisor) processMessage(ctx context.Context, msg *Message) (*Message, error) {
	log.Debug().
		Str("type", string(msg.Type)).
		Str("owner_space", msg.OwnerSpace).
		Str("subject", msg.Subject).
		Msg("Processing message")

	switch msg.Type {
	case MessageTypeVaultOp:
		return s.handleVaultOp(ctx, msg)

	case MessageTypeAttestationRequest:
		return s.handleAttestationRequest(ctx, msg)

	case MessageTypeHealthCheck:
		return s.handleHealthCheck(ctx, msg)

	case MessageTypeEvictVault:
		return s.handleEvictVault(ctx, msg)

	case MessageTypeStorageResponse:
		// Storage responses should be handled by the sealer handler's synchronous S3 operations.
		// If we receive one here, it means there was a race condition or message ordering issue.
		// Log a warning and return nil to avoid propagating an error.
		// The client should retry the operation.
		log.Warn().
			Str("type", string(msg.Type)).
			Str("request_id", msg.RequestID).
			Msg("Received storage_response in main loop - possible race condition with sealer handler")
		return nil, nil

	case MessageTypeKMSResponse:
		// Similar to storage_response - KMS responses should be handled by the sealer.
		log.Warn().
			Str("type", string(msg.Type)).
			Str("request_id", msg.RequestID).
			Msg("Received KMS response in main loop - possible race condition with sealer")
		return nil, nil

	default:
		return nil, fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

// extractOwnerSpaceFromSubject extracts the owner GUID from a NATS subject
// Expected formats:
//   - OwnerSpace.{guid}.forVault.{operation...}
//   - MessageSpace.{guid}.forOwner.{operation...}
func extractOwnerSpaceFromSubject(subject string) (string, error) {
	parts := splitSubject(subject)
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid subject format: %s", subject)
	}

	prefix := parts[0]
	if prefix != "OwnerSpace" && prefix != "MessageSpace" && prefix != "OrgSpace" {
		return "", fmt.Errorf("unknown subject prefix: %s", prefix)
	}

	return parts[1], nil
}

// splitSubject splits a NATS subject by dots
func splitSubject(subject string) []string {
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

// handleVaultOp routes a vault operation to the appropriate vault-manager
// The ownerSpace is extracted from the NATS subject if not explicitly provided
func (s *Supervisor) handleVaultOp(ctx context.Context, msg *Message) (*Message, error) {
	// DEBUG: Log incoming vault operation for tracing
	log.Info().
		Str("subject", msg.Subject).
		Str("owner_space", msg.OwnerSpace).
		Str("request_id", msg.RequestID).
		Int("payload_len", len(msg.Payload)).
		Msg("DEBUG: handleVaultOp received message")

	ownerSpace := msg.OwnerSpace

	// Extract ownerSpace from subject if not provided
	if ownerSpace == "" && msg.Subject != "" {
		var err error
		ownerSpace, err = extractOwnerSpaceFromSubject(msg.Subject)
		if err != nil {
			return nil, fmt.Errorf("failed to extract owner space: %w", err)
		}
		msg.OwnerSpace = ownerSpace
	}

	if ownerSpace == "" {
		return nil, fmt.Errorf("owner_space required for vault operation")
	}

	// Harness-only: simulate real S3/KMS round-trip latency so the
	// Tier-2 concurrent-load scenario can measure serial vs concurrent
	// throughput. No-op in production builds.
	harnessOpLatency()

	// For PIN operations, include the attestation private key
	// The mobile app encrypts PIN with the attestation public key
	if isPinOperation(msg.Subject) {
		// DEBUG: Log PIN operation details
		s.attestationKeysMu.RLock()
		keyCount := len(s.attestationKeys)
		var storedKeys []string
		for k := range s.attestationKeys {
			storedKeys = append(storedKeys, k[:8]+"...")
		}
		s.attestationKeysMu.RUnlock()

		log.Info().
			Str("owner_space", ownerSpace).
			Int("stored_keys", keyCount).
			Strs("key_prefixes", storedKeys).
			Msg("DEBUG: PIN operation - checking attestation key")

		attestationKey := s.getAttestationKey(ownerSpace)
		if attestationKey != nil {
			msg.AttestationPrivateKey = attestationKey
			log.Info().
				Str("owner_space", ownerSpace).
				Int("key_len", len(attestationKey)).
				Msg("DEBUG: Found attestation key for PIN operation")
		} else {
			log.Warn().
				Str("owner_space", ownerSpace).
				Int("stored_keys", keyCount).
				Msg("DEBUG: No attestation key found for PIN operation")
		}
	}

	// Route based on subject prefix: OrgSpace goes to org vault manager
	if msg.Subject != "" && strings.HasPrefix(msg.Subject, "OrgSpace.") {
		if s.orgVaults == nil {
			return nil, fmt.Errorf("org vault manager not available")
		}
		vault, err := s.orgVaults.GetOrCreate(ctx, ownerSpace)
		if err != nil {
			return nil, fmt.Errorf("failed to get org vault: %w", err)
		}
		return vault.ProcessMessage(ctx, msg)
	}

	// Get or create vault for this owner (user vaults), then forward
	// the message — with one retry if the subprocess turns out to be
	// gone. A vault-manager subprocess that self-evicted (D3
	// split-brain self-heal) or was evicted on a routing reclaim can
	// leave a stale pipe; the first send then fails with
	// "file already closed" / "pipe closed: EOF". Evicting and
	// respawning gives a fresh subprocess that cold-loads current S3
	// state, and the op runs cleanly. The initial write is the safe
	// retry point — if it failed the subprocess never saw the
	// message, so the op hasn't half-executed.
	vault, err := s.vaults.GetOrCreate(ctx, ownerSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault: %w", err)
	}
	resp, err := vault.ProcessMessage(ctx, msg)
	if err != nil && isSubprocessGone(err) {
		log.Warn().
			Err(err).
			Str("owner_space", ownerSpace).
			Msg("vault subprocess gone — evicting and retrying op once on a fresh subprocess")
		s.vaults.Evict(ownerSpace)
		vault, err = s.vaults.GetOrCreate(ctx, ownerSpace)
		if err != nil {
			return nil, fmt.Errorf("failed to respawn vault after subprocess loss: %w", err)
		}
		resp, err = vault.ProcessMessage(ctx, msg)
	} else if err != nil && isVaultProcessWedged(err) {
		// Read timeout: the subprocess accepted the op but produced
		// nothing within its 30s deadline — it is wedged on something
		// internal, not merely slow (a vault op is reads plus small
		// writes; >30s is never legitimate). Evict it so the NEXT op
		// for this user spawns a fresh subprocess that cold-loads
		// current S3 state, instead of every subsequent op piling onto
		// the same wedged subprocess and timing out in turn — the
		// 2026-05-20 ~2-minute cascade behind the device-approval
		// timeouts. The op is NOT retried here: a read timeout cannot
		// prove the subprocess didn't already half-apply a mutating
		// op, so an auto-retry could double-run it. The client
		// re-issues against the fresh subprocess.
		log.Warn().
			Err(err).
			Str("owner_space", ownerSpace).
			Msg("vault subprocess wedged (op read timeout) — evicting so the next op gets a fresh subprocess")
		s.vaults.Evict(ownerSpace)
	}
	return resp, err
}

// isVaultProcessWedged reports whether err is a ProcessMessage read
// timeout — the subprocess accepted an op but produced nothing within
// the deadline. Unlike isSubprocessGone (a dead pipe), the subprocess
// is alive but stuck, so it must be evicted; the op must NOT be
// auto-retried, since a read timeout cannot prove a mutating op did
// not half-apply.
func isVaultProcessWedged(err error) bool {
	return err != nil && strings.Contains(err.Error(), "read timeout")
}

// isSubprocessGone reports whether err indicates the vault-manager
// subprocess pipe is dead — the subprocess exited (D3 self-eviction,
// reclaim eviction, or a crash). Matches the concrete dead-pipe
// signatures only, NOT the broad "vault-manager read error" wrapper
// (which can also wrap a benign read timeout — retrying that could
// double-run an op). The observed migration-window errors —
// "failed to write length prefix: ... file already closed" and
// "vault-manager read error: pipe closed: EOF" — are both caught by
// the substring set below.
func isSubprocessGone(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "file already closed") ||
		strings.Contains(s, "pipe closed") ||
		strings.Contains(s, "broken pipe")
}

// isPinOperation checks if a NATS subject is a PIN operation
func isPinOperation(subject string) bool {
	// Match: forVault.pin, forVault.pin-setup, forVault.pin-unlock, forVault.pin-change
	return strings.Contains(subject, "forVault.pin")
}

// handleEvictVault kills the warm vault-manager subprocess for a user
// whose routing claim the parent just lost (handoff / reclaim / lease
// loss). This is the load-bearing half of the split-brain fix (D1):
// without eviction, OLD keeps a warm subprocess that serves requests
// and force-flushes a stale vault_state.enc, racing NEW for the same
// S3 key.
//
// Before the kill we forward a revoke_ownership message into the
// subprocess pipe (D2). The subprocess's own receive goroutine reads
// that independently of the supervisor's request loop, so it can set
// its ownershipRevoked flag even while a request is in flight — the
// flag suppresses that request's tail-end force-flush. The kill then
// drops the warm state entirely.
//
// Fire-and-forget from the parent's side: returns nil, nil so the
// supervisor loop writes no response.
func (s *Supervisor) handleEvictVault(ctx context.Context, msg *Message) (*Message, error) {
	ownerSpace := msg.OwnerSpace
	if ownerSpace == "" {
		log.Warn().Msg("evict_vault: missing owner_space — ignoring")
		return nil, nil
	}

	// D2: signal the warm subprocess to stop persisting BEFORE we kill
	// it, so an in-flight request's tail-end flush is suppressed. The
	// subprocess pipe has a dedicated writeMu (separate from readMu),
	// so this write is framing-safe even mid-request. Best-effort —
	// the kill below is the hard guarantee.
	if vp := s.vaults.Get(ownerSpace); vp != nil {
		if conn := vp.PipeConn(); conn != nil {
			if err := conn.WriteMessage(&Message{
				Type:       MessageTypeRevokeOwnership,
				OwnerSpace: ownerSpace,
			}); err != nil {
				log.Warn().Err(err).Str("owner_space", ownerSpace).
					Msg("evict_vault: failed to forward revoke_ownership to subprocess (proceeding to evict)")
			} else {
				log.Info().Str("owner_space", ownerSpace).
					Msg("evict_vault: forwarded revoke_ownership to subprocess")
			}
		}
		// Wait for any in-flight op to finish before the kill below.
		// Killing mid-op closes the subprocess pipe under
		// ProcessMessage; during a migration handoff the in-flight op
		// is the migration that triggered this eviction and must be
		// allowed to send its response. The revoke_ownership above has
		// already fenced its tail-end flush. (Before this, the faster
		// multiplexed transport delivered evict_vault mid-op and broke
		// migration-handoff — 2026-05-20.)
		vp.WaitIdle()
	}

	// D1: kill the subprocess. Idempotent — Evict/evictVault no-ops if
	// the vault isn't resident, so a double release (heartbeat CAS-fail
	// then a watcher event for the same user) is harmless.
	s.vaults.Evict(ownerSpace)
	// Migration handoff is user-vault-scoped; org vaults are not part
	// of the per-user routing model, so they are intentionally not
	// evicted here.
	log.Info().Str("owner_space", ownerSpace).
		Msg("evict_vault: evicted vault subprocess on routing-claim loss")
	return nil, nil
}

// handleAttestationRequest generates an attestation document
// SECURITY: Stores the ephemeral X25519 private key for later PIN decryption
func (s *Supervisor) handleAttestationRequest(ctx context.Context, msg *Message) (*Message, error) {
	// DEBUG: Log attestation request
	log.Info().
		Str("owner_space", msg.OwnerSpace).
		Str("subject", msg.Subject).
		Int("nonce_len", len(msg.Nonce)).
		Msg("DEBUG: handleAttestationRequest received")

	// Generate attestation with ephemeral X25519 keypair
	attestation, err := GenerateAttestation(msg.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %w", err)
	}

	// Store the private key for later PIN decryption
	// SECURITY: Key is stored per owner_space and expires with attestation validity
	if msg.OwnerSpace != "" && len(attestation.PrivateKey) > 0 {
		s.storeAttestationKey(msg.OwnerSpace, attestation.PrivateKey)
		log.Info().
			Str("owner_space", msg.OwnerSpace).
			Int("pubkey_len", len(attestation.PublicKey)).
			Int("privkey_len", len(attestation.PrivateKey)).
			Msg("DEBUG: Stored attestation private key for PIN decryption")
	} else {
		log.Warn().
			Str("owner_space", msg.OwnerSpace).
			Bool("has_owner_space", msg.OwnerSpace != "").
			Int("privkey_len", len(attestation.PrivateKey)).
			Msg("DEBUG: NOT storing attestation key - missing owner_space or private key")
	}

	// Clear private key from response (never sent outside enclave)
	// Note: The Attestation struct has json:"-" on PrivateKey, but we clear it anyway
	responsAttestation := &Attestation{
		Document:  attestation.Document,
		PublicKey: attestation.PublicKey,
		// PrivateKey intentionally not copied
	}

	return &Message{
		Type:        MessageTypeAttestationResponse,
		Attestation: responsAttestation,
	}, nil
}

// storeAttestationKey stores an X25519 private key for later PIN decryption
// SECURITY: Keys expire after maxAttestationAgeSeconds (5 minutes)
func (s *Supervisor) storeAttestationKey(ownerSpace string, privateKey []byte) {
	s.attestationKeysMu.Lock()
	defer s.attestationKeysMu.Unlock()

	// Store with expiry time
	s.attestationKeys[ownerSpace] = &AttestationKeyEntry{
		PrivateKey: privateKey,
		ExpiresAt:  time.Now().Add(time.Duration(maxAttestationAgeSeconds) * time.Second),
	}

	// Cleanup expired keys (opportunistic)
	s.cleanupExpiredKeysLocked()
}

// getAttestationKey retrieves the X25519 private key for PIN decryption
// Returns nil if no key exists or if it has expired
func (s *Supervisor) getAttestationKey(ownerSpace string) []byte {
	s.attestationKeysMu.RLock()
	defer s.attestationKeysMu.RUnlock()

	entry, exists := s.attestationKeys[ownerSpace]
	if !exists {
		return nil
	}

	// Check expiry
	if time.Now().After(entry.ExpiresAt) {
		return nil
	}

	return entry.PrivateKey
}

// cleanupExpiredKeysLocked removes expired attestation keys
// MUST be called with attestationKeysMu held
func (s *Supervisor) cleanupExpiredKeysLocked() {
	now := time.Now()
	for ownerSpace, entry := range s.attestationKeys {
		if now.After(entry.ExpiresAt) {
			// SECURITY: Zero the key before removal
			for i := range entry.PrivateKey {
				entry.PrivateKey[i] = 0
			}
			delete(s.attestationKeys, ownerSpace)
		}
	}
}

// handleHealthCheck returns supervisor health status
func (s *Supervisor) handleHealthCheck(ctx context.Context, msg *Message) (*Message, error) {
	stats := s.vaults.GetStats()
	memStats := s.memoryManager.GetStats()

	health := &HealthStatus{
		Healthy:        true,
		ActiveVaults:   stats.ActiveVaults,
		TotalVaults:    stats.TotalVaults,
		MemoryUsedMB:   memStats.UsedMB,
		MemoryTotalMB:  memStats.TotalMB,
		UptimeSeconds:  stats.UptimeSeconds,
		Version:        Version,
	}

	healthJSON, err := json.Marshal(health)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal health: %w", err)
	}

	return &Message{
		Type:    MessageTypeHealthResponse,
		Payload: healthJSON,
	}, nil
}

// shutdown gracefully stops all vaults
func (s *Supervisor) shutdown() {
	log.Info().Msg("Shutting down all vaults")
	s.vaults.ShutdownAll()
}

// SendLog sends a log message to the parent for CloudWatch forwarding.
// This is fire-and-forget - we don't wait for a response. mux.Send only
// enqueues the frame for the I/O goroutine, so it does not block on a
// socket write.
func (s *Supervisor) SendLog(level, source, message string) {
	s.parentConnMu.RLock()
	mux := s.parentMux
	s.parentConnMu.RUnlock()

	if mux == nil {
		// No parent connection, can't forward logs
		return
	}

	// Best-effort: a send error here can't itself be logged (infinite
	// loop), so it is intentionally dropped.
	_ = mux.Send(&Message{
		Type:       MessageTypeLog,
		LogLevel:   level,
		LogSource:  source,
		LogMessage: message,
	})
}
