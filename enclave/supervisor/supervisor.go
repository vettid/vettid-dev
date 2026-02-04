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
	memoryManager *MemoryManager
	sealer        *NitroSealer
	vsock         Listener

	// Active connection to parent (for sending vault-initiated messages)
	parentConn   Connection
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

	// Create sealer (connection will be set when parent connects)
	sealer := NewNitroSealer(nil)

	s := &Supervisor{
		config:          cfg,
		memoryManager:   memMgr,
		sealer:          sealer,
		attestationKeys: make(map[string]*AttestationKeyEntry),
	}

	// Create vault manager with reference to supervisor for outbound messages
	// Pass log forwarder to enable CloudWatch log streaming
	s.vaults = NewVaultManager(cfg, memMgr, s, sealer, s.SendLog)

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

	defer func() {
		authConn.Close()
		s.parentConnMu.Lock()
		s.parentConn = nil
		s.parentConnMu.Unlock()
		// Clear sealer connection
		s.sealer.SetConnection(nil)
		// Clear sealer handler connection (for S3 operations)
		s.vaults.SetParentConnection(nil)
	}()

	// SECURITY: Perform mutual authentication handshake before accepting any messages
	// The server side (enclave) doesn't verify PCRs (it IS the enclave)
	// PCR verification happens on the client side (parent verifying enclave)
	log.Debug().Str("conn_id", connID).Msg("Starting mutual authentication handshake")
	if err := authConn.PerformServerHandshake(nil); err != nil {
		log.Error().Err(err).Str("conn_id", connID).Msg("SECURITY: Handshake failed, rejecting connection")
		return
	}
	log.Info().Str("conn_id", connID).Msg("Mutual authentication successful")

	// Store authenticated connection for outbound messages from vaults
	s.parentConnMu.Lock()
	s.parentConn = authConn
	s.parentConnMu.Unlock()

	// Set connection for sealer (for KMS operations)
	s.sealer.SetConnection(authConn)

	// Set connection for sealer handler (for S3 storage operations)
	// This allows vault-manager processes to store/load data via the parent
	s.vaults.SetParentConnection(authConn)

	log.Debug().Msg("New authenticated connection from parent process")

	// Read messages in a loop
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read message from authenticated connection
		msg, err := authConn.ReadMessage()
		if err != nil {
			log.Debug().Err(err).Msg("Connection closed")
			return
		}

		// Process message
		response, err := s.processMessage(ctx, msg)
		if err != nil {
			log.Error().Err(err).Msg("Error processing message")
			response = &Message{
				Type:      MessageTypeError,
				RequestID: msg.RequestID,
				Error:     err.Error(),
			}
		}

		// Send response
		if response != nil {
			if err := authConn.WriteMessage(response); err != nil {
				log.Error().Err(err).Msg("Error writing response")
				return
			}
		}
	}
}

// SendToParent sends a message to the parent process (for vault-initiated messages)
func (s *Supervisor) SendToParent(msg *Message) error {
	s.parentConnMu.RLock()
	conn := s.parentConn
	s.parentConnMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("no parent connection available")
	}

	return conn.WriteMessage(msg)
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
	if prefix != "OwnerSpace" && prefix != "MessageSpace" {
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

	// Get or create vault for this owner
	vault, err := s.vaults.GetOrCreate(ctx, ownerSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault: %w", err)
	}

	// Forward message to vault
	return vault.ProcessMessage(ctx, msg)
}

// isPinOperation checks if a NATS subject is a PIN operation
func isPinOperation(subject string) bool {
	// Match: forVault.pin, forVault.pin-setup, forVault.pin-unlock, forVault.pin-change
	return strings.Contains(subject, "forVault.pin")
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
// This is fire-and-forget - we don't wait for a response.
func (s *Supervisor) SendLog(level, source, message string) {
	s.parentConnMu.RLock()
	conn := s.parentConn
	s.parentConnMu.RUnlock()

	if conn == nil {
		// No parent connection, can't forward logs
		return
	}

	msg := &Message{
		Type:       MessageTypeLog,
		LogLevel:   level,
		LogSource:  source,
		LogMessage: message,
	}

	// Fire and forget - don't block on log sending
	go func() {
		if err := conn.WriteMessage(msg); err != nil {
			// Can't log this error (would cause infinite loop), just ignore
			return
		}
	}()
}
