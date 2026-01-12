package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Supervisor manages vault-manager processes inside the Nitro Enclave.
// It receives messages from the parent process via vsock and routes them
// to the appropriate vault-manager process.
type Supervisor struct {
	config        *Config
	vaults        *VaultManager
	memoryManager *MemoryManager
	handlerCache  *HandlerCache
	sealer        *NitroSealer
	vsock         Listener

	// Active connection to parent (for sending vault-initiated messages)
	parentConn   Connection
	parentConnMu sync.RWMutex

	mu sync.RWMutex
}

// NewSupervisor creates a new enclave supervisor
func NewSupervisor(cfg *Config) (*Supervisor, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Create memory manager
	memMgr := NewMemoryManager(cfg.MaxMemoryMB, cfg.MaxVaults)

	// Create handler cache for shared WASM handlers
	handlerCache := NewHandlerCache()

	// Create sealer (connection will be set when parent connects)
	sealer := NewNitroSealer(nil)

	s := &Supervisor{
		config:        cfg,
		memoryManager: memMgr,
		handlerCache:  handlerCache,
		sealer:        sealer,
	}

	// Create vault manager with reference to supervisor for outbound messages
	s.vaults = NewVaultManager(cfg, memMgr, handlerCache, s, sealer)

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
		// Clear handler fetcher when connection is closed
		s.handlerCache.SetFetcher(nil)
		// Clear sealer connection
		s.sealer.SetConnection(nil)
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

	// Set up handler fetcher that uses this connection
	// This closure captures 'authConn' so handlers can be fetched during message processing
	s.handlerCache.SetFetcher(func(ctx context.Context, handlerID string) ([]byte, string, error) {
		return s.fetchHandlerFromParent(authConn, handlerID)
	})

	log.Debug().Msg("New authenticated connection from parent process, handler fetcher configured")

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

// fetchHandlerFromParent requests a handler from the parent process
// This is called during message processing when a handler is needed but not cached
func (s *Supervisor) fetchHandlerFromParent(conn Connection, handlerID string) ([]byte, string, error) {
	log.Debug().Str("handler_id", handlerID).Msg("Requesting handler from parent")

	// Send handler_get request
	request := &Message{
		Type:      MessageTypeHandlerGet,
		HandlerID: handlerID,
	}

	if err := conn.WriteMessage(request); err != nil {
		return nil, "", fmt.Errorf("failed to send handler request: %w", err)
	}

	// Read response (we're inside processMessage, so we own the connection read)
	response, err := conn.ReadMessage()
	if err != nil {
		return nil, "", fmt.Errorf("failed to read handler response: %w", err)
	}

	// Validate response
	if response.Type == MessageTypeError {
		return nil, "", fmt.Errorf("parent returned error: %s", response.Error)
	}

	if response.Type != MessageTypeHandlerResponse {
		return nil, "", fmt.Errorf("unexpected response type: %s", response.Type)
	}

	if len(response.Payload) == 0 {
		return nil, "", fmt.Errorf("parent returned empty handler")
	}

	log.Info().
		Str("handler_id", handlerID).
		Str("version", response.HandlerVersion).
		Int("size", len(response.Payload)).
		Msg("Handler received from parent")

	return response.Payload, response.HandlerVersion, nil
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

	// Get or create vault for this owner
	vault, err := s.vaults.GetOrCreate(ctx, ownerSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault: %w", err)
	}

	// Forward message to vault
	return vault.ProcessMessage(ctx, msg)
}

// handleAttestationRequest generates an attestation document
func (s *Supervisor) handleAttestationRequest(ctx context.Context, msg *Message) (*Message, error) {
	// In a real Nitro enclave, this would call the Nitro attestation API
	// For now, return a placeholder
	attestation, err := GenerateAttestation(msg.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %w", err)
	}

	return &Message{
		Type:        MessageTypeAttestationResponse,
		Attestation: attestation,
	}, nil
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
