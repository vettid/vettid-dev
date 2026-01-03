package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
)

// ParentProcess bridges the enclave to external services
type ParentProcess struct {
	config      *Config
	natsClient  *NATSClient
	s3Client    *S3Client
	vsockClient *VsockClient
	healthSrv   *HealthServer
	mu          sync.RWMutex
}

// NewParentProcess creates a new parent process
func NewParentProcess(cfg *Config) (*ParentProcess, error) {
	return &ParentProcess{
		config: cfg,
	}, nil
}

// Run starts the parent process and blocks until context is cancelled
func (p *ParentProcess) Run(ctx context.Context) error {
	log.Info().Msg("Parent process starting")

	// Connect to NATS
	natsClient, err := NewNATSClient(p.config.NATS)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}
	p.natsClient = natsClient
	defer natsClient.Close()

	log.Info().Str("url", p.config.NATS.URL).Msg("Connected to NATS")

	// Create S3 client
	s3Client, err := NewS3Client(p.config.S3)
	if err != nil {
		return fmt.Errorf("failed to create S3 client: %w", err)
	}
	p.s3Client = s3Client

	log.Info().Str("bucket", p.config.S3.Bucket).Msg("S3 client initialized")

	// Connect to enclave via vsock
	vsockClient, err := NewVsockClient(p.config.Enclave, p.config.DevMode)
	if err != nil {
		return fmt.Errorf("failed to connect to enclave: %w", err)
	}
	p.vsockClient = vsockClient
	defer vsockClient.Close()

	log.Info().
		Uint32("cid", p.config.Enclave.CID).
		Uint32("port", p.config.Enclave.Port).
		Msg("Connected to enclave")

	// Start health server
	p.healthSrv = NewHealthServer(p.config.Health.Port)
	go p.healthSrv.Start()
	defer p.healthSrv.Stop()

	// Start message routing
	errChan := make(chan error, 2)

	// Route NATS → Enclave
	go func() {
		err := p.routeNATSToEnclave(ctx)
		if err != nil && ctx.Err() == nil {
			errChan <- fmt.Errorf("NATS→Enclave routing error: %w", err)
		}
	}()

	// Route Enclave → NATS/S3
	go func() {
		err := p.routeEnclaveToExternal(ctx)
		if err != nil && ctx.Err() == nil {
			errChan <- fmt.Errorf("Enclave→External routing error: %w", err)
		}
	}()

	// Wait for shutdown or error
	select {
	case <-ctx.Done():
		log.Info().Msg("Parent process shutting down")
		return nil
	case err := <-errChan:
		return err
	}
}

// routeNATSToEnclave subscribes to NATS topics and forwards messages to enclave
func (p *ParentProcess) routeNATSToEnclave(ctx context.Context) error {
	// Subscribe to vault-related topics
	// Namespace patterns:
	//   OwnerSpace.{guid}.forVault.> - Messages from mobile apps (includes call signaling)
	//   OwnerSpace.{guid}.control    - Control commands from admin
	//   OwnerSpace.{guid}.eventTypes - Event type queries
	//   MessageSpace.{guid}.forOwner.> - Connection messages
	//
	// Call signaling flows through OwnerSpace so the vault can:
	//   - Verify caller identity
	//   - Enforce block lists
	//   - Log call attempts

	msgChan := make(chan *NATSMessage, 100)

	// Subscribe to messages from mobile apps to vaults (includes call signaling)
	if err := p.natsClient.Subscribe("OwnerSpace.*.forVault.>", msgChan); err != nil {
		return fmt.Errorf("failed to subscribe to OwnerSpace.*.forVault.>: %w", err)
	}
	log.Debug().Str("subject", "OwnerSpace.*.forVault.>").Msg("Subscribed to NATS")

	// Subscribe to control commands
	if err := p.natsClient.Subscribe("OwnerSpace.*.control", msgChan); err != nil {
		return fmt.Errorf("failed to subscribe to OwnerSpace.*.control: %w", err)
	}
	log.Debug().Str("subject", "OwnerSpace.*.control").Msg("Subscribed to NATS")

	// Subscribe to event type queries
	if err := p.natsClient.Subscribe("OwnerSpace.*.eventTypes", msgChan); err != nil {
		return fmt.Errorf("failed to subscribe to OwnerSpace.*.eventTypes: %w", err)
	}
	log.Debug().Str("subject", "OwnerSpace.*.eventTypes").Msg("Subscribed to NATS")

	// Subscribe to connection messages
	if err := p.natsClient.Subscribe("MessageSpace.*.forOwner.>", msgChan); err != nil {
		return fmt.Errorf("failed to subscribe to MessageSpace.*.forOwner.>: %w", err)
	}
	log.Debug().Str("subject", "MessageSpace.*.forOwner.>").Msg("Subscribed to NATS")

	log.Info().Msg("Subscribed to OwnerSpace and MessageSpace topics")

	for {
		select {
		case <-ctx.Done():
			return nil
		case msg := <-msgChan:
			if err := p.forwardToEnclave(ctx, msg); err != nil {
				log.Error().Err(err).
					Str("subject", msg.Subject).
					Msg("Failed to forward message to enclave")
			}
		}
	}
}

// forwardToEnclave forwards a NATS message to the enclave
func (p *ParentProcess) forwardToEnclave(ctx context.Context, msg *NATSMessage) error {
	// Extract owner space from subject (vault.{user_guid}.{operation})
	ownerSpace, err := extractOwnerSpace(msg.Subject)
	if err != nil {
		return err
	}

	// Create enclave message
	enclaveMsg := &EnclaveMessage{
		Type:       EnclaveMessageTypeVaultOp,
		OwnerSpace: ownerSpace,
		Subject:    msg.Subject,
		Payload:    msg.Data,
		ReplyTo:    msg.Reply,
	}

	// Send to enclave
	response, err := p.vsockClient.SendMessage(ctx, enclaveMsg)
	if err != nil {
		return err
	}

	// If there's a reply address, send response back via NATS
	if msg.Reply != "" && response != nil {
		if err := p.natsClient.Publish(msg.Reply, response.Payload); err != nil {
			log.Error().Err(err).Str("reply", msg.Reply).Msg("Failed to publish reply")
		}
	}

	return nil
}

// routeEnclaveToExternal handles requests from enclave (storage, etc.)
func (p *ParentProcess) routeEnclaveToExternal(ctx context.Context) error {
	// The enclave sends storage requests through vsock
	// We handle them here and return responses

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Read message from enclave
		msg, err := p.vsockClient.ReceiveMessage(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Error receiving from enclave")
			continue
		}

		// Handle the message
		response, err := p.handleEnclaveRequest(ctx, msg)
		if err != nil {
			log.Error().Err(err).Str("type", string(msg.Type)).Msg("Error handling enclave request")
			response = &EnclaveMessage{
				Type:  EnclaveMessageTypeError,
				Error: err.Error(),
			}
		}

		// Send response back to enclave
		if err := p.vsockClient.SendResponse(response); err != nil {
			log.Error().Err(err).Msg("Error sending response to enclave")
		}
	}
}

// handleEnclaveRequest processes requests from the enclave
func (p *ParentProcess) handleEnclaveRequest(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	switch msg.Type {
	case EnclaveMessageTypeStorageGet:
		return p.handleStorageGet(ctx, msg)
	case EnclaveMessageTypeStoragePut:
		return p.handleStoragePut(ctx, msg)
	case EnclaveMessageTypeNATSPublish:
		return p.handleNATSPublish(ctx, msg)
	case EnclaveMessageTypeHealthCheck:
		return p.handleHealthCheck(ctx, msg)
	default:
		return nil, fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

// handleStorageGet retrieves data from S3
func (p *ParentProcess) handleStorageGet(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	key := p.config.S3.KeyPrefix + msg.StorageKey

	data, err := p.s3Client.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("S3 get failed: %w", err)
	}

	return &EnclaveMessage{
		Type:    EnclaveMessageTypeStorageResponse,
		Payload: data,
	}, nil
}

// handleStoragePut writes data to S3
func (p *ParentProcess) handleStoragePut(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	key := p.config.S3.KeyPrefix + msg.StorageKey

	if err := p.s3Client.Put(ctx, key, msg.Payload); err != nil {
		return nil, fmt.Errorf("S3 put failed: %w", err)
	}

	return &EnclaveMessage{
		Type: EnclaveMessageTypeStorageResponse,
	}, nil
}

// handleNATSPublish publishes a message to NATS
func (p *ParentProcess) handleNATSPublish(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	if err := p.natsClient.Publish(msg.Subject, msg.Payload); err != nil {
		return nil, fmt.Errorf("NATS publish failed: %w", err)
	}

	return &EnclaveMessage{
		Type: EnclaveMessageTypeOK,
	}, nil
}

// handleHealthCheck returns health status
func (p *ParentProcess) handleHealthCheck(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	status := p.getHealthStatus()

	return &EnclaveMessage{
		Type:    EnclaveMessageTypeHealthResponse,
		Payload: status,
	}, nil
}

// getHealthStatus returns the current health status
func (p *ParentProcess) getHealthStatus() []byte {
	// TODO: Implement proper health status
	return []byte(`{"status":"healthy"}`)
}

// extractOwnerSpace extracts the user GUID from a NATS subject
func extractOwnerSpace(subject string) (string, error) {
	// Expected formats:
	//   OwnerSpace.{guid}.forVault.{operation} - Messages from apps (includes calls)
	//   OwnerSpace.{guid}.control              - Control commands
	//   OwnerSpace.{guid}.eventTypes           - Event type queries
	//   MessageSpace.{guid}.forOwner.{operation} - Connection messages
	// The GUID is always at index 1
	parts := splitSubject(subject)
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid subject format: %s", subject)
	}

	// Validate prefix
	prefix := parts[0]
	if prefix != "OwnerSpace" && prefix != "MessageSpace" {
		return "", fmt.Errorf("unknown subject prefix: %s (expected OwnerSpace or MessageSpace)", prefix)
	}

	return parts[1], nil
}

// splitSubject splits a NATS subject into parts
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
