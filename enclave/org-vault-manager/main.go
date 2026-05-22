// Package main implements the Org Vault Manager for VettID Nitro Enclave.
// Each org-vault-manager process handles a single organization's vault.
//
// Key differences from user vaults and service vaults:
// - Holds organizational secrets (DB credentials, API keys, certificates)
// - Proxies operations using stored credentials (credentials never leave enclave)
// - Per-operator connections provide cryptographic identity for audit attribution
// - Structured HIPAA-compliant audit trail for every credential access
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Version is set at build time
var Version = "dev"

func main() {
	ownerSpace := flag.String("owner-space", "", "Owner space (org vault GUID)")
	devMode := flag.Bool("dev-mode", false, "Run in development mode")
	flag.Parse()

	if *ownerSpace == "" {
		fmt.Fprintln(os.Stderr, "Error: --owner-space is required")
		os.Exit(1)
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().
		Str("org_space", *ownerSpace).
		Logger()

	log.Info().
		Str("version", Version).
		Bool("dev_mode", *devMode).
		Msg("Org Vault Manager starting")

	cfg := &OrgVaultConfig{
		OwnerSpace: *ownerSpace,
		DevMode:    *devMode,
	}

	vault, err := NewOrgVaultManager(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create org vault manager")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
	}()

	if err := vault.Run(ctx); err != nil {
		log.Fatal().Err(err).Msg("Org vault manager error")
	}

	vault.SecureShutdown()
	log.Info().Msg("Org vault manager shutdown complete")
}

// OrgVaultConfig holds configuration for the org vault manager.
type OrgVaultConfig struct {
	OwnerSpace string
	DevMode    bool
}

// OrgVaultManager handles a single organization's vault operations.
type OrgVaultManager struct {
	config         *OrgVaultConfig
	storage        *EncryptedStorage
	messageHandler *MessageHandler
	parentConn     *ParentConnection
}

// NewOrgVaultManager creates a new org vault manager.
func NewOrgVaultManager(cfg *OrgVaultConfig) (*OrgVaultManager, error) {
	storage, err := NewEncryptedStorage(cfg.OwnerSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	ovm := &OrgVaultManager{
		config:     cfg,
		storage:    storage,
		parentConn: NewParentConnection(),
	}

	ovm.messageHandler = NewMessageHandler(cfg.OwnerSpace, storage, ovm.sendToParent)

	return ovm, nil
}

// Run starts the org vault manager and processes messages.
// The message loop intercepts HTTP responses and audit events before
// they reach HandleMessage, routing them to the appropriate channels.
// This mirrors the vault-manager's async pattern for HTTP proxy operations.
func (ovm *OrgVaultManager) Run(ctx context.Context) error {
	log.Info().Str("org_space", ovm.config.OwnerSpace).Msg("Org vault manager running")

	if err := ovm.messageHandler.Initialize(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to initialize message handler (continuing)")
	}

	msgChan := make(chan *IncomingMessage, 10)
	go ovm.receiveMessages(ctx, msgChan)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Org vault manager shutting down")
			return nil
		case msg := <-msgChan:
			// IMPORTANT: Intercept HTTP responses before HandleMessage.
			// HTTP proxy is async — the credential proxy sends an HTTP request
			// and waits on a channel. The response comes back as a separate message
			// that must be routed to the proxy's response channel, not to HandleMessage.
			if msg.Type == MessageTypeHTTPResponse {
				if ovm.messageHandler.httpProxy != nil && ovm.messageHandler.httpProxy.responseCh != nil {
					ovm.messageHandler.httpProxy.responseCh <- msg
				} else {
					log.Warn().Msg("Received HTTP response but no proxy waiting")
				}
				continue
			}

			response, err := ovm.messageHandler.HandleMessage(ctx, msg)
			if err != nil {
				log.Error().Err(err).Str("msg_id", msg.GetID()).Msg("Error handling message")
				response = &OutgoingMessage{
					RequestID: msg.GetID(),
					Type:      MessageTypeError,
					Error:     err.Error(),
				}
			}
			// Every op the supervisor writes is awaited by a
			// ProcessMessage call that holds the per-vault procMu until
			// a response carrying the op's PipeID comes back. Always
			// send one: synthesize a minimal ack when a handler returns
			// (nil, nil), and echo msg.PipeID so the supervisor's pipe
			// reader routes it to the waiting op. Without this an
			// org-vault op stalls ProcessMessage for its full 30s
			// opTimeout, holding procMu (same class as the 2026-05-22
			// user-vault device-approval stall).
			if response == nil {
				response = &OutgoingMessage{
					RequestID: msg.GetID(),
					Type:      MessageTypeResponse,
					Payload:   json.RawMessage(`{"success":true}`),
				}
			}
			response.PipeID = msg.PipeID
			if err := ovm.sendToParent(response); err != nil {
				log.Error().Err(err).Msg("Failed to send response")
			}
		}
	}
}

// receiveMessages reads messages from the supervisor.
func (ovm *OrgVaultManager) receiveMessages(ctx context.Context, msgChan chan<- *IncomingMessage) {
	log.Debug().Msg("Message receiver started")

	for {
		select {
		case <-ctx.Done():
			return
		default:
			msg, err := ovm.parentConn.ReadMessage()
			if err != nil {
				log.Error().Err(err).Msg("Failed to read message from supervisor")
				return
			}

			select {
			case msgChan <- msg:
			case <-ctx.Done():
				return
			}
		}
	}
}

// sendToParent sends a message to the supervisor.
func (ovm *OrgVaultManager) sendToParent(msg *OutgoingMessage) error {
	return ovm.parentConn.WriteMessage(msg)
}

// SecureShutdown zeros all sensitive data.
func (ovm *OrgVaultManager) SecureShutdown() {
	log.Info().Msg("Performing secure shutdown")
	if ovm.messageHandler != nil {
		ovm.messageHandler.SecureErase()
	}
	if ovm.storage != nil {
		ovm.storage.SecureErase()
	}
	if ovm.parentConn != nil {
		ovm.parentConn.Close()
	}
	log.Info().Msg("Secure shutdown complete")
}
