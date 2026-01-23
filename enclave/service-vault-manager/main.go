// Package main implements the Service Vault Manager for VettID Nitro Enclave.
// Each service-vault-manager process handles a single service's vault operations.
//
// Key difference from user vaults:
// - Services can request data from users but cannot cache it
// - Services publish their contracts and profiles
// - Users connect to services, not vice versa
package main

import (
	"context"
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
	// Parse command line flags
	ownerSpace := flag.String("owner-space", "", "Owner space (service GUID) for this service vault")
	parentFD := flag.Int("parent-fd", 0, "File descriptor for parent communication")
	devMode := flag.Bool("dev-mode", false, "Run in development mode")
	flag.Parse()

	if *ownerSpace == "" {
		fmt.Fprintln(os.Stderr, "Error: --owner-space is required")
		os.Exit(1)
	}

	// Configure logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().
		Str("service_space", *ownerSpace).
		Logger()

	log.Info().
		Str("version", Version).
		Bool("dev_mode", *devMode).
		Msg("Service Vault Manager starting")

	// Create service vault manager
	cfg := &ServiceVaultConfig{
		OwnerSpace: *ownerSpace,
		ParentFD:   *parentFD,
		DevMode:    *devMode,
	}

	vault, err := NewServiceVaultManager(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create service vault manager")
	}

	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
	}()

	// Run service vault manager (blocks until context is cancelled)
	if err := vault.Run(ctx); err != nil {
		log.Fatal().Err(err).Msg("Service vault manager error")
	}

	// Secure cleanup
	vault.SecureShutdown()

	log.Info().Msg("Service vault manager shutdown complete")
}

// ServiceVaultConfig holds the service vault manager configuration
type ServiceVaultConfig struct {
	OwnerSpace string // Service GUID
	ParentFD   int
	DevMode    bool
}

// ServiceVaultManager handles a single service's vault operations
type ServiceVaultManager struct {
	config         *ServiceVaultConfig
	storage        *EncryptedStorage
	messageHandler *MessageHandler
	parentConn     *ParentConnection
}

// NewServiceVaultManager creates a new service vault manager
func NewServiceVaultManager(cfg *ServiceVaultConfig) (*ServiceVaultManager, error) {
	// Create encrypted storage adapter
	storage, err := NewEncryptedStorage(cfg.OwnerSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	svm := &ServiceVaultManager{
		config:     cfg,
		storage:    storage,
		parentConn: NewParentConnection(),
	}

	// Create message handler
	svm.messageHandler = NewMessageHandler(cfg.OwnerSpace, storage, svm.sendToParent)

	return svm, nil
}

// Run starts the service vault manager and processes messages
func (svm *ServiceVaultManager) Run(ctx context.Context) error {
	log.Info().Str("service_space", svm.config.OwnerSpace).Msg("Service vault manager running")

	// Initialize message handler
	if err := svm.messageHandler.Initialize(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to initialize message handler (continuing)")
	}

	// Message processing loop
	msgChan := make(chan *IncomingMessage, 10)

	// Start message receiver
	go svm.receiveMessages(ctx, msgChan)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Service vault manager shutting down")
			return nil
		case msg := <-msgChan:
			response, err := svm.messageHandler.HandleMessage(ctx, msg)
			if err != nil {
				log.Error().Err(err).Str("msg_id", msg.GetID()).Msg("Error handling message")
				response = &OutgoingMessage{
					RequestID: msg.GetID(),
					Type:      MessageTypeError,
					Error:     err.Error(),
				}
			}
			if response != nil {
				if err := svm.sendToParent(response); err != nil {
					log.Error().Err(err).Msg("Failed to send response")
				}
			}
		}
	}
}

// receiveMessages reads messages from the supervisor
func (svm *ServiceVaultManager) receiveMessages(ctx context.Context, msgChan chan<- *IncomingMessage) {
	log.Debug().Msg("Message receiver started")

	for {
		select {
		case <-ctx.Done():
			return
		default:
			msg, err := svm.parentConn.ReadMessage()
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

// sendToParent sends a message to the supervisor
func (svm *ServiceVaultManager) sendToParent(msg *OutgoingMessage) error {
	return svm.parentConn.WriteMessage(msg)
}

// SecureShutdown performs secure cleanup
func (svm *ServiceVaultManager) SecureShutdown() {
	log.Info().Msg("Performing secure shutdown")
	// Zero any sensitive data
	if svm.messageHandler != nil {
		svm.messageHandler.SecureErase()
	}
	if svm.parentConn != nil {
		svm.parentConn.Close()
	}
	log.Info().Msg("Secure shutdown complete")
}
