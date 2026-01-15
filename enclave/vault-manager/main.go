// Package main implements the Vault Manager for VettID Nitro Enclave.
// Each vault-manager process handles a single user's vault operations,
// holding their unsealed credential in secure enclave memory.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Version is set at build time
var Version = "dev"

func main() {
	// Parse command line flags
	ownerSpace := flag.String("owner-space", "", "Owner space (user GUID) for this vault")
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
		Str("owner_space", *ownerSpace).
		Logger()

	log.Info().
		Str("version", Version).
		Bool("dev_mode", *devMode).
		Msg("Vault Manager starting")

	// SECURITY: Enforce process isolation hardening
	// This must be done early before any sensitive data is loaded
	isoCfg := DefaultIsolationConfig(*devMode)
	if err := EnforceIsolation(isoCfg); err != nil {
		log.Error().Err(err).Msg("Failed to enforce process isolation")
		// In production, this is a fatal error
		if !*devMode {
			os.Exit(1)
		}
	}

	// Create vault manager
	cfg := &VaultConfig{
		OwnerSpace: *ownerSpace,
		ParentFD:   *parentFD,
		DevMode:    *devMode,
	}

	vault, err := NewVaultManager(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create vault manager")
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

	// Run vault manager (blocks until context is cancelled)
	if err := vault.Run(ctx); err != nil {
		log.Fatal().Err(err).Msg("Vault manager error")
	}

	// SECURITY: Secure erase all sensitive data before exit
	vault.SecureShutdown()

	log.Info().Msg("Vault manager shutdown complete")
}

// VaultConfig holds the vault manager configuration
type VaultConfig struct {
	OwnerSpace string
	ParentFD   int
	DevMode    bool
}

// VaultManager handles a single user's vault operations
type VaultManager struct {
	config         *VaultConfig
	storage        *EncryptedStorage
	credential     *UnsealedCredential
	session        *Session
	messageHandler *MessageHandler
	publisher      *VsockPublisher
	parentConn     *ParentConnection // IPC connection to supervisor
}

// NOTE: UnsealedCredential and CryptoKey types are defined in credential_types.go

// Session holds session state for authenticated operations
type Session struct {
	Token       []byte
	ExpiresAt   int64
	Permissions []string
}

// NewVaultManager creates a new vault manager
func NewVaultManager(cfg *VaultConfig) (*VaultManager, error) {
	// Create encrypted storage adapter
	storage, err := NewEncryptedStorage(cfg.OwnerSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	vm := &VaultManager{
		config:     cfg,
		storage:    storage,
		parentConn: NewParentConnection(), // IPC to supervisor via stdin/stdout
	}

	// Create publisher for sending messages via supervisor
	vm.publisher = NewVsockPublisher(cfg.OwnerSpace, vm.sendToParent)

	// Create message handler with call support
	// Pass sendFn so the sealer proxy can request KMS operations from supervisor
	vm.messageHandler = NewMessageHandler(cfg.OwnerSpace, storage, vm.publisher, vm.sendToParent)

	return vm, nil
}

// Run starts the vault manager and processes messages
func (vm *VaultManager) Run(ctx context.Context) error {
	log.Info().Str("owner_space", vm.config.OwnerSpace).Msg("Vault manager running")

	// Initialize message handler (loads block list, etc.)
	if err := vm.messageHandler.Initialize(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to initialize message handler (continuing)")
	}

	// Message processing loop
	msgChan := make(chan *IncomingMessage, 10)

	// Channel for sealer responses from supervisor
	// This allows the sealer proxy to receive KMS responses asynchronously
	// IMPORTANT: Sealer responses are routed directly in receiveMessages() to avoid
	// a deadlock where the main loop blocks in HandleMessage waiting for the sealer
	// response, but the main loop is the only thing that reads from msgChan.
	sealerResponseCh := make(chan *IncomingMessage, 5)
	vm.messageHandler.SetSealerResponseChannel(sealerResponseCh)

	// Start message receiver (reads from parent FD)
	// Pass sealerResponseCh so sealer responses can be routed directly, bypassing the main loop
	go vm.receiveMessages(ctx, msgChan, sealerResponseCh)

	// SECURITY: Periodic cleanup of expired replay prevention events (every hour)
	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Vault manager shutting down")
			return nil
		case <-cleanupTicker.C:
			// SECURITY: Clean up expired replay prevention events
			if deleted, err := vm.storage.CleanupExpiredEvents(); err != nil {
				log.Warn().Err(err).Msg("Failed to cleanup expired events")
			} else if deleted > 0 {
				log.Debug().Int64("deleted", deleted).Msg("Cleaned up expired replay prevention events")
			}
		case msg := <-msgChan:
			// Note: Sealer responses are now routed directly in receiveMessages()
			// to avoid a deadlock when HandleMessage blocks waiting for sealer responses.

			// Handle regular vault operations
			response, err := vm.messageHandler.HandleMessage(ctx, msg)
			if err != nil {
				log.Error().Err(err).Str("msg_id", msg.GetID()).Msg("Error handling message")
				response = &OutgoingMessage{
					RequestID: msg.GetID(),
					Type:      MessageTypeError,
					Error:     err.Error(),
				}
			}
			if response != nil {
				if err := vm.sendToParent(response); err != nil {
					log.Error().Err(err).Msg("Failed to send response")
				}
			}
		}
	}
}

// receiveMessages reads messages from the supervisor via stdin pipe.
// Sealer responses (sealer_response type) are routed directly to sealerResponseCh
// to avoid a deadlock with the main message processing loop.
func (vm *VaultManager) receiveMessages(ctx context.Context, msgChan chan<- *IncomingMessage, sealerResponseCh chan<- *IncomingMessage) {
	log.Debug().Msg("Message receiver started, reading from stdin")

	for {
		select {
		case <-ctx.Done():
			log.Debug().Msg("Message receiver stopping")
			return
		default:
			// Read next message from supervisor
			msg, err := vm.parentConn.ReadMessage()
			if err != nil {
				log.Error().Err(err).Msg("Failed to read message from supervisor")
				// If pipe is closed, the supervisor has terminated us
				return
			}

			// Route sealer responses directly to avoid deadlock.
			// The main loop blocks in HandleMessage waiting for sealer responses,
			// so we can't route through msgChan (main loop can't read it when blocked).
			if vm.messageHandler.IsSealerResponse(msg) {
				select {
				case sealerResponseCh <- msg:
					log.Debug().Str("msg_id", msg.GetID()).Msg("Routed sealer response directly")
				default:
					log.Warn().Str("msg_id", msg.GetID()).Msg("Sealer response channel full, dropping")
				}
				continue
			}

			// Send regular messages to processing channel
			select {
			case msgChan <- msg:
			case <-ctx.Done():
				return
			}
		}
	}
}

// sendToParent sends a message to the supervisor via stdout pipe
func (vm *VaultManager) sendToParent(msg *OutgoingMessage) error {
	return vm.parentConn.WriteMessage(msg)
}

// SecureShutdown performs secure cleanup of all sensitive data
// SECURITY: This must be called before process exit to prevent credential leakage
func (vm *VaultManager) SecureShutdown() {
	log.Info().Msg("Performing secure shutdown")

	// 1. Zero credential if loaded
	if vm.credential != nil {
		vm.credential.SecureErase()
		vm.credential = nil
		log.Debug().Msg("Zeroed credential data")
	}

	// 2. Zero session token
	if vm.session != nil {
		zeroBytes(vm.session.Token)
		vm.session = nil
		log.Debug().Msg("Zeroed session token")
	}

	// 3. Zero message handler state (which holds VaultState)
	if vm.messageHandler != nil {
		vm.messageHandler.SecureErase()
		log.Debug().Msg("Zeroed message handler state")
	}

	// 4. Close parent connection
	if vm.parentConn != nil {
		vm.parentConn.Close()
	}

	log.Info().Msg("Secure shutdown complete - all sensitive data zeroed")
}
