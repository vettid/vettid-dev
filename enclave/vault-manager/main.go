// Package main implements the Vault Manager for VettID Nitro Enclave.
// Each vault-manager process handles a single user's vault operations,
// holding their unsealed credential in secure enclave memory.
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

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Vault manager shutting down")
			return nil
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

// CreateCredential creates a new Protean Credential
func (vm *VaultManager) CreateCredential(ctx context.Context, req *CredentialCreateRequest) (*CredentialCreateResponse, error) {
	log.Info().Str("auth_type", req.AuthType).Msg("Creating new credential")

	// 1. Decrypt the PIN/password using enclave's private key
	authInput, err := vm.decryptAuthInput(req.EncryptedAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt auth input: %w", err)
	}

	// 2. Generate identity keypair (Ed25519)
	identityPriv, identityPub, err := generateIdentityKeypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity keypair: %w", err)
	}

	// 3. Generate vault master secret
	masterSecret, err := generateMasterSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate master secret: %w", err)
	}

	// 4. Hash auth input with Argon2id
	authSalt, err := generateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	authHash := hashAuthInput(authInput, authSalt)

	// 5. Create credential structure
	credential := &UnsealedCredential{
		IdentityPrivateKey: identityPriv,
		IdentityPublicKey:  identityPub,
		VaultMasterSecret:  masterSecret,
		AuthType:           req.AuthType,
		AuthHash:           authHash,
		AuthSalt:           authSalt,
		CryptoKeys:         []CryptoKey{},
		CreatedAt:          currentTimestamp(),
		Version:            1,
	}

	// 6. Seal credential to PCRs
	sealedCredential, err := vm.sealCredential(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to seal credential: %w", err)
	}

	// 7. Store credential in vault state
	vm.credential = credential

	log.Info().Msg("Credential created successfully")

	return &CredentialCreateResponse{
		SealedCredential: sealedCredential,
		PublicKey:        identityPub,
	}, nil
}

// UnsealCredential unseals a credential and verifies the auth challenge
func (vm *VaultManager) UnsealCredential(ctx context.Context, sealed []byte, challenge *AuthChallenge) (*UnsealResponse, error) {
	log.Info().Msg("Unsealing credential")

	// 1. Unseal using PCR-bound key
	credential, err := vm.unsealCredentialBlob(sealed)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal credential: %w", err)
	}

	// 2. Verify auth challenge (PIN/password/pattern)
	if !vm.verifyAuthChallenge(credential, challenge) {
		return nil, ErrAuthFailed
	}

	// 3. Store unsealed credential in memory
	vm.credential = credential

	// 4. Create session token
	session, err := vm.createSession(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	vm.session = session

	log.Info().Msg("Credential unsealed successfully")

	return &UnsealResponse{
		SessionToken: session.Token,
		ExpiresAt:    session.ExpiresAt,
	}, nil
}

// Request/Response types

// CredentialCreateRequest is the request to create a new credential
type CredentialCreateRequest struct {
	AuthType      string `json:"auth_type"` // "pin", "password", "pattern"
	EncryptedAuth []byte `json:"encrypted_auth"`
}

// CredentialCreateResponse is the response from credential creation
type CredentialCreateResponse struct {
	SealedCredential []byte `json:"sealed_credential"`
	PublicKey        []byte `json:"public_key"`
}

// AuthChallenge is the challenge for unsealing a credential
type AuthChallenge struct {
	ChallengeID   string `json:"challenge_id"`
	EncryptedAuth []byte `json:"encrypted_auth"`
}

// UnsealResponse is the response from unsealing a credential
type UnsealResponse struct {
	SessionToken []byte `json:"session_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// Helper functions (to be implemented)

func (vm *VaultManager) decryptAuthInput(encrypted []byte) ([]byte, error) {
	// TODO: Decrypt using enclave's ephemeral private key
	return nil, ErrNotImplemented
}

func (vm *VaultManager) sealCredential(cred *UnsealedCredential) ([]byte, error) {
	// TODO: Seal using Nitro KMS bound to PCRs
	data, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	return sealToNitroKMS(data)
}

func (vm *VaultManager) unsealCredentialBlob(sealed []byte) (*UnsealedCredential, error) {
	// TODO: Unseal using Nitro KMS
	data, err := unsealFromNitroKMS(sealed)
	if err != nil {
		return nil, err
	}
	var cred UnsealedCredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}

func (vm *VaultManager) verifyAuthChallenge(cred *UnsealedCredential, challenge *AuthChallenge) bool {
	// TODO: Decrypt challenge response and verify against stored hash
	// Use timing-safe comparison
	return false
}

func (vm *VaultManager) createSession(cred *UnsealedCredential) (*Session, error) {
	// TODO: Generate secure session token
	token, err := generateSecureToken(32)
	if err != nil {
		return nil, err
	}
	return &Session{
		Token:       token,
		ExpiresAt:   currentTimestamp() + 15*60, // 15 minutes
		Permissions: []string{"read", "write", "sign"},
	}, nil
}

// Errors
var (
	ErrNotImplemented = fmt.Errorf("not implemented")
	ErrAuthFailed     = fmt.Errorf("authentication failed")
)
