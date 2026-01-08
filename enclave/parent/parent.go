package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
)

// ParentProcess bridges the enclave to external services
type ParentProcess struct {
	config        *Config
	natsClient    *NATSClient
	s3Client      *S3Client
	vsockClient   *VsockClient
	healthSrv     *HealthServer
	handlerLoader *HandlerLoader
	kmsClient     *KMSClient
	mu            sync.RWMutex
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

	// Start health server first so we can track connection states
	p.healthSrv = NewHealthServer(p.config.Health.Port)
	go p.healthSrv.Start()
	defer p.healthSrv.Stop()

	// Connect to NATS with health status callback
	natsClient, err := NewNATSClient(p.config.NATS, func(connected bool) {
		p.updateHealthStatus()
	})
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

	// Create handler loader for dynamic WASM handler loading
	handlerLoader, err := NewHandlerLoader(p.config.Handlers)
	if err != nil {
		return fmt.Errorf("failed to create handler loader: %w", err)
	}
	p.handlerLoader = handlerLoader

	log.Info().
		Str("bucket", p.config.Handlers.Bucket).
		Str("manifest_table", p.config.Handlers.ManifestTable).
		Msg("Handler loader initialized")

	// Create KMS client for Nitro attestation-based sealing
	kmsClient, err := NewKMSClient(p.config.KMS)
	if err != nil {
		return fmt.Errorf("failed to create KMS client: %w", err)
	}
	p.kmsClient = kmsClient

	if p.config.KMS.SealingKeyARN != "" {
		log.Info().Str("key_arn", p.config.KMS.SealingKeyARN).Msg("KMS client initialized")
	} else {
		log.Warn().Msg("KMS sealing key not configured - enclave sealing will use dev mode")
	}

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

	// Update health status now that all connections are established
	p.updateHealthStatus()

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
	// TODO: Re-enable when enclave-initiated messages are needed
	// Currently disabled because it blocks on read holding the mutex,
	// which prevents SendMessage from working. Need a proper async design.
	// go func() {
	// 	err := p.routeEnclaveToExternal(ctx)
	// 	if err != nil && ctx.Err() == nil {
	// 		errChan <- fmt.Errorf("Enclave→External routing error: %w", err)
	// 	}
	// }()

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

	// Subscribe to enclave control messages from Lambdas (attestation requests, etc.)
	if err := p.natsClient.Subscribe("enclave.>", msgChan); err != nil {
		return fmt.Errorf("failed to subscribe to enclave.>: %w", err)
	}
	log.Debug().Str("subject", "enclave.>").Msg("Subscribed to NATS")

	log.Info().Msg("Subscribed to OwnerSpace, MessageSpace, and enclave topics")

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
	var enclaveMsg *EnclaveMessage

	// Check if this is an enclave control message (from Lambdas)
	if isEnclaveSubject(msg.Subject) {
		// Map enclave subject to appropriate message type
		msgType := mapEnclaveSubjectToType(msg.Subject)
		enclaveMsg = &EnclaveMessage{
			Type:    msgType,
			Subject: msg.Subject,
			Payload: msg.Data,
			ReplyTo: msg.Reply,
		}

		// For attestation requests, parse the JSON payload to extract nonce
		if msgType == EnclaveMessageTypeAttestationRequest {
			if err := p.parseAttestationRequest(msg.Data, enclaveMsg); err != nil {
				log.Warn().Err(err).Msg("Failed to parse attestation request, using raw payload")
			}
		}

		// For credential operations, parse the JSON payload to extract owner_space and credential_request
		if msgType == EnclaveMessageTypeCredentialCreate || msgType == EnclaveMessageTypeCredentialUnseal {
			if err := p.parseCredentialRequest(msg.Data, enclaveMsg); err != nil {
				log.Warn().Err(err).Msg("Failed to parse credential request, using raw payload")
			}
		}

		log.Debug().
			Str("type", string(msgType)).
			Int("nonce_len", len(enclaveMsg.Nonce)).
			Str("owner_space", enclaveMsg.OwnerSpace).
			Msg("Forwarding enclave control message to vsock")
	} else {
		// Extract owner space from subject (OwnerSpace.{guid}.* or MessageSpace.{guid}.*)
		ownerSpace, err := extractOwnerSpace(msg.Subject)
		if err != nil {
			return err
		}

		// Determine message type based on subject suffix
		msgType := mapSubjectToMessageType(msg.Subject)

		// Create enclave message
		enclaveMsg = &EnclaveMessage{
			Type:       msgType,
			OwnerSpace: ownerSpace,
			Subject:    msg.Subject,
			Payload:    msg.Data,
			ReplyTo:    msg.Reply,
		}

		// For credential operations, parse the JSON payload
		if msgType == EnclaveMessageTypeCredentialCreate || msgType == EnclaveMessageTypeCredentialUnseal {
			if err := p.parseCredentialRequestFromPayload(msg.Data, enclaveMsg); err != nil {
				log.Warn().Err(err).Msg("Failed to parse credential request from payload")
			}
		}
	}

	// Send to enclave and handle nested handler requests
	response, err := p.sendWithHandlerSupport(ctx, enclaveMsg)
	if err != nil {
		return err
	}

	// If there's a reply address, send response back via NATS
	if msg.Reply != "" && response != nil {
		responseData := p.formatEnclaveResponse(response)
		if err := p.natsClient.Publish(msg.Reply, responseData); err != nil {
			log.Error().Err(err).Str("reply", msg.Reply).Msg("Failed to publish reply")
		}
	}

	return nil
}

// sendWithHandlerSupport sends a message to the enclave and handles any nested
// handler_get requests that may come back before the final response.
// This allows the enclave to dynamically request handlers during vault operations.
func (p *ParentProcess) sendWithHandlerSupport(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	// Lock for write
	p.vsockClient.writeMu.Lock()
	if err := p.vsockClient.writeMessage(msg); err != nil {
		p.vsockClient.writeMu.Unlock()
		return nil, fmt.Errorf("failed to send message: %w", err)
	}
	p.vsockClient.writeMu.Unlock()

	// Lock for read and loop until we get the final response
	p.vsockClient.readMu.Lock()
	defer p.vsockClient.readMu.Unlock()

	for {
		response, err := p.vsockClient.readMessage()
		if err != nil {
			log.Error().Err(err).Msg("Failed to read vsock response")
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		log.Debug().
			Str("type", string(response.Type)).
			Bool("has_error", response.Error != "").
			Str("error", response.Error).
			Int("credential_len", len(response.Credential)).
			Int("payload_len", len(response.Payload)).
			Msg("Received vsock response")

		// Check if this is a handler request
		if response.Type == EnclaveMessageTypeHandlerGet {
			log.Debug().
				Str("handler_id", response.HandlerID).
				Msg("Enclave requested handler during operation")

			// Fetch and send handler
			if err := p.handleHandlerRequest(ctx, response); err != nil {
				log.Error().Err(err).Str("handler_id", response.HandlerID).Msg("Failed to handle handler request")
				// Send error response to enclave
				errMsg := &EnclaveMessage{
					Type:  EnclaveMessageTypeError,
					Error: err.Error(),
				}
				p.vsockClient.writeMu.Lock()
				p.vsockClient.writeMessage(errMsg)
				p.vsockClient.writeMu.Unlock()
			}
			continue // Wait for next response
		}

		// Check if this is a KMS encrypt request (enclave needs to seal data)
		if response.Type == EnclaveMessageTypeKMSEncrypt {
			log.Debug().
				Int("plaintext_len", len(response.Plaintext)).
				Msg("Enclave requested KMS encrypt during operation")

			kmsResp, err := p.handleKMSEncrypt(ctx, response)
			if err != nil {
				log.Error().Err(err).Msg("Failed to handle KMS encrypt request")
				errMsg := &EnclaveMessage{
					Type:  EnclaveMessageTypeError,
					Error: err.Error(),
				}
				p.vsockClient.writeMu.Lock()
				p.vsockClient.writeMessage(errMsg)
				p.vsockClient.writeMu.Unlock()
			} else {
				p.vsockClient.writeMu.Lock()
				if err := p.vsockClient.writeMessage(kmsResp); err != nil {
					log.Error().Err(err).Msg("Failed to send KMS encrypt response")
				}
				p.vsockClient.writeMu.Unlock()
			}
			continue // Wait for next response
		}

		// Check if this is a KMS decrypt request (enclave needs to unseal data)
		if response.Type == EnclaveMessageTypeKMSDecrypt {
			log.Debug().
				Int("ciphertext_len", len(response.CiphertextDEK)).
				Msg("Enclave requested KMS decrypt during operation")

			kmsResp, err := p.handleKMSDecrypt(ctx, response)
			if err != nil {
				log.Error().Err(err).Msg("Failed to handle KMS decrypt request")
				errMsg := &EnclaveMessage{
					Type:  EnclaveMessageTypeError,
					Error: err.Error(),
				}
				p.vsockClient.writeMu.Lock()
				p.vsockClient.writeMessage(errMsg)
				p.vsockClient.writeMu.Unlock()
			} else {
				p.vsockClient.writeMu.Lock()
				if err := p.vsockClient.writeMessage(kmsResp); err != nil {
					log.Error().Err(err).Msg("Failed to send KMS decrypt response")
				}
				p.vsockClient.writeMu.Unlock()
			}
			continue // Wait for next response
		}

		// Got the final response
		return response, nil
	}
}

// handleHandlerRequest fetches a handler from S3 and sends it to the enclave
func (p *ParentProcess) handleHandlerRequest(ctx context.Context, request *EnclaveMessage) error {
	wasmBytes, version, err := p.handlerLoader.GetHandler(ctx, request.HandlerID)
	if err != nil {
		return err
	}

	response := &EnclaveMessage{
		Type:           EnclaveMessageTypeHandlerResponse,
		HandlerID:      request.HandlerID,
		HandlerVersion: version,
		Payload:        wasmBytes,
	}

	p.vsockClient.writeMu.Lock()
	defer p.vsockClient.writeMu.Unlock()

	return p.vsockClient.writeMessage(response)
}

// parseAttestationRequest parses the JSON attestation request to extract the nonce
func (p *ParentProcess) parseAttestationRequest(data []byte, msg *EnclaveMessage) error {
	var req struct {
		Nonce string `json:"nonce"` // Base64-encoded nonce
	}

	if err := json.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("failed to unmarshal attestation request: %w", err)
	}

	if req.Nonce == "" {
		return fmt.Errorf("nonce is required in attestation request")
	}

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %w", err)
	}

	msg.Nonce = nonce
	log.Debug().Int("nonce_len", len(nonce)).Msg("Parsed attestation request nonce")
	return nil
}

// parseCredentialRequest parses the JSON credential request from enclave.credential.* subjects
// Lambda sends flat fields: { owner_space, encrypted_auth, auth_type } or { owner_space, sealed_credential, encrypted_challenge }
func (p *ParentProcess) parseCredentialRequest(data []byte, msg *EnclaveMessage) error {
	var req struct {
		OwnerSpace string `json:"owner_space"`
		// For credential create
		EncryptedAuth string `json:"encrypted_auth,omitempty"` // Base64-encoded
		AuthType      string `json:"auth_type,omitempty"`
		// For credential unseal
		SealedCredential   string `json:"sealed_credential,omitempty"`   // Base64-encoded
		EncryptedChallenge string `json:"encrypted_challenge,omitempty"` // Base64-encoded
	}

	if err := json.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("failed to unmarshal credential request: %w", err)
	}

	if req.OwnerSpace == "" {
		return fmt.Errorf("owner_space is required in credential request")
	}

	msg.OwnerSpace = req.OwnerSpace

	// Handle credential create (has encrypted_auth)
	if req.EncryptedAuth != "" {
		encryptedAuth, err := base64.StdEncoding.DecodeString(req.EncryptedAuth)
		if err != nil {
			return fmt.Errorf("failed to decode encrypted_auth: %w", err)
		}
		msg.CredentialRequest = &CredentialRequest{
			EncryptedPIN: encryptedAuth,
			AuthType:     req.AuthType,
		}
		log.Debug().
			Str("owner_space", req.OwnerSpace).
			Str("auth_type", req.AuthType).
			Int("encrypted_auth_len", len(encryptedAuth)).
			Msg("Parsed credential create request")
	}

	// Handle credential unseal (has sealed_credential)
	if req.SealedCredential != "" {
		sealedCredential, err := base64.StdEncoding.DecodeString(req.SealedCredential)
		if err != nil {
			return fmt.Errorf("failed to decode sealed_credential: %w", err)
		}
		msg.SealedCredential = sealedCredential

		// Decode encrypted challenge (PIN/password for verification)
		if req.EncryptedChallenge != "" {
			encryptedChallenge, err := base64.StdEncoding.DecodeString(req.EncryptedChallenge)
			if err != nil {
				return fmt.Errorf("failed to decode encrypted_challenge: %w", err)
			}
			msg.Challenge = &Challenge{
				ChallengeID: "unseal-" + req.OwnerSpace,
				Response:    encryptedChallenge,
			}
		}

		log.Debug().
			Str("owner_space", req.OwnerSpace).
			Int("sealed_credential_len", len(sealedCredential)).
			Bool("has_challenge", msg.Challenge != nil).
			Msg("Parsed credential unseal request")
	}

	return nil
}

// parseCredentialRequestFromPayload parses the Lambda's credential request format
// Lambda sends: { "user_guid": "...", "encrypted_auth": "base64...", "auth_type": "pin" }
// We need to map this to the enclave message format
func (p *ParentProcess) parseCredentialRequestFromPayload(data []byte, msg *EnclaveMessage) error {
	// For credential create
	var createReq struct {
		UserGUID      string `json:"user_guid"`
		EncryptedAuth string `json:"encrypted_auth"` // Base64-encoded
		AuthType      string `json:"auth_type"`
	}

	// For credential unseal
	var unsealReq struct {
		OwnerSpace         string `json:"owner_space"`         // Primary field
		UserGUID           string `json:"user_guid"`           // Fallback for legacy compatibility
		SealedCredential   string `json:"sealed_credential"`   // Base64-encoded
		EncryptedChallenge string `json:"encrypted_challenge"` // Base64-encoded
	}

	if msg.Type == EnclaveMessageTypeCredentialCreate {
		if err := json.Unmarshal(data, &createReq); err != nil {
			return fmt.Errorf("failed to unmarshal credential create request: %w", err)
		}

		// Decode encrypted auth
		encryptedAuth, err := base64.StdEncoding.DecodeString(createReq.EncryptedAuth)
		if err != nil {
			return fmt.Errorf("failed to decode encrypted_auth: %w", err)
		}

		msg.CredentialRequest = &CredentialRequest{
			EncryptedPIN: encryptedAuth,
			AuthType:     createReq.AuthType,
		}

		log.Debug().
			Str("user_guid", createReq.UserGUID).
			Str("auth_type", createReq.AuthType).
			Int("encrypted_auth_len", len(encryptedAuth)).
			Msg("Parsed credential create request from Lambda")

	} else if msg.Type == EnclaveMessageTypeCredentialUnseal {
		if err := json.Unmarshal(data, &unsealReq); err != nil {
			return fmt.Errorf("failed to unmarshal credential unseal request: %w", err)
		}

		// Decode sealed credential
		sealedCredential, err := base64.StdEncoding.DecodeString(unsealReq.SealedCredential)
		if err != nil {
			return fmt.Errorf("failed to decode sealed_credential: %w", err)
		}

		msg.SealedCredential = sealedCredential

		// Decode encrypted challenge (PIN/password for verification)
		ownerSpace := unsealReq.OwnerSpace
		if ownerSpace == "" {
			ownerSpace = unsealReq.UserGUID // Fallback to user_guid for compatibility
		}

		if unsealReq.EncryptedChallenge != "" {
			encryptedChallenge, err := base64.StdEncoding.DecodeString(unsealReq.EncryptedChallenge)
			if err != nil {
				return fmt.Errorf("failed to decode encrypted_challenge: %w", err)
			}
			msg.Challenge = &Challenge{
				ChallengeID: "unseal-" + ownerSpace,
				Response:    encryptedChallenge,
			}
		}

		log.Debug().
			Str("owner_space", ownerSpace).
			Int("sealed_credential_len", len(sealedCredential)).
			Bool("has_challenge", msg.Challenge != nil).
			Msg("Parsed credential unseal request from Lambda")
	}

	return nil
}

// formatEnclaveResponse formats an enclave response for NATS reply
func (p *ParentProcess) formatEnclaveResponse(response *EnclaveMessage) []byte {
	// For attestation responses, format with proper fields
	if response.Type == EnclaveMessageTypeAttestationResponse && response.Attestation != nil {
		resp := struct {
			Attestation string `json:"attestation"`
			PublicKey   string `json:"public_key"`
			Timestamp   int64  `json:"timestamp"`
		}{
			Attestation: base64.StdEncoding.EncodeToString(response.Attestation.Document),
			PublicKey:   base64.StdEncoding.EncodeToString(response.Attestation.PublicKey),
			Timestamp:   0, // Will be filled by enclave
		}

		data, err := json.Marshal(resp)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal attestation response")
			return response.Payload
		}
		return data
	}

	// For credential responses, format with proper fields
	// The Lambda expects: sealed_credential, public_key, backup_key (all base64)
	if response.Type == EnclaveMessageTypeCredentialResponse {
		// If there's an error, return error response
		if response.Error != "" {
			resp := struct {
				Error string `json:"error"`
			}{
				Error: response.Error,
			}
			data, _ := json.Marshal(resp)
			return data
		}

		// Return credential response with base64-encoded sealed credential
		resp := struct {
			SealedCredential string `json:"sealed_credential"`
			PublicKey        string `json:"public_key,omitempty"`
			BackupKey        string `json:"backup_key,omitempty"`
		}{
			SealedCredential: base64.StdEncoding.EncodeToString(response.Credential),
			// TODO: Enclave should return these separately
			PublicKey: "",
			BackupKey: "",
		}

		data, err := json.Marshal(resp)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal credential response")
			return response.Payload
		}

		log.Debug().
			Int("sealed_len", len(response.Credential)).
			Msg("Formatted credential response")
		return data
	}

	// For error responses, include the error message
	if response.Type == EnclaveMessageTypeError && response.Error != "" {
		resp := struct {
			Type  string `json:"type"`
			Error string `json:"error"`
		}{
			Type:  string(response.Type),
			Error: response.Error,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal error response")
			return response.Payload
		}
		return data
	}

	// For other responses, use the payload directly
	return response.Payload
}

// isEnclaveSubject checks if a subject is an enclave control subject
func isEnclaveSubject(subject string) bool {
	return len(subject) >= 8 && subject[:8] == "enclave."
}

// mapSubjectToMessageType maps NATS subjects to enclave message types
// This handles OwnerSpace.*.forVault.* patterns
func mapSubjectToMessageType(subject string) EnclaveMessageType {
	// Check for credential operations in OwnerSpace pattern
	// OwnerSpace.{guid}.forVault.credential.create
	// OwnerSpace.{guid}.forVault.credential.unseal
	if hasSubjectSuffix(subject, "credential.create") {
		return EnclaveMessageTypeCredentialCreate
	}
	if hasSubjectSuffix(subject, "credential.unseal") {
		return EnclaveMessageTypeCredentialUnseal
	}

	// Default to vault operation
	return EnclaveMessageTypeVaultOp
}

// hasSubjectSuffix checks if a NATS subject ends with a given suffix
func hasSubjectSuffix(subject, suffix string) bool {
	if len(subject) < len(suffix) {
		return false
	}
	return subject[len(subject)-len(suffix):] == suffix
}

// mapEnclaveSubjectToType maps enclave.* subjects to message types
func mapEnclaveSubjectToType(subject string) EnclaveMessageType {
	// Map known enclave subjects to message types
	// enclave.attestation.request -> attestation_request
	// enclave.health -> health_check
	// enclave.credential.create -> credential_create
	// enclave.credential.unseal -> credential_unseal
	switch {
	case subject == "enclave.attestation.request":
		return EnclaveMessageTypeAttestationRequest
	case subject == "enclave.health" || subject == "enclave.health.check":
		return EnclaveMessageTypeHealthCheck
	case subject == "enclave.credential.create":
		return EnclaveMessageTypeCredentialCreate
	case subject == "enclave.credential.unseal":
		return EnclaveMessageTypeCredentialUnseal
	default:
		// For unknown enclave subjects, use vault_op as fallback
		log.Warn().Str("subject", subject).Msg("Unknown enclave subject, using vault_op")
		return EnclaveMessageTypeVaultOp
	}
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
	case EnclaveMessageTypeHandlerGet:
		return p.handleHandlerGet(ctx, msg)
	case EnclaveMessageTypeKMSEncrypt:
		return p.handleKMSEncrypt(ctx, msg)
	case EnclaveMessageTypeKMSDecrypt:
		return p.handleKMSDecrypt(ctx, msg)
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

// handleHandlerGet retrieves a WASM handler from S3 with signature verification
func (p *ParentProcess) handleHandlerGet(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	if msg.HandlerID == "" {
		return nil, fmt.Errorf("handler_id is required")
	}

	log.Debug().
		Str("handler_id", msg.HandlerID).
		Msg("Enclave requested handler")

	// Fetch handler (uses manifest cache + signature verification)
	wasmBytes, version, err := p.handlerLoader.GetHandler(ctx, msg.HandlerID)
	if err != nil {
		log.Error().
			Err(err).
			Str("handler_id", msg.HandlerID).
			Msg("Failed to get handler")
		return nil, fmt.Errorf("handler get failed: %w", err)
	}

	log.Info().
		Str("handler_id", msg.HandlerID).
		Str("version", version).
		Int("size", len(wasmBytes)).
		Msg("Handler retrieved and verified")

	return &EnclaveMessage{
		Type:           EnclaveMessageTypeHandlerResponse,
		HandlerID:      msg.HandlerID,
		HandlerVersion: version,
		Payload:        wasmBytes,
	}, nil
}

// handleKMSEncrypt encrypts data using KMS (for envelope encryption)
// Used by the enclave to encrypt a DEK before storing sealed data
func (p *ParentProcess) handleKMSEncrypt(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	if len(msg.Plaintext) == 0 {
		return nil, fmt.Errorf("plaintext is required for KMS encrypt")
	}

	log.Debug().
		Int("plaintext_len", len(msg.Plaintext)).
		Msg("Encrypting data with KMS")

	ciphertext, err := p.kmsClient.Encrypt(ctx, msg.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("KMS encrypt failed: %w", err)
	}

	return &EnclaveMessage{
		Type:          EnclaveMessageTypeKMSResponse,
		CiphertextDEK: ciphertext,
	}, nil
}

// handleKMSDecrypt decrypts data using KMS with attestation
// The attestation document must contain PCR values that match the key policy
// This is the core of Nitro attestation-based sealing
func (p *ParentProcess) handleKMSDecrypt(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	if len(msg.CiphertextDEK) == 0 {
		return nil, fmt.Errorf("ciphertext_dek is required for KMS decrypt")
	}

	if msg.Attestation == nil || len(msg.Attestation.Document) == 0 {
		return nil, fmt.Errorf("attestation document is required for KMS decrypt")
	}

	log.Debug().
		Int("ciphertext_len", len(msg.CiphertextDEK)).
		Int("attestation_len", len(msg.Attestation.Document)).
		Msg("Decrypting data with KMS using attestation")

	// Call KMS with attestation - this returns CiphertextForRecipient
	// which is the plaintext encrypted to the enclave's public key
	result, err := p.kmsClient.DecryptWithAttestation(ctx, msg.CiphertextDEK, msg.Attestation.Document)
	if err != nil {
		return nil, fmt.Errorf("KMS decrypt with attestation failed: %w", err)
	}

	return &EnclaveMessage{
		Type:    EnclaveMessageTypeKMSResponse,
		Payload: result, // CiphertextForRecipient - enclave must decrypt with its private key
	}, nil
}

// getHealthStatus returns the current health status
func (p *ParentProcess) getHealthStatus() []byte {
	// TODO: Implement proper health status
	return []byte(`{"status":"healthy"}`)
}

// updateHealthStatus updates the health server with current connection states
func (p *ParentProcess) updateHealthStatus() {
	if p.healthSrv == nil {
		return
	}

	natsConnected := p.natsClient != nil && p.natsClient.IsConnected()
	enclaveConnected := p.vsockClient != nil && p.vsockClient.IsConnected()

	p.healthSrv.UpdateStatus(natsConnected, enclaveConnected)
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
