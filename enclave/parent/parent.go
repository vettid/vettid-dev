package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ParentProcess bridges the enclave to external services
type ParentProcess struct {
	config      *Config
	enclaveID   string // Unique identifier for this enclave instance
	natsClient  *NATSClient
	s3Client    *S3Client
	vsockClient *VsockClient
	healthSrv   *HealthServer
	kmsClient   *KMSClient
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

	// Generate or use configured enclave ID
	// This unique identifier is used for Control.enclave.{id}.* topic subscriptions
	if p.config.EnclaveID != "" {
		p.enclaveID = p.config.EnclaveID
	} else {
		var err error
		p.enclaveID, err = GenerateEnclaveID(p.config.DevMode)
		if err != nil {
			return fmt.Errorf("failed to generate enclave ID: %w", err)
		}
	}
	log.Info().Str("enclave_id", p.enclaveID).Msg("Enclave identity established")

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

	// Route Enclave → NATS/S3 (Disabled by design)
	//
	// The routeEnclaveToExternal goroutine is intentionally disabled because:
	// 1. Current architecture uses request-response pattern only (NATS→Enclave→NATS)
	// 2. The enclave doesn't need to initiate messages - it only responds to requests
	// 3. Enabling it causes a mutex conflict: it blocks on read while holding readMu,
	//    which prevents sendWithHandlerSupport from reading responses
	//
	// If enclave-initiated messages are needed in the future (e.g., push notifications,
	// async events), this requires architectural changes:
	// - Separate channels for request-response vs event streams
	// - Non-blocking vsock read with message type discrimination
	// - Consider using NATS JetStream for durable event delivery instead
	//
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
	//   OwnerSpace.{guid}.eventTypes - Event type queries
	//   MessageSpace.{guid}.forOwner.> - Connection messages
	//
	// Control topic patterns (multi-tenant architecture):
	//   Control.global.>                    - Commands for ALL enclaves (handler updates, health checks)
	//   Control.enclave.{enclave_id}.>      - Commands for THIS specific enclave
	//   Control.user.{guid}.>               - User-specific commands (dynamically routed)
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

	// === Multi-tenant Control Topic Architecture ===
	// Subscribe to global control commands (all enclaves)
	if err := p.natsClient.Subscribe("Control.global.>", msgChan); err != nil {
		return fmt.Errorf("failed to subscribe to Control.global.>: %w", err)
	}
	log.Debug().Str("subject", "Control.global.>").Msg("Subscribed to NATS (global control)")

	// Subscribe to enclave-specific control commands (this enclave only)
	enclaveControlSubject := fmt.Sprintf("Control.enclave.%s.>", p.enclaveID)
	if err := p.natsClient.Subscribe(enclaveControlSubject, msgChan); err != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", enclaveControlSubject, err)
	}
	log.Debug().Str("subject", enclaveControlSubject).Msg("Subscribed to NATS (enclave-specific control)")

	// Subscribe to user-specific control commands (for dynamic routing)
	if err := p.natsClient.Subscribe("Control.user.>", msgChan); err != nil {
		return fmt.Errorf("failed to subscribe to Control.user.>: %w", err)
	}
	log.Debug().Str("subject", "Control.user.>").Msg("Subscribed to NATS (user control routing)")

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

	log.Info().
		Str("enclave_id", p.enclaveID).
		Msg("Subscribed to OwnerSpace, MessageSpace, Control, and enclave topics")

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
	// SECURITY: For Control.* subjects, verify signed commands
	// This prevents unauthorized execution even if NATS credentials are compromised
	if IsControlSubject(msg.Subject) {
		return p.handleControlCommand(ctx, msg)
	}

	// SECURITY: Check for replay attacks before processing
	// This prevents attackers from capturing and re-sending messages
	if allowed, reason := CheckMessageReplay(msg.Subject, msg.Data); !allowed {
		log.Warn().
			Str("subject", msg.Subject).
			Str("reason", reason).
			Msg("SECURITY: Message rejected - replay attack")

		// Send error response if there's a reply address
		if msg.Reply != "" {
			errorResponse := map[string]interface{}{
				"error":   "message_rejected",
				"message": "Message failed security validation: " + reason,
			}
			if responseData, err := json.Marshal(errorResponse); err == nil {
				if err := p.natsClient.Publish(msg.Reply, responseData); err != nil {
					log.Error().Err(err).Str("reply", msg.Reply).Msg("Failed to publish error reply")
				}
			}
		}
		return fmt.Errorf("message replay detected: %s", reason)
	}

	var enclaveMsg *EnclaveMessage

	// Check if this is an enclave control message (from Lambdas)
	if isEnclaveSubject(msg.Subject) {
		// Map enclave subject to appropriate message type
		msgType := mapEnclaveSubjectToType(msg.Subject)

		// Handle vault reset directly in parent (not forwarded to vault-manager)
		if msgType == EnclaveMessageTypeVaultReset {
			return p.handleVaultReset(ctx, msg)
		}

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

		// For attestation requests from mobile apps, parse the JSON payload to extract nonce
		if msgType == EnclaveMessageTypeAttestationRequest {
			if err := p.parseAttestationRequest(msg.Data, enclaveMsg); err != nil {
				log.Warn().Err(err).Msg("Failed to parse attestation request, using raw payload")
			}
			// DEBUG: Log incoming attestation request details for testing
			log.Info().
				Str("owner_space", ownerSpace).
				Str("subject", msg.Subject).
				Int("nonce_len", len(enclaveMsg.Nonce)).
				Int("payload_len", len(msg.Data)).
				Msg("Received attestation request from mobile app")
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

	// Send response back via NATS
	if response != nil {
		// Copy RequestID from original message for response correlation (issue #5)
		if enclaveMsg.RequestID != "" {
			response.RequestID = enclaveMsg.RequestID
		}
		responseData := p.formatEnclaveResponse(response)

		// If there's a reply address (NATS request/reply pattern), use it
		if msg.Reply != "" {
			if err := p.natsClient.Publish(msg.Reply, responseData); err != nil {
				log.Error().Err(err).Str("reply", msg.Reply).Msg("Failed to publish reply")
			}
		}

		// Also publish to app response subject for mobile apps using pub/sub pattern
		// OwnerSpace.<guid>.forVault.<op> -> OwnerSpace.<guid>.forApp.<op>.response
		//
		// Uses JetStream for exactly-once delivery with message persistence.
		// Messages are retained until consumed or MaxAge (5 min) expires.
		if enclaveMsg.OwnerSpace != "" {
			appResponseSubject := buildAppResponseSubject(msg.Subject, enclaveMsg.OwnerSpace)
			if appResponseSubject != "" {
				log.Info().
					Str("msg_type", string(response.Type)).
					Str("owner_space", enclaveMsg.OwnerSpace).
					Str("original_subject", msg.Subject).
					Str("response_subject", appResponseSubject).
					Int("response_bytes", len(responseData)).
					Bool("has_attestation", response.Attestation != nil).
					Msg("Publishing enclave response to mobile app via JetStream")

				if err := p.natsClient.Publish(appResponseSubject, responseData); err != nil {
					log.Error().Err(err).Str("subject", appResponseSubject).Msg("Failed to publish to app response subject")
				}
			}
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

// parseAttestationRequest parses the JSON attestation request to extract the nonce and request ID
// Handles both flat format {"nonce": "..."} and nested format {"payload": {"nonce": "..."}}
func (p *ParentProcess) parseAttestationRequest(data []byte, msg *EnclaveMessage) error {
	// Try nested format first (Android sends {"type": "...", "id": "...", "payload": {"nonce": "..."}})
	var nestedReq struct {
		ID      string `json:"id"` // Request ID to echo back in response
		Payload struct {
			Nonce string `json:"nonce"`
		} `json:"payload"`
		Nonce string `json:"nonce"` // Also check top-level for flat format
	}

	if err := json.Unmarshal(data, &nestedReq); err != nil {
		return fmt.Errorf("failed to unmarshal attestation request: %w", err)
	}

	// Capture request ID for response correlation (issue #5)
	if nestedReq.ID != "" {
		msg.RequestID = nestedReq.ID
	}

	// Check nested payload first, then fall back to top-level
	nonceStr := nestedReq.Payload.Nonce
	if nonceStr == "" {
		nonceStr = nestedReq.Nonce
	}

	if nonceStr == "" {
		return fmt.Errorf("nonce is required in attestation request (checked payload.nonce and nonce)")
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceStr)
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %w", err)
	}

	msg.Nonce = nonce
	log.Debug().Int("nonce_len", len(nonce)).Str("request_id", msg.RequestID).Msg("Parsed attestation request")
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
			Timestamp   string `json:"timestamp"`
			EventID     string `json:"event_id,omitempty"` // Echo back request ID for correlation (issue #5)
		}{
			Attestation: base64.StdEncoding.EncodeToString(response.Attestation.Document),
			PublicKey:   base64.StdEncoding.EncodeToString(response.Attestation.PublicKey),
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			EventID:     response.RequestID,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal attestation response")
			return response.Payload
		}

		// DEBUG: Log attestation response details for testing
		log.Debug().
			Str("timestamp", resp.Timestamp).
			Str("event_id", resp.EventID).
			Int("attestation_len", len(resp.Attestation)).
			Int("public_key_len", len(resp.PublicKey)).
			Int("response_size", len(data)).
			Msg("Formatted attestation response for mobile")

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
		// Note: PublicKey and BackupKey fields are reserved for future use.
		// Currently, the identity public key is embedded inside the sealed_credential blob.
		// If mobile apps need direct access to the identity public key (for independent
		// verification), the supervisor would need to extract and return it separately.
		resp := struct {
			SealedCredential string `json:"sealed_credential"`
			PublicKey        string `json:"public_key,omitempty"`
			BackupKey        string `json:"backup_key,omitempty"`
		}{
			SealedCredential: base64.StdEncoding.EncodeToString(response.Credential),
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

	// For vault_op responses (PIN setup, etc.), wrap with event_id for correlation
	// Mobile apps expect event_id to match request ID (issue #6)
	if len(response.Payload) > 0 && response.RequestID != "" {
		// Try to parse payload as JSON and add event_id
		var payloadMap map[string]interface{}
		if err := json.Unmarshal(response.Payload, &payloadMap); err == nil {
			// Successfully parsed as object - add event_id and timestamp
			payloadMap["event_id"] = response.RequestID
			if _, hasTimestamp := payloadMap["timestamp"]; !hasTimestamp {
				payloadMap["timestamp"] = time.Now().UTC().Format(time.RFC3339)
			}
			if data, err := json.Marshal(payloadMap); err == nil {
				log.Debug().
					Str("event_id", response.RequestID).
					Int("payload_len", len(data)).
					Msg("Wrapped vault response with event_id")
				return data
			}
		}
	}

	// Fallback: return payload directly
	return response.Payload
}

// isEnclaveSubject checks if a subject is an enclave control subject
func isEnclaveSubject(subject string) bool {
	return len(subject) >= 8 && subject[:8] == "enclave."
}

// mapSubjectToMessageType maps NATS subjects to enclave message types
// This handles OwnerSpace.*.forVault.* patterns
func mapSubjectToMessageType(subject string) EnclaveMessageType {
	// Check for attestation request from mobile apps
	// OwnerSpace.{guid}.forVault.attestation
	if hasSubjectSuffix(subject, ".attestation") {
		return EnclaveMessageTypeAttestationRequest
	}

	// Note: OwnerSpace.*.forVault.credential.create and credential.unseal are
	// handled as vault_op and routed through vault-manager's normal message handling.
	// Only enclave.credential.* subjects (legacy Lambda flow) use special handling.
	// Mobile apps use forVault.credential.create which goes to proteanCredentialHandler.

	// Default to vault operation - includes credential.create/unseal for mobile apps
	return EnclaveMessageTypeVaultOp
}

// hasSubjectSuffix checks if a NATS subject ends with a given suffix
func hasSubjectSuffix(subject, suffix string) bool {
	if len(subject) < len(suffix) {
		return false
	}
	return subject[len(subject)-len(suffix):] == suffix
}

// buildAppResponseSubject converts a forVault subject to a forApp response subject
// OwnerSpace.<guid>.forVault.<op> -> OwnerSpace.<guid>.forApp.<op>.response
// This allows mobile apps using pub/sub pattern to receive responses
// Note: ownerSpace parameter is just the GUID (from extractOwnerSpace)
func buildAppResponseSubject(subject, ownerSpace string) string {
	// Find ".forVault." in the subject
	forVaultIdx := -1
	searchStr := ".forVault."
	for i := 0; i <= len(subject)-len(searchStr); i++ {
		if subject[i:i+len(searchStr)] == searchStr {
			forVaultIdx = i
			break
		}
	}

	if forVaultIdx == -1 {
		return "" // Not a forVault subject
	}

	// Extract the operation part after ".forVault."
	opPart := subject[forVaultIdx+len(searchStr):]
	if opPart == "" {
		return ""
	}

	// Build: OwnerSpace.<guid>.forApp.<op>.response
	// ownerSpace is just the GUID, so we need to prepend "OwnerSpace."
	return "OwnerSpace." + ownerSpace + ".forApp." + opPart + ".response"
}

// mapEnclaveSubjectToType maps enclave.* subjects to message types
func mapEnclaveSubjectToType(subject string) EnclaveMessageType {
	// Map known enclave subjects to message types
	// enclave.attestation.request -> attestation_request
	// enclave.health -> health_check
	// enclave.vault.reset -> vault_reset (for decommission)
	switch {
	case subject == "enclave.attestation.request":
		return EnclaveMessageTypeAttestationRequest
	case subject == "enclave.health" || subject == "enclave.health.check":
		return EnclaveMessageTypeHealthCheck
	case subject == "enclave.vault.reset":
		return EnclaveMessageTypeVaultReset
	default:
		// For unknown enclave subjects, use vault_op as fallback
		// Note: enclave.credential.create/unseal are deprecated - mobile apps use
		// OwnerSpace.{guid}.forVault.pin-setup/pin-unlock instead
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
	case EnclaveMessageTypeKMSEncrypt:
		return p.handleKMSEncrypt(ctx, msg)
	case EnclaveMessageTypeKMSDecrypt:
		return p.handleKMSDecrypt(ctx, msg)
	case EnclaveMessageTypeLog:
		return p.handleLogMessage(ctx, msg)
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
		Type:       EnclaveMessageTypeKMSResponse,
		Ciphertext: result, // CiphertextForRecipient - enclave must decrypt with its private key
	}, nil
}

// handleLogMessage processes log messages from the enclave and forwards to stdout
// for CloudWatch to capture via systemd journal
func (p *ParentProcess) handleLogMessage(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	// Log the message at the appropriate level
	switch msg.LogLevel {
	case "debug":
		log.Debug().
			Str("source", msg.LogSource).
			Msg(msg.LogMessage)
	case "info":
		log.Info().
			Str("source", msg.LogSource).
			Msg(msg.LogMessage)
	case "warn":
		log.Warn().
			Str("source", msg.LogSource).
			Msg(msg.LogMessage)
	case "error":
		log.Error().
			Str("source", msg.LogSource).
			Msg(msg.LogMessage)
	default:
		log.Info().
			Str("source", msg.LogSource).
			Str("level", msg.LogLevel).
			Msg(msg.LogMessage)
	}

	// Return OK (fire-and-forget from enclave perspective)
	return &EnclaveMessage{
		Type: EnclaveMessageTypeOK,
	}, nil
}

// getHealthStatus returns the current health status
func (p *ParentProcess) getHealthStatus() []byte {
	// Build health status from current connection states
	natsConnected := p.natsClient != nil && p.natsClient.IsConnected()
	enclaveConnected := p.vsockClient != nil && p.vsockClient.IsConnected()

	status := struct {
		Healthy          bool   `json:"healthy"`
		NATSConnected    bool   `json:"nats_connected"`
		EnclaveConnected bool   `json:"enclave_connected"`
		Version          string `json:"version"`
	}{
		Healthy:          natsConnected && enclaveConnected,
		NATSConnected:    natsConnected,
		EnclaveConnected: enclaveConnected,
		Version:          Version,
	}

	data, err := json.Marshal(status)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal health status")
		return []byte(`{"healthy":false,"error":"marshal_failed"}`)
	}
	return data
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

// handleControlCommand processes signed control commands from Control.* subjects
// SECURITY: All control commands must be Ed25519 signed and pass verification
func (p *ParentProcess) handleControlCommand(ctx context.Context, msg *NATSMessage) error {
	// Verify the signed control command
	cmd, valid, reason := VerifyControlCommand(msg.Data)
	if !valid {
		log.Warn().
			Str("subject", msg.Subject).
			Str("reason", reason).
			Msg("SECURITY: Control command rejected")

		// Send error response if there's a reply address
		if msg.Reply != "" {
			errorResponse := map[string]interface{}{
				"error":   "command_rejected",
				"message": "Control command failed security validation: " + reason,
			}
			if responseData, err := json.Marshal(errorResponse); err == nil {
				if err := p.natsClient.Publish(msg.Reply, responseData); err != nil {
					log.Error().Err(err).Str("reply", msg.Reply).Msg("Failed to publish error reply")
				}
			}
		}
		return fmt.Errorf("control command rejected: %s", reason)
	}

	// Route command to appropriate handler based on command type
	switch cmd.Command {
	case "health.request":
		return p.handleHealthRequestCommand(ctx, msg, cmd)
	case "credential.delete":
		return p.handleCredentialDeleteCommand(ctx, msg, cmd)
	default:
		log.Warn().
			Str("command", cmd.Command).
			Str("command_id", cmd.CommandID).
			Msg("Unknown control command - forwarding to enclave")
		// Forward unknown commands to enclave for handling
		return p.forwardControlToEnclave(ctx, msg, cmd)
	}
}

// handleHealthRequestCommand handles health check control commands
func (p *ParentProcess) handleHealthRequestCommand(ctx context.Context, msg *NATSMessage, cmd *SignedControlCommand) error {
	log.Debug().
		Str("command_id", cmd.CommandID).
		Str("issued_by", cmd.IssuedBy).
		Msg("Processing health request command")

	// Get health status
	status := p.getHealthStatus()

	// Send response
	if msg.Reply != "" {
		if err := p.natsClient.Publish(msg.Reply, status); err != nil {
			log.Error().Err(err).Str("reply", msg.Reply).Msg("Failed to publish health response")
		}
	}

	return nil
}

// handleCredentialDeleteCommand handles credential deletion for vault decommission
// Subject format: Control.user.{guid}.credential.delete
// This is an admin-only operation used during vault decommission to clear
// the credential from the enclave's SQLite storage.
func (p *ParentProcess) handleCredentialDeleteCommand(ctx context.Context, msg *NATSMessage, cmd *SignedControlCommand) error {
	// Extract user GUID from subject: Control.user.{guid}.credential.delete
	parts := splitSubject(msg.Subject)
	if len(parts) < 5 || parts[0] != "Control" || parts[1] != "user" {
		log.Error().Str("subject", msg.Subject).Msg("Invalid credential.delete subject format")
		return fmt.Errorf("invalid subject format for credential.delete")
	}

	userGuid := parts[2]

	log.Info().
		Str("command_id", cmd.CommandID).
		Str("issued_by", cmd.IssuedBy).
		Str("user_guid", userGuid).
		Msg("Processing credential delete command (vault decommission)")

	// Transform to vault operation subject that the vault-manager expects
	// OwnerSpace.{guid}.forVault.credential.delete
	vaultSubject := fmt.Sprintf("OwnerSpace.%s.forVault.credential.delete", userGuid)

	// Create enclave message with proper routing
	enclaveMsg := &EnclaveMessage{
		Type:       EnclaveMessageTypeVaultOp,
		OwnerSpace: userGuid,
		Subject:    vaultSubject,
		Payload:    []byte("{}"), // Empty payload - delete doesn't need parameters
		ReplyTo:    msg.Reply,
	}

	// Send to enclave
	response, err := p.sendWithHandlerSupport(ctx, enclaveMsg)
	if err != nil {
		log.Error().Err(err).Str("user_guid", userGuid).Msg("Failed to delete credential in enclave")
		return err
	}

	// Send response back
	if response != nil && msg.Reply != "" {
		responseData := p.formatEnclaveResponse(response)
		if err := p.natsClient.Publish(msg.Reply, responseData); err != nil {
			log.Error().Err(err).Str("reply", msg.Reply).Msg("Failed to publish credential delete reply")
		}
	}

	log.Info().
		Str("user_guid", userGuid).
		Str("command_id", cmd.CommandID).
		Msg("Credential delete command completed")

	return nil
}

// handleVaultReset handles vault reset requests for decommissioning
// Subject: enclave.vault.reset
// Payload: {"user_guid": "..."}
// This forwards a credential.delete request to the vault-manager for the specified user
func (p *ParentProcess) handleVaultReset(ctx context.Context, msg *NATSMessage) error {
	// Parse the request payload
	var req struct {
		UserGuid string `json:"user_guid"`
	}
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Error().Err(err).Msg("Failed to parse vault reset request")
		if msg.Reply != "" {
			errorResponse := map[string]interface{}{
				"success": false,
				"error":   "invalid request format",
			}
			if responseData, err := json.Marshal(errorResponse); err == nil {
				p.natsClient.Publish(msg.Reply, responseData)
			}
		}
		return fmt.Errorf("invalid vault reset request: %w", err)
	}

	if req.UserGuid == "" {
		log.Error().Msg("Vault reset request missing user_guid")
		if msg.Reply != "" {
			errorResponse := map[string]interface{}{
				"success": false,
				"error":   "user_guid is required",
			}
			if responseData, err := json.Marshal(errorResponse); err == nil {
				p.natsClient.Publish(msg.Reply, responseData)
			}
		}
		return fmt.Errorf("user_guid is required")
	}

	log.Info().
		Str("user_guid", req.UserGuid).
		Msg("Processing vault reset request (decommission)")

	// Forward as credential.delete to the vault-manager
	// This is the same path used by the Control.user.*.credential.delete command
	vaultSubject := fmt.Sprintf("OwnerSpace.%s.forVault.credential.delete", req.UserGuid)

	enclaveMsg := &EnclaveMessage{
		Type:       EnclaveMessageTypeVaultOp,
		OwnerSpace: req.UserGuid,
		Subject:    vaultSubject,
		Payload:    []byte("{}"),
		ReplyTo:    msg.Reply,
	}

	// Send to enclave
	response, err := p.sendWithHandlerSupport(ctx, enclaveMsg)
	if err != nil {
		log.Error().Err(err).Str("user_guid", req.UserGuid).Msg("Failed to reset vault")
		if msg.Reply != "" {
			errorResponse := map[string]interface{}{
				"success": false,
				"error":   "failed to reset vault",
			}
			if responseData, err := json.Marshal(errorResponse); err == nil {
				p.natsClient.Publish(msg.Reply, responseData)
			}
		}
		return err
	}

	// Send response back
	if response != nil && msg.Reply != "" {
		responseData := p.formatEnclaveResponse(response)
		p.natsClient.Publish(msg.Reply, responseData)
	}

	log.Info().
		Str("user_guid", req.UserGuid).
		Msg("Vault reset completed")

	return nil
}

// forwardControlToEnclave forwards a control command to the enclave
func (p *ParentProcess) forwardControlToEnclave(ctx context.Context, msg *NATSMessage, cmd *SignedControlCommand) error {
	// Create enclave message for control command
	enclaveMsg := &EnclaveMessage{
		Type:    EnclaveMessageTypeVaultOp,
		Subject: msg.Subject,
		Payload: msg.Data,
		ReplyTo: msg.Reply,
	}

	// Send to enclave
	response, err := p.sendWithHandlerSupport(ctx, enclaveMsg)
	if err != nil {
		return err
	}

	// Send response back
	if response != nil && msg.Reply != "" {
		responseData := p.formatEnclaveResponse(response)
		if err := p.natsClient.Publish(msg.Reply, responseData); err != nil {
			log.Error().Err(err).Str("reply", msg.Reply).Msg("Failed to publish control command reply")
		}
	}

	return nil
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
