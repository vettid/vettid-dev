package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/vsock"
	"github.com/rs/zerolog/log"
)

// SECURITY: Authentication constants
const (
	handshakeTimeout       = 10 * time.Second
	handshakeNonceSize     = 32
	maxHandshakeAgeSeconds = 300
	secretFilePath         = "/etc/vettid/vsock-secret"
	secretFilePathDev      = "/tmp/vettid-vsock-secret"
)

// SECURITY: Handshake message types
const (
	MessageTypeHandshake         = "handshake"
	MessageTypeHandshakeResponse = "handshake_response"
)

// handshakeMessage is the wire format for handshake messages
type handshakeMessage struct {
	Type               string             `json:"type"`
	HandshakeNonce     []byte             `json:"handshake_nonce,omitempty"`
	HandshakeMAC       []byte             `json:"handshake_mac,omitempty"`
	HandshakeTimestamp int64              `json:"handshake_timestamp,omitempty"`
	Attestation        *HandshakeAttestation `json:"attestation,omitempty"`
}

// HandshakeAttestation holds attestation data for handshake
type HandshakeAttestation struct {
	Document  []byte `json:"document"`
	PublicKey []byte `json:"public_key"`
}

// SECURITY: Authentication errors
var (
	ErrHandshakeFailed  = errors.New("handshake authentication failed")
	ErrInvalidMAC       = errors.New("invalid handshake MAC")
	ErrExpiredHandshake = errors.New("handshake timestamp expired")
	ErrFutureTimestamp  = errors.New("handshake timestamp in the future")
	ErrNoSharedSecret   = errors.New("shared secret not configured")
)

// EnclaveMessageType identifies the type of message
type EnclaveMessageType string

const (
	// Vault operations
	EnclaveMessageTypeVaultOp         EnclaveMessageType = "vault_op"
	EnclaveMessageTypeVaultResponse   EnclaveMessageType = "vault_response"

	// Attestation (from Lambdas requesting attestation documents)
	EnclaveMessageTypeAttestationRequest  EnclaveMessageType = "attestation_request"
	EnclaveMessageTypeAttestationResponse EnclaveMessageType = "attestation_response"

	// Storage operations
	EnclaveMessageTypeStorageGet      EnclaveMessageType = "storage_get"
	EnclaveMessageTypeStoragePut      EnclaveMessageType = "storage_put"
	EnclaveMessageTypeStorageResponse EnclaveMessageType = "storage_response"

	// NATS operations
	EnclaveMessageTypeNATSPublish     EnclaveMessageType = "nats_publish"
	EnclaveMessageTypeNATSRequest     EnclaveMessageType = "nats_request"

	// Health
	EnclaveMessageTypeHealthCheck     EnclaveMessageType = "health_check"
	EnclaveMessageTypeHealthResponse  EnclaveMessageType = "health_response"

	// Handler loading
	EnclaveMessageTypeHandlerGet      EnclaveMessageType = "handler_get"
	EnclaveMessageTypeHandlerResponse EnclaveMessageType = "handler_response"

	// KMS operations (for Nitro attestation-based sealing)
	EnclaveMessageTypeKMSEncrypt  EnclaveMessageType = "kms_encrypt"
	EnclaveMessageTypeKMSDecrypt  EnclaveMessageType = "kms_decrypt"
	EnclaveMessageTypeKMSResponse EnclaveMessageType = "kms_response"

	// Credential operations
	EnclaveMessageTypeCredentialCreate   EnclaveMessageType = "credential_create"
	EnclaveMessageTypeCredentialUnseal   EnclaveMessageType = "credential_unseal"
	EnclaveMessageTypeCredentialResponse EnclaveMessageType = "credential_response"

	// General
	EnclaveMessageTypeOK              EnclaveMessageType = "ok"
	EnclaveMessageTypeError           EnclaveMessageType = "error"
)

// Attestation holds a Nitro attestation document
type Attestation struct {
	Document  []byte `json:"document"`   // CBOR-encoded attestation document
	PublicKey []byte `json:"public_key"` // Enclave's ephemeral public key
}

// EnclaveMessage is the wire format for parent-enclave communication
type EnclaveMessage struct {
	Type       EnclaveMessageType `json:"type"`
	OwnerSpace string             `json:"owner_space,omitempty"`
	Subject    string             `json:"subject,omitempty"`
	ReplyTo    string             `json:"reply_to,omitempty"`
	StorageKey string             `json:"storage_key,omitempty"`
	Payload    json.RawMessage    `json:"payload,omitempty"`
	Error      string             `json:"error,omitempty"`

	// Attestation fields
	Nonce       []byte       `json:"nonce,omitempty"`
	Attestation *Attestation `json:"attestation,omitempty"`

	// Handler loading fields
	HandlerID      string `json:"handler_id,omitempty"`
	HandlerVersion string `json:"handler_version,omitempty"`

	// KMS fields (for Nitro attestation-based sealing)
	KMSKeyID     string `json:"kms_key_id,omitempty"`     // KMS key ARN
	Plaintext    []byte `json:"plaintext,omitempty"`      // Data to encrypt (for encrypt)
	Ciphertext   []byte `json:"ciphertext,omitempty"`     // Encrypted data (for decrypt)
	CiphertextDEK []byte `json:"ciphertext_dek,omitempty"` // Encrypted DEK from KMS

	// Credential operation fields
	CredentialRequest *CredentialRequest `json:"credential_request,omitempty"`
	SealedCredential  []byte             `json:"sealed_credential,omitempty"`
	Challenge         *Challenge         `json:"challenge,omitempty"`
	Credential        []byte             `json:"credential,omitempty"`
}

// CredentialRequest is the request to create a new credential
type CredentialRequest struct {
	EncryptedPIN []byte `json:"encrypted_pin"` // PIN encrypted to enclave's pubkey
	AuthType     string `json:"auth_type"`     // "pin", "password", "pattern"
}

// Challenge is a PIN/password challenge for credential unseal
type Challenge struct {
	ChallengeID string `json:"challenge_id"`
	Response    []byte `json:"response"` // Encrypted PIN/password
}

// VsockClient handles communication with the enclave
type VsockClient struct {
	conn          net.Conn
	config        EnclaveConfig
	devMode       bool
	readMu        sync.Mutex // Mutex for read operations
	writeMu       sync.Mutex // Mutex for write operations
	authenticated bool       // SECURITY: True if handshake completed
	sharedSecret  []byte     // Pre-shared key for authentication
}

// NewVsockClient creates a new vsock client to communicate with the enclave
// SECURITY: Performs mutual authentication handshake before returning
func NewVsockClient(cfg EnclaveConfig, devMode bool) (*VsockClient, error) {
	var conn net.Conn
	var err error

	if devMode {
		// Development mode: use TCP
		addr := fmt.Sprintf("localhost:%d", cfg.Port)
		conn, err = net.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to dev enclave at %s: %w", addr, err)
		}
		log.Info().Str("addr", addr).Msg("Connected to development enclave via TCP")
	} else {
		// Production mode: use vsock
		conn, err = vsock.Dial(cfg.CID, cfg.Port, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to enclave CID %d port %d: %w", cfg.CID, cfg.Port, err)
		}
		log.Info().Uint32("cid", cfg.CID).Uint32("port", cfg.Port).Msg("Connected to enclave via vsock")
	}

	client := &VsockClient{
		conn:    conn,
		config:  cfg,
		devMode: devMode,
	}

	// SECURITY: Perform mutual authentication handshake
	if err := client.performHandshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	return client, nil
}

// performHandshake performs the client-side (parent) mutual authentication
// SECURITY: Verifies enclave identity via attestation and shared secret
func (c *VsockClient) performHandshake() error {
	log.Info().Msg("Starting vsock mutual authentication handshake")

	// Get shared secret
	secret, err := getSharedSecret(c.devMode)
	if err != nil {
		return err
	}
	c.sharedSecret = secret

	// Set deadline for handshake
	c.conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.conn.SetDeadline(time.Time{})

	// 1. Generate our nonce
	nonce := make([]byte, handshakeNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// 2. Compute MAC with timestamp: HMAC-SHA256(secret, "parent:" || timestamp || nonce)
	timestamp := time.Now().Unix()
	macData := append([]byte(fmt.Sprintf("%d:", timestamp)), nonce...)
	mac := computeHandshakeMAC(c.sharedSecret, "parent:", macData)

	// 3. Send handshake
	msg := &handshakeMessage{
		Type:               MessageTypeHandshake,
		HandshakeNonce:     nonce,
		HandshakeMAC:       mac,
		HandshakeTimestamp: timestamp,
	}

	if err := c.writeHandshakeMessage(msg); err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	// 4. Receive handshake response
	response, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("failed to read handshake response: %w", err)
	}

	if response.Type != MessageTypeHandshakeResponse {
		return fmt.Errorf("%w: expected handshake_response, got %s", ErrHandshakeFailed, response.Type)
	}

	// SECURITY: Validate enclave's nonce
	if len(response.HandshakeNonce) != handshakeNonceSize {
		return fmt.Errorf("%w: invalid nonce size", ErrHandshakeFailed)
	}

	// SECURITY: Validate response timestamp
	now := time.Now().Unix()
	if response.HandshakeTimestamp == 0 {
		if !c.devMode {
			log.Error().Msg("SECURITY: Response missing timestamp in production mode")
			return fmt.Errorf("%w: response timestamp required", ErrHandshakeFailed)
		}
		log.Warn().Msg("SECURITY WARNING: Response without timestamp (dev mode only)")
	} else {
		age := now - response.HandshakeTimestamp
		if age > maxHandshakeAgeSeconds {
			log.Error().
				Int64("timestamp", response.HandshakeTimestamp).
				Int64("now", now).
				Int64("age_seconds", age).
				Msg("SECURITY: Response timestamp expired")
			return ErrExpiredHandshake
		}
		if response.HandshakeTimestamp > now+60 {
			log.Error().
				Int64("timestamp", response.HandshakeTimestamp).
				Int64("now", now).
				Msg("SECURITY: Response timestamp in the future")
			return ErrFutureTimestamp
		}
	}

	// 5. Verify attestation document (if provided)
	if response.Attestation != nil {
		log.Debug().
			Int("attestation_len", len(response.Attestation.Document)).
			Msg("Attestation document received")
		// TODO: In production, verify attestation with expected PCRs
		// For now, we just log that we received it
	} else if !c.devMode {
		log.Warn().Msg("SECURITY WARNING: No attestation in response (expected in production)")
	}

	// 6. Verify enclave's MAC: HMAC-SHA256(secret, "enclave:" || timestamp || enclave_nonce || attestation_hash)
	var attestHash [32]byte
	if response.Attestation != nil {
		attestHash = sha256.Sum256(response.Attestation.Document)
	}
	responseMacData := append([]byte(fmt.Sprintf("%d:", response.HandshakeTimestamp)), response.HandshakeNonce...)
	responseMacData = append(responseMacData, attestHash[:]...)
	expectedMAC := computeHandshakeMAC(c.sharedSecret, "enclave:", responseMacData)
	if !hmac.Equal(response.HandshakeMAC, expectedMAC) {
		log.Error().Msg("SECURITY: Enclave handshake MAC verification failed")
		return ErrInvalidMAC
	}

	c.authenticated = true
	log.Info().Msg("Vsock mutual authentication completed successfully")
	return nil
}

// getSharedSecret retrieves the shared secret for authentication
func getSharedSecret(devMode bool) ([]byte, error) {
	// Try production path first
	secret, err := readSecretFromFile(secretFilePath)
	if err == nil {
		return secret, nil
	}

	// Try development path
	if devMode {
		secret, err = readSecretFromFile(secretFilePathDev)
		if err == nil {
			log.Warn().Str("path", secretFilePathDev).Msg("SECURITY WARNING: Using development secret file")
			return secret, nil
		}

		// Last resort in dev mode: hardcoded test secret
		log.Warn().Msg("SECURITY WARNING: Using hardcoded development secret - not for production")
		return []byte("development-vsock-secret-32bytes!"), nil
	}

	return nil, fmt.Errorf("%w: failed to read from %s: %v", ErrNoSharedSecret, secretFilePath, err)
}

// readSecretFromFile reads and validates a hex-encoded secret from a file
func readSecretFromFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// SECURITY: Warn if file permissions are too permissive
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		log.Warn().
			Str("path", path).
			Str("mode", fmt.Sprintf("%04o", mode)).
			Msg("SECURITY WARNING: Secret file has permissive permissions, should be 0400")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret file: %w", err)
	}

	secretHex := strings.TrimSpace(string(data))
	if secretHex == "" {
		return nil, fmt.Errorf("secret file is empty")
	}

	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("invalid secret format (expected hex): %w", err)
	}

	if len(secret) < 32 {
		return nil, fmt.Errorf("secret too short: need 32 bytes, got %d", len(secret))
	}

	log.Info().Str("path", path).Msg("Loaded vsock shared secret from file")
	return secret, nil
}

// computeHandshakeMAC computes HMAC-SHA256 for handshake authentication
func computeHandshakeMAC(secret []byte, prefix string, data []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(prefix))
	h.Write(data)
	return h.Sum(nil)
}

// writeHandshakeMessage writes a handshake message
func (c *VsockClient) writeHandshakeMessage(msg *handshakeMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	if err := binary.Write(c.conn, binary.BigEndian, uint32(len(data))); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}

	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

// readHandshakeMessage reads a handshake message
func (c *VsockClient) readHandshakeMessage() (*handshakeMessage, error) {
	var length uint32
	if err := binary.Read(c.conn, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("failed to read length: %w", err)
	}

	if length > 10*1024*1024 {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	var msg handshakeMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	return &msg, nil
}

// SendMessage sends a message to the enclave and waits for a response
// This uses both write and read mutexes to ensure exclusive access for the request-reply pattern
func (c *VsockClient) SendMessage(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	// Lock write first, then read - ensures we can send and receive our response atomically
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.readMu.Lock()
	defer c.readMu.Unlock()

	log.Debug().
		Str("type", string(msg.Type)).
		Bool("has_nonce", len(msg.Nonce) > 0).
		Msg("Sending message to enclave")

	// Send message
	if err := c.writeMessage(msg); err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	log.Debug().Msg("Message sent, waiting for response...")

	// Read response
	response, err := c.readMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	log.Debug().
		Str("type", string(response.Type)).
		Bool("has_attestation", response.Attestation != nil).
		Bool("has_error", response.Error != "").
		Str("error_msg", response.Error).
		Int("payload_len", len(response.Payload)).
		Msg("Received response from enclave")

	return response, nil
}

// ReceiveMessage waits for a message from the enclave
// Only locks readMu so writes can happen concurrently
func (c *VsockClient) ReceiveMessage(ctx context.Context) (*EnclaveMessage, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	return c.readMessage()
}

// SendResponse sends a response back to the enclave
// Only locks writeMu so reads can happen concurrently
func (c *VsockClient) SendResponse(msg *EnclaveMessage) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return c.writeMessage(msg)
}

// writeMessage writes a length-prefixed JSON message
func (c *VsockClient) writeMessage(msg *EnclaveMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Write 4-byte length prefix (big-endian)
	if err := binary.Write(c.conn, binary.BigEndian, uint32(len(data))); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}

	// Write message body
	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

// readMessage reads a length-prefixed JSON message
func (c *VsockClient) readMessage() (*EnclaveMessage, error) {
	// Read 4-byte length prefix
	var length uint32
	if err := binary.Read(c.conn, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("failed to read length: %w", err)
	}

	// Sanity check - max 10MB message
	if length > 10*1024*1024 {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	// Read message body
	data := make([]byte, length)
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	// Unmarshal JSON
	var msg EnclaveMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	return &msg, nil
}

// Close closes the connection to the enclave
func (c *VsockClient) Close() error {
	return c.conn.Close()
}

// IsConnected returns true if connected to the enclave
func (c *VsockClient) IsConnected() bool {
	return c.conn != nil
}
