package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/fxamacker/cbor/v2"
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
	// SECURITY: Message size limits to prevent resource exhaustion
	maxMessageSize = 10 * 1024 * 1024 // 10MB maximum
	minMessageSize = 2                 // Minimum valid JSON "{}"
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
	ErrHandshakeFailed     = errors.New("handshake authentication failed")
	ErrInvalidMAC          = errors.New("invalid handshake MAC")
	ErrExpiredHandshake    = errors.New("handshake timestamp expired")
	ErrFutureTimestamp     = errors.New("handshake timestamp in the future")
	ErrNoSharedSecret      = errors.New("shared secret not configured")
	ErrInvalidAttestation  = errors.New("invalid attestation document")
	ErrPCRMismatch         = errors.New("PCR values do not match expected")
	ErrAttestationExpired  = errors.New("attestation document expired")
	ErrInvalidSignature    = errors.New("attestation signature verification failed")
	ErrMessageTooSmall     = errors.New("message too small")
	ErrMessageTooLarge     = errors.New("message too large")
)

// SECURITY: AWS Nitro Attestation Root CA (embedded for trust anchor)
const awsNitroRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`

// Maximum age for attestation documents (5 minutes)
const maxAttestationAgeSeconds = 300

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

	// Vault management
	EnclaveMessageTypeVaultReset EnclaveMessageType = "vault_reset"

	// General
	EnclaveMessageTypeOK              EnclaveMessageType = "ok"
	EnclaveMessageTypeError           EnclaveMessageType = "error"

	// Log forwarding (enclave sends logs to parent for CloudWatch)
	EnclaveMessageTypeLog EnclaveMessageType = "log"
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
	StorageKey   string             `json:"storage_key,omitempty"`
	StorageValue []byte             `json:"storage_value,omitempty"` // Binary data for storage operations
	Payload      json.RawMessage    `json:"payload,omitempty"`
	Error      string             `json:"error,omitempty"`

	// Attestation fields
	Nonce       []byte       `json:"nonce,omitempty"`
	Attestation *Attestation `json:"attestation,omitempty"`
	RequestID   string       `json:"request_id,omitempty"` // Echo back to mobile for correlation

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

	// Log forwarding fields
	LogLevel   string `json:"log_level,omitempty"`   // "debug", "info", "warn", "error"
	LogMessage string `json:"log_message,omitempty"` // Log message content
	LogSource  string `json:"log_source,omitempty"`  // "supervisor", "vault-manager", or owner_space
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
	requestMu     sync.Mutex // Mutex for serializing complete request-response cycles (prevents response interleaving)
	authenticated bool       // SECURITY: True if handshake completed
	sharedSecret  []byte     // Pre-shared key for authentication
	expectedPCRs  map[int][]byte // SECURITY: Expected PCR values for attestation verification
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

	// SECURITY: Load expected PCR values for attestation verification
	if !devMode {
		if err := client.loadExpectedPCRs(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to load PCR values: %w", err)
		}
	}

	// SECURITY: Perform mutual authentication handshake
	if err := client.performHandshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	return client, nil
}

// loadExpectedPCRs loads expected PCR values from SSM parameter or config
// SECURITY: PCR values are critical for attestation verification
func (c *VsockClient) loadExpectedPCRs() error {
	var pcr0Hex string

	// Try to load from SSM parameter first
	if c.config.PCR0SSMParameter != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to load AWS config, falling back to static PCR0")
		} else {
			ssmClient := ssm.NewFromConfig(cfg)
			result, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
				Name: &c.config.PCR0SSMParameter,
			})
			if err != nil {
				log.Warn().Err(err).Str("param", c.config.PCR0SSMParameter).Msg("Failed to load PCR0 from SSM, falling back to static config")
			} else if result.Parameter != nil && result.Parameter.Value != nil {
				pcr0Hex = *result.Parameter.Value
				log.Info().Str("param", c.config.PCR0SSMParameter).Msg("Loaded PCR0 from SSM parameter")
			}
		}
	}

	// Fall back to static config
	if pcr0Hex == "" && c.config.ExpectedPCR0 != "" {
		pcr0Hex = c.config.ExpectedPCR0
		log.Info().Msg("Using static PCR0 from config")
	}

	// If no PCR0 available, production mode should fail
	if pcr0Hex == "" {
		log.Error().Msg("SECURITY: No PCR0 value available for attestation verification")
		return fmt.Errorf("PCR0 value required in production mode")
	}

	// Decode hex PCR0
	pcr0, err := hex.DecodeString(pcr0Hex)
	if err != nil {
		return fmt.Errorf("invalid PCR0 hex format: %w", err)
	}

	// PCR0 should be 48 bytes (SHA-384)
	if len(pcr0) != 48 {
		return fmt.Errorf("invalid PCR0 length: expected 48 bytes, got %d", len(pcr0))
	}

	c.expectedPCRs = map[int][]byte{
		0: pcr0,
	}

	log.Info().Str("pcr0", pcr0Hex[:16]+"...").Msg("PCR0 loaded for attestation verification")
	return nil
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

	// 5. SECURITY: Verify attestation document with PCR values
	if response.Attestation != nil {
		log.Debug().
			Int("attestation_len", len(response.Attestation.Document)).
			Msg("Attestation document received")

		// SECURITY: In production, verify attestation with expected PCRs
		if !c.devMode && c.expectedPCRs != nil && len(c.expectedPCRs) > 0 {
			if err := verifyAttestation(response.Attestation, c.expectedPCRs); err != nil {
				log.Error().Err(err).Msg("SECURITY: Enclave attestation verification FAILED")
				return fmt.Errorf("%w: attestation verification failed: %v", ErrHandshakeFailed, err)
			}
			log.Info().Msg("SECURITY: Enclave attestation verified successfully")
		} else if !c.devMode {
			log.Warn().Msg("SECURITY WARNING: No PCR values configured, skipping attestation verification")
		}
	} else if !c.devMode {
		log.Error().Msg("SECURITY: No attestation in response - rejecting connection")
		return fmt.Errorf("%w: attestation required in production", ErrHandshakeFailed)
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

		// SECURITY: No hardcoded fallback - require explicit configuration
		// To set up dev mode: echo -n "your-32-byte-hex-encoded-secret" > /tmp/vettid-vsock-secret
		return nil, fmt.Errorf("%w: no secret file found at %s or %s - create dev secret file with: echo -n '<64-hex-chars>' > %s",
			ErrNoSharedSecret, secretFilePath, secretFilePathDev, secretFilePathDev)
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
// SECURITY: Implements strict bounds checking to prevent resource exhaustion
func (c *VsockClient) readHandshakeMessage() (*handshakeMessage, error) {
	var length uint32
	if err := binary.Read(c.conn, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("failed to read length: %w", err)
	}

	// SECURITY: Check message size bounds
	if length < minMessageSize {
		return nil, fmt.Errorf("%w: %d bytes (minimum %d)", ErrMessageTooSmall, length, minMessageSize)
	}
	if length > maxMessageSize {
		return nil, fmt.Errorf("%w: %d bytes (maximum %d)", ErrMessageTooLarge, length, maxMessageSize)
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
// SECURITY: Implements strict bounds checking to prevent resource exhaustion
func (c *VsockClient) readMessage() (*EnclaveMessage, error) {
	// Read 4-byte length prefix
	var length uint32
	if err := binary.Read(c.conn, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("failed to read length: %w", err)
	}

	// SECURITY: Check message size bounds
	// - Prevents zero-length allocation
	// - Prevents excessive memory allocation (DoS via resource exhaustion)
	if length < minMessageSize {
		return nil, fmt.Errorf("%w: %d bytes (minimum %d)", ErrMessageTooSmall, length, minMessageSize)
	}
	if length > maxMessageSize {
		return nil, fmt.Errorf("%w: %d bytes (maximum %d)", ErrMessageTooLarge, length, maxMessageSize)
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

// --- Attestation Verification ---

// COSESign1 represents a COSE_Sign1 structure (RFC 8152)
type COSESign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
	Payload     []byte
	Signature   []byte
}

// AttestationDocument represents the payload of a Nitro attestation
type AttestationDocument struct {
	ModuleID    string         `cbor:"module_id"`
	Timestamp   uint64         `cbor:"timestamp"`
	Digest      string         `cbor:"digest"`
	PCRs        map[int][]byte `cbor:"pcrs"`
	Certificate []byte         `cbor:"certificate"`
	CABundle    [][]byte       `cbor:"cabundle"`
	PublicKey   []byte         `cbor:"public_key,omitempty"`
	UserData    []byte         `cbor:"user_data,omitempty"`
	Nonce       []byte         `cbor:"nonce,omitempty"`
}

// verifyAttestation verifies a Nitro attestation document
// SECURITY: This is critical - it validates the enclave's identity
func verifyAttestation(attestation *HandshakeAttestation, expectedPCRs map[int][]byte) error {
	if attestation == nil || len(attestation.Document) == 0 {
		return ErrInvalidAttestation
	}

	// Check for mock attestation (development only - should be rejected in production)
	if bytes.HasPrefix(attestation.Document, []byte("MOCK_ATTESTATION:")) {
		log.Warn().Msg("SECURITY WARNING: Mock attestation detected - rejecting in production")
		return fmt.Errorf("%w: mock attestations not allowed", ErrInvalidAttestation)
	}

	// Parse COSE_Sign1 structure
	var coseSign1 COSESign1
	if err := cbor.Unmarshal(attestation.Document, &coseSign1); err != nil {
		log.Error().Err(err).Msg("Failed to parse COSE_Sign1 structure")
		return fmt.Errorf("%w: failed to parse COSE_Sign1", ErrInvalidAttestation)
	}

	// Parse the attestation document payload
	var attDoc AttestationDocument
	if err := cbor.Unmarshal(coseSign1.Payload, &attDoc); err != nil {
		log.Error().Err(err).Msg("Failed to parse attestation document payload")
		return fmt.Errorf("%w: failed to parse payload", ErrInvalidAttestation)
	}

	// 1. Verify certificate chain against AWS Nitro root CA
	if err := verifyCertificateChain(attDoc.Certificate, attDoc.CABundle); err != nil {
		log.Error().Err(err).Msg("Certificate chain verification failed")
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	// 2. Verify COSE signature using the leaf certificate's public key
	if err := verifyCOSESignature(&coseSign1, attDoc.Certificate); err != nil {
		log.Error().Err(err).Msg("COSE signature verification failed")
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	// 3. Validate timestamp (freshness check)
	// NOTE: Nitro attestation document timestamp is in milliseconds since epoch
	now := uint64(time.Now().UnixMilli())
	docAge := (now - attDoc.Timestamp) / 1000 // Convert to seconds for comparison
	if docAge > maxAttestationAgeSeconds {
		log.Error().
			Uint64("doc_timestamp", attDoc.Timestamp).
			Uint64("now", now).
			Uint64("age_seconds", docAge).
			Msg("Attestation document too old")
		return fmt.Errorf("%w: document is %d seconds old (max %d)",
			ErrAttestationExpired, docAge, maxAttestationAgeSeconds)
	}

	// 4. Verify PCR values
	if err := verifyPCRs(attDoc.PCRs, expectedPCRs); err != nil {
		return err
	}

	log.Info().
		Str("module_id", attDoc.ModuleID).
		Uint64("timestamp", attDoc.Timestamp).
		Msg("Attestation verification successful")

	return nil
}

// verifyCertificateChain verifies the certificate chain against AWS Nitro root CA
func verifyCertificateChain(leafCertDER []byte, caBundle [][]byte) error {
	// Parse the AWS Nitro root CA
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM([]byte(awsNitroRootCAPEM)) {
		return errors.New("failed to parse AWS Nitro root CA")
	}

	// Parse the leaf certificate
	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Build intermediate certificate pool from CA bundle
	intermediatePool := x509.NewCertPool()
	for i, certDER := range caBundle {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("failed to parse intermediate cert %d: %w", i, err)
		}
		intermediatePool.AddCert(cert)
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := leafCert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return nil
}

// verifyCOSESignature verifies the COSE_Sign1 signature
func verifyCOSESignature(coseSign1 *COSESign1, certDER []byte) error {
	// Parse the certificate to get the public key
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Get ECDSA public key (Nitro uses P-384)
	ecdsaPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("certificate does not contain ECDSA public key")
	}

	// Build Sig_structure for verification (COSE specification)
	// Sig_structure = ["Signature1", protected, external_aad, payload]
	sigStructure := []interface{}{
		"Signature1",
		coseSign1.Protected,
		[]byte{}, // external_aad (empty for attestation)
		coseSign1.Payload,
	}

	sigStructureBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return fmt.Errorf("failed to build Sig_structure: %w", err)
	}

	// Hash with SHA-384 (P-384 curve uses SHA-384)
	hash := sha512.Sum384(sigStructureBytes)

	// The signature is in raw R||S format, each 48 bytes for P-384
	if len(coseSign1.Signature) != 96 {
		return fmt.Errorf("invalid signature length: expected 96, got %d", len(coseSign1.Signature))
	}

	// Parse R and S from signature
	r := new(big.Int).SetBytes(coseSign1.Signature[:48])
	s := new(big.Int).SetBytes(coseSign1.Signature[48:])

	// Verify signature
	if !ecdsa.Verify(ecdsaPubKey, hash[:], r, s) {
		return errors.New("ECDSA signature verification failed")
	}

	return nil
}

// verifyPCRs compares actual PCR values against expected
func verifyPCRs(actualPCRs map[int][]byte, expectedPCRs map[int][]byte) error {
	for index, expected := range expectedPCRs {
		actual, ok := actualPCRs[index]
		if !ok {
			log.Error().Int("pcr_index", index).Msg("Missing PCR value")
			return fmt.Errorf("%w: PCR%d not present in attestation", ErrPCRMismatch, index)
		}

		if !bytes.Equal(actual, expected) {
			log.Error().
				Int("pcr_index", index).
				Str("expected", hex.EncodeToString(expected)).
				Str("actual", hex.EncodeToString(actual)).
				Msg("PCR value mismatch")
			return fmt.Errorf("%w: PCR%d mismatch", ErrPCRMismatch, index)
		}
	}

	log.Debug().
		Int("pcr_count", len(expectedPCRs)).
		Msg("All PCR values verified")

	return nil
}
