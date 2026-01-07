package main

import (
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
	"time"

	"github.com/mdlayher/vsock"
	"github.com/rs/zerolog/log"
)

// MessageType identifies the type of message being sent over vsock
type MessageType string

const (
	// Vault operations (from parent, routed by NATS subject)
	MessageTypeVaultOp       MessageType = "vault_op"        // Incoming NATS message to vault
	MessageTypeVaultResponse MessageType = "vault_response"  // Response from vault

	// NATS publish (from vault to parent)
	MessageTypeNATSPublish MessageType = "nats_publish" // Vault wants to publish to NATS

	// Attestation
	MessageTypeAttestationRequest  MessageType = "attestation_request"
	MessageTypeAttestationResponse MessageType = "attestation_response"

	// Credential operations
	MessageTypeCredentialCreate   MessageType = "credential_create"
	MessageTypeCredentialUnseal   MessageType = "credential_unseal"
	MessageTypeCredentialResponse MessageType = "credential_response"

	// Storage operations (proxied through parent)
	MessageTypeStorageGet      MessageType = "storage_get"
	MessageTypeStoragePut      MessageType = "storage_put"
	MessageTypeStorageResponse MessageType = "storage_response"

	// Health check
	MessageTypeHealthCheck    MessageType = "health_check"
	MessageTypeHealthResponse MessageType = "health_response"

	// Handler loading (enclave requests handler from parent)
	MessageTypeHandlerGet      MessageType = "handler_get"
	MessageTypeHandlerResponse MessageType = "handler_response"

	// KMS operations (for Nitro attestation-based sealing)
	MessageTypeKMSEncrypt  MessageType = "kms_encrypt"
	MessageTypeKMSDecrypt  MessageType = "kms_decrypt"
	MessageTypeKMSResponse MessageType = "kms_response"

	// Error
	MessageTypeError MessageType = "error"
	MessageTypeOK    MessageType = "ok"

	// Mutual authentication handshake
	MessageTypeHandshake         MessageType = "handshake"
	MessageTypeHandshakeResponse MessageType = "handshake_response"
)

// SECURITY: Handshake constants
const (
	// Maximum time allowed for handshake completion
	handshakeTimeout = 10 * time.Second
	// Nonce size for handshake challenge
	handshakeNonceSize = 32
	// Maximum handshake attempts before blocking connection
	maxHandshakeAttempts = 3
)

// Message is the wire format for vsock communication
type Message struct {
	Type       MessageType `json:"type"`
	OwnerSpace string      `json:"owner_space,omitempty"`
	RequestID  string      `json:"request_id,omitempty"`

	// NATS routing (for vault_op and nats_publish)
	Subject string `json:"subject,omitempty"` // NATS subject (e.g., "OwnerSpace.user-123.forVault.call.initiate")
	ReplyTo string `json:"reply_to,omitempty"` // NATS reply subject

	// Attestation
	Nonce       []byte       `json:"nonce,omitempty"`
	Attestation *Attestation `json:"attestation,omitempty"`

	// Credential operations
	CredentialRequest *CredentialRequest `json:"credential_request,omitempty"`
	SealedCredential  []byte             `json:"sealed_credential,omitempty"`
	Challenge         *Challenge         `json:"challenge,omitempty"`
	Credential        []byte             `json:"credential,omitempty"`
	UnsealResult      *UnsealResult      `json:"unseal_result,omitempty"`

	// Storage operations
	StorageKey   string `json:"storage_key,omitempty"`
	StorageValue []byte `json:"storage_value,omitempty"`

	// Generic payload (JSON-encoded data)
	Payload []byte `json:"payload,omitempty"`

	// Handler loading
	HandlerID      string `json:"handler_id,omitempty"`
	HandlerVersion string `json:"handler_version,omitempty"`

	// KMS operations (for Nitro attestation-based sealing)
	KMSKeyID      string `json:"kms_key_id,omitempty"`
	Plaintext     []byte `json:"plaintext,omitempty"`
	Ciphertext    []byte `json:"ciphertext,omitempty"`
	CiphertextDEK []byte `json:"ciphertext_dek,omitempty"`

	// Error
	Error string `json:"error,omitempty"`

	// Handshake (mutual authentication)
	HandshakeNonce []byte `json:"handshake_nonce,omitempty"`
	HandshakeMAC   []byte `json:"handshake_mac,omitempty"`
}

// Attestation holds a Nitro attestation document
type Attestation struct {
	Document  []byte `json:"document"`  // CBOR-encoded attestation document
	PublicKey []byte `json:"public_key"` // Enclave's ephemeral public key
}

// CredentialRequest is the request to create a new credential
type CredentialRequest struct {
	EncryptedPIN []byte `json:"encrypted_pin"` // PIN encrypted to enclave's pubkey
	AuthType     string `json:"auth_type"`     // "pin", "password", "pattern"
}

// Challenge is a PIN/password challenge for credential operations
type Challenge struct {
	ChallengeID string `json:"challenge_id"`
	Response    []byte `json:"response"` // Encrypted response
}

// UnsealResult is the result of unsealing a credential
type UnsealResult struct {
	SessionToken []byte `json:"session_token"` // Token for subsequent operations
	ExpiresAt    int64  `json:"expires_at"`    // Token expiry timestamp
}

// HealthStatus is the supervisor health status
type HealthStatus struct {
	Healthy       bool   `json:"healthy"`
	ActiveVaults  int    `json:"active_vaults"`
	TotalVaults   int    `json:"total_vaults"`
	MemoryUsedMB  int    `json:"memory_used_mb"`
	MemoryTotalMB int    `json:"memory_total_mb"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	Version       string `json:"version"`
}

// SECURITY: Authentication errors
var (
	ErrHandshakeFailed   = errors.New("handshake authentication failed")
	ErrHandshakeTimeout  = errors.New("handshake timeout")
	ErrInvalidMAC        = errors.New("invalid handshake MAC")
	ErrNotAuthenticated  = errors.New("connection not authenticated")
	ErrNoSharedSecret    = errors.New("shared secret not configured")
)

// AuthenticatedConnection wraps a Connection with mutual authentication
// SECURITY: This ensures both parent and enclave verify each other's identity
type AuthenticatedConnection struct {
	conn          Connection
	authenticated bool
	sharedSecret  []byte // Pre-shared key for HMAC-based authentication
	localNonce    []byte
	remoteNonce   []byte
}

// getSharedSecret retrieves the shared secret for vsock authentication
// SECURITY: This secret is provisioned via KMS and enclave attestation
func getSharedSecret() ([]byte, error) {
	// In production, this comes from KMS decryption using attestation
	// The parent encrypts the secret to the enclave's PCRs
	secretHex := os.Getenv("VSOCK_SHARED_SECRET")
	if secretHex == "" {
		// Development mode: use hardcoded test secret
		if os.Getenv("VETTID_PRODUCTION") != "true" {
			log.Warn().Msg("SECURITY WARNING: Using development shared secret - not for production")
			return []byte("development-vsock-secret-32bytes!"), nil
		}
		return nil, ErrNoSharedSecret
	}

	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("invalid shared secret format: %w", err)
	}

	// SECURITY: Validate secret length (256-bit minimum)
	if len(secret) < 32 {
		return nil, fmt.Errorf("shared secret too short: need 32 bytes, got %d", len(secret))
	}

	return secret, nil
}

// NewAuthenticatedConnection creates a new authenticated connection wrapper
func NewAuthenticatedConnection(conn Connection) *AuthenticatedConnection {
	return &AuthenticatedConnection{
		conn:          conn,
		authenticated: false,
	}
}

// PerformServerHandshake performs the server-side (enclave) handshake
// SECURITY: The enclave verifies the parent's identity via HMAC and provides attestation
func (ac *AuthenticatedConnection) PerformServerHandshake(expectedPCRs map[int][]byte) error {
	secret, err := getSharedSecret()
	if err != nil {
		return err
	}
	ac.sharedSecret = secret

	// Set deadline for handshake
	if tcpConn, ok := ac.conn.(*tcpConnection); ok {
		tcpConn.conn.SetDeadline(time.Now().Add(handshakeTimeout))
		defer tcpConn.conn.SetDeadline(time.Time{})
	}

	// 1. Receive handshake from parent
	msg, err := ac.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read handshake: %w", err)
	}

	if msg.Type != MessageTypeHandshake {
		return fmt.Errorf("%w: expected handshake, got %s", ErrHandshakeFailed, msg.Type)
	}

	// SECURITY: Validate parent's nonce
	if len(msg.HandshakeNonce) != handshakeNonceSize {
		return fmt.Errorf("%w: invalid nonce size", ErrHandshakeFailed)
	}
	ac.remoteNonce = msg.HandshakeNonce

	// 2. Verify parent's MAC: HMAC-SHA256(secret, "parent:" || nonce)
	expectedMAC := computeHandshakeMAC(ac.sharedSecret, "parent:", ac.remoteNonce)
	if !hmac.Equal(msg.HandshakeMAC, expectedMAC) {
		log.Error().Msg("SECURITY: Parent handshake MAC verification failed")
		return ErrInvalidMAC
	}

	// 3. Generate our nonce
	ac.localNonce = make([]byte, handshakeNonceSize)
	if _, err := rand.Read(ac.localNonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// 4. Generate attestation with combined nonce (proves enclave identity)
	combinedNonce := append(ac.remoteNonce, ac.localNonce...)
	attestation, err := GenerateAttestation(combinedNonce)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %w", err)
	}

	// 5. Compute our MAC: HMAC-SHA256(secret, "enclave:" || local_nonce || attestation_hash)
	attestHash := sha256.Sum256(attestation.Document)
	responseMAC := computeHandshakeMAC(ac.sharedSecret, "enclave:", append(ac.localNonce, attestHash[:]...))

	// 6. Send handshake response with attestation
	response := &Message{
		Type:           MessageTypeHandshakeResponse,
		HandshakeNonce: ac.localNonce,
		HandshakeMAC:   responseMAC,
		Attestation:    attestation,
	}

	if err := ac.conn.WriteMessage(response); err != nil {
		return fmt.Errorf("failed to send handshake response: %w", err)
	}

	ac.authenticated = true
	log.Info().Msg("Vsock mutual authentication completed (server)")
	return nil
}

// PerformClientHandshake performs the client-side (parent) handshake
// SECURITY: The parent verifies the enclave's attestation and PCRs
func (ac *AuthenticatedConnection) PerformClientHandshake(expectedPCRs map[int][]byte) error {
	secret, err := getSharedSecret()
	if err != nil {
		return err
	}
	ac.sharedSecret = secret

	// 1. Generate our nonce
	ac.localNonce = make([]byte, handshakeNonceSize)
	if _, err := rand.Read(ac.localNonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// 2. Compute our MAC: HMAC-SHA256(secret, "parent:" || nonce)
	mac := computeHandshakeMAC(ac.sharedSecret, "parent:", ac.localNonce)

	// 3. Send handshake
	msg := &Message{
		Type:           MessageTypeHandshake,
		HandshakeNonce: ac.localNonce,
		HandshakeMAC:   mac,
	}

	if err := ac.conn.WriteMessage(msg); err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	// 4. Receive handshake response
	response, err := ac.conn.ReadMessage()
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
	ac.remoteNonce = response.HandshakeNonce

	// 5. Verify attestation document
	if response.Attestation == nil {
		return fmt.Errorf("%w: missing attestation", ErrHandshakeFailed)
	}

	// Verify attestation with expected PCRs (if provided)
	if expectedPCRs != nil {
		if err := VerifyAttestation(response.Attestation, expectedPCRs); err != nil {
			log.Error().Err(err).Msg("SECURITY: Enclave attestation verification failed")
			return fmt.Errorf("%w: attestation verification failed: %v", ErrHandshakeFailed, err)
		}
	}

	// 6. Verify enclave's MAC: HMAC-SHA256(secret, "enclave:" || enclave_nonce || attestation_hash)
	attestHash := sha256.Sum256(response.Attestation.Document)
	expectedMAC := computeHandshakeMAC(ac.sharedSecret, "enclave:", append(ac.remoteNonce, attestHash[:]...))
	if !hmac.Equal(response.HandshakeMAC, expectedMAC) {
		log.Error().Msg("SECURITY: Enclave handshake MAC verification failed")
		return ErrInvalidMAC
	}

	ac.authenticated = true
	log.Info().Msg("Vsock mutual authentication completed (client)")
	return nil
}

// ReadMessage reads a message (requires authentication)
func (ac *AuthenticatedConnection) ReadMessage() (*Message, error) {
	if !ac.authenticated {
		return nil, ErrNotAuthenticated
	}
	return ac.conn.ReadMessage()
}

// WriteMessage writes a message (requires authentication)
func (ac *AuthenticatedConnection) WriteMessage(msg *Message) error {
	if !ac.authenticated {
		return ErrNotAuthenticated
	}
	return ac.conn.WriteMessage(msg)
}

// Close closes the underlying connection
func (ac *AuthenticatedConnection) Close() error {
	return ac.conn.Close()
}

// IsAuthenticated returns whether the connection is authenticated
func (ac *AuthenticatedConnection) IsAuthenticated() bool {
	return ac.authenticated
}

// computeHandshakeMAC computes HMAC-SHA256 for handshake authentication
func computeHandshakeMAC(secret []byte, prefix string, data []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(prefix))
	h.Write(data)
	return h.Sum(nil)
}

// Listener is the interface for accepting connections
type Listener interface {
	Accept() (Connection, error)
	Close() error
}

// Connection is the interface for reading/writing messages
type Connection interface {
	ReadMessage() (*Message, error)
	WriteMessage(msg *Message) error
	Close() error
}

// vsockListener implements Listener for vsock connections
type vsockListener struct {
	listener *vsock.Listener
}

// NewVsockListener creates a new vsock listener
func NewVsockListener(port uint32) (Listener, error) {
	// CID 3 is always the enclave's own CID
	// We listen for connections from the parent (CID 2 or any)
	l, err := vsock.Listen(port, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create vsock listener: %w", err)
	}
	return &vsockListener{listener: l}, nil
}

func (l *vsockListener) Accept() (Connection, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	return &vsockConnection{conn: conn}, nil
}

func (l *vsockListener) Close() error {
	return l.listener.Close()
}

// vsockConnection implements Connection for vsock
type vsockConnection struct {
	conn net.Conn
}

func (c *vsockConnection) ReadMessage() (*Message, error) {
	return readMessage(c.conn)
}

func (c *vsockConnection) WriteMessage(msg *Message) error {
	return writeMessage(c.conn, msg)
}

func (c *vsockConnection) Close() error {
	return c.conn.Close()
}

// tcpListener implements Listener for TCP (dev mode)
type tcpListener struct {
	listener net.Listener
}

// NewTCPListener creates a new TCP listener for development mode
func NewTCPListener(port uint16) (Listener, error) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP listener: %w", err)
	}
	return &tcpListener{listener: l}, nil
}

func (l *tcpListener) Accept() (Connection, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tcpConnection{conn: conn}, nil
}

func (l *tcpListener) Close() error {
	return l.listener.Close()
}

// tcpConnection implements Connection for TCP
type tcpConnection struct {
	conn net.Conn
}

func (c *tcpConnection) ReadMessage() (*Message, error) {
	return readMessage(c.conn)
}

func (c *tcpConnection) WriteMessage(msg *Message) error {
	return writeMessage(c.conn, msg)
}

func (c *tcpConnection) Close() error {
	return c.conn.Close()
}

// readMessage reads a length-prefixed JSON message
func readMessage(r io.Reader) (*Message, error) {
	// Read 4-byte length prefix
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	// Sanity check - max 10MB message
	if length > 10*1024*1024 {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	// Read message body
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	// Unmarshal JSON
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	return &msg, nil
}

// writeMessage writes a length-prefixed JSON message
func writeMessage(w io.Writer, msg *Message) error {
	// Marshal to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Write 4-byte length prefix
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}

	// Write message body
	_, err = w.Write(data)
	return err
}
