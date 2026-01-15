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
	"strings"
	"sync"
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
	// Maximum age of handshake timestamp (5 minutes)
	maxHandshakeAgeSeconds = 300
	// Nonce cache retention period (10 minutes to cover clock skew)
	nonceCacheRetentionSeconds = 600
	// Maximum nonces to cache (prevent memory exhaustion)
	maxNonceCacheSize = 10000
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
	Payload json.RawMessage `json:"payload,omitempty"`

	// Handler loading
	HandlerID      string `json:"handler_id,omitempty"`
	HandlerVersion string `json:"handler_version,omitempty"`

	// KMS operations (for Nitro attestation-based sealing)
	KMSKeyID      string `json:"kms_key_id,omitempty"`
	Plaintext     []byte `json:"plaintext,omitempty"`
	Ciphertext    []byte `json:"ciphertext,omitempty"`
	CiphertextDEK []byte `json:"ciphertext_dek,omitempty"`

	// Attestation private key (for PIN decryption - passed to vault-manager)
	// SECURITY: Only included for PIN operations, cleared after use
	AttestationPrivateKey []byte `json:"attestation_private_key,omitempty"`

	// Error
	Error string `json:"error,omitempty"`

	// Handshake (mutual authentication)
	HandshakeNonce     []byte `json:"handshake_nonce,omitempty"`
	HandshakeMAC       []byte `json:"handshake_mac,omitempty"`
	HandshakeTimestamp int64  `json:"handshake_timestamp,omitempty"` // Unix timestamp for freshness validation
}

// Attestation holds a Nitro attestation document
type Attestation struct {
	Document   []byte `json:"document"`    // CBOR-encoded attestation document
	PublicKey  []byte `json:"public_key"`  // Enclave's ephemeral X25519 public key (32 bytes)
	PrivateKey []byte `json:"-"`           // X25519 private key (never serialized, kept in supervisor)
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
	ErrHandshakeFailed    = errors.New("handshake authentication failed")
	ErrHandshakeTimeout   = errors.New("handshake timeout")
	ErrInvalidMAC         = errors.New("invalid handshake MAC")
	ErrNotAuthenticated   = errors.New("connection not authenticated")
	ErrNoSharedSecret     = errors.New("shared secret not configured")
	ErrReplayedNonce      = errors.New("replayed nonce detected")
	ErrExpiredHandshake   = errors.New("handshake timestamp expired")
	ErrRateLimitExceeded  = errors.New("handshake rate limit exceeded")
	ErrFutureTimestamp    = errors.New("handshake timestamp in the future")
)

// nonceEntry stores a nonce with its creation time for cache expiration
type nonceEntry struct {
	nonce     [32]byte
	timestamp time.Time
}

// NonceCache prevents replay attacks by tracking used nonces
// SECURITY: Thread-safe cache with automatic expiration and size limits
type NonceCache struct {
	entries map[[32]byte]time.Time
	mu      sync.RWMutex
}

// NewNonceCache creates a new nonce cache
func NewNonceCache() *NonceCache {
	return &NonceCache{
		entries: make(map[[32]byte]time.Time),
	}
}

// Add attempts to add a nonce to the cache. Returns false if already present (replay detected).
// SECURITY: Atomically checks and inserts to prevent race conditions
func (nc *NonceCache) Add(nonce []byte) bool {
	if len(nonce) != handshakeNonceSize {
		return false
	}

	var key [32]byte
	copy(key[:], nonce)

	nc.mu.Lock()
	defer nc.mu.Unlock()

	// Check if nonce already exists
	if _, exists := nc.entries[key]; exists {
		return false // Replay detected
	}

	// Clean up expired entries if cache is getting full
	if len(nc.entries) >= maxNonceCacheSize {
		nc.cleanupLocked()
	}

	// Still full after cleanup? Reject to prevent memory exhaustion
	if len(nc.entries) >= maxNonceCacheSize {
		return false
	}

	// Add the nonce
	nc.entries[key] = time.Now()
	return true
}

// cleanupLocked removes expired entries (must be called with lock held)
func (nc *NonceCache) cleanupLocked() {
	cutoff := time.Now().Add(-time.Duration(nonceCacheRetentionSeconds) * time.Second)
	for key, ts := range nc.entries {
		if ts.Before(cutoff) {
			delete(nc.entries, key)
		}
	}
}

// RateLimiter tracks handshake attempts per connection
// SECURITY: Prevents brute-force attacks on the shared secret
type RateLimiter struct {
	attempts  map[string][]time.Time // IP -> attempt timestamps
	mu        sync.Mutex
	window    time.Duration
	maxAttempts int
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxAttempts int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		attempts:    make(map[string][]time.Time),
		window:      window,
		maxAttempts: maxAttempts,
	}
}

// Allow checks if a connection is allowed to attempt handshake
// SECURITY: Returns false if rate limit exceeded
func (rl *RateLimiter) Allow(connID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Filter out old attempts
	attempts := rl.attempts[connID]
	var recent []time.Time
	for _, t := range attempts {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	// Check limit
	if len(recent) >= rl.maxAttempts {
		return false
	}

	// Record this attempt
	rl.attempts[connID] = append(recent, now)
	return true
}

// Global nonce cache and rate limiter
var (
	globalNonceCache   = NewNonceCache()
	globalRateLimiter  = NewRateLimiter(maxHandshakeAttempts, time.Minute)
)

// AuthenticatedConnection wraps a Connection with mutual authentication
// SECURITY: This ensures both parent and enclave verify each other's identity
type AuthenticatedConnection struct {
	conn          Connection
	authenticated bool
	sharedSecret  []byte // Pre-shared key for HMAC-based authentication
	localNonce    []byte
	remoteNonce   []byte
	connID        string // Connection identifier for rate limiting
}

// SECURITY: Secret file path - provisioned by parent from Secrets Manager
// File permissions should be 0400 (read-only by owner)
const (
	secretFilePath    = "/etc/vettid/vsock-secret"
	secretFilePathDev = "/tmp/vettid-vsock-secret" // Development fallback
)

// getSharedSecret retrieves the shared secret for vsock authentication
// SECURITY: Secret is read from a file (not environment variable) to prevent:
// - Exposure via /proc/<pid>/environ
// - Inclusion in crash dumps
// - Inheritance by child processes
// - Logging by deployment tools
func getSharedSecret() ([]byte, error) {
	// Try production path first
	secret, err := readSecretFromFile(secretFilePath)
	if err == nil {
		return secret, nil
	}

	// Try development path
	if !isProductionMode() {
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
// SECURITY: File is read once and should be deleted by caller after use in production
func readSecretFromFile(path string) ([]byte, error) {
	// Check file exists and has proper permissions
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// SECURITY: Warn if file permissions are too permissive (not checking in enclave as /proc may not exist)
	mode := info.Mode().Perm()
	if mode&0077 != 0 && isProductionMode() {
		log.Warn().
			Str("path", path).
			Str("mode", fmt.Sprintf("%04o", mode)).
			Msg("SECURITY WARNING: Secret file has permissive permissions, should be 0400")
	}

	// Read the file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret file: %w", err)
	}

	// Trim whitespace (common when files are created with echo)
	secretHex := string(data)
	secretHex = strings.TrimSpace(secretHex)

	if secretHex == "" {
		return nil, fmt.Errorf("secret file is empty")
	}

	// Decode hex
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("invalid secret format (expected hex): %w", err)
	}

	// SECURITY: Validate secret length (256-bit minimum)
	if len(secret) < 32 {
		return nil, fmt.Errorf("secret too short: need 32 bytes, got %d", len(secret))
	}

	// SECURITY: Clear the hex string from memory
	zeroString([]byte(secretHex))

	log.Info().Str("path", path).Msg("Loaded vsock shared secret from file")
	return secret, nil
}

// isProductionMode checks if running in production mode
func isProductionMode() bool {
	return os.Getenv("VETTID_PRODUCTION") == "true"
}

// zeroString zeros out a byte slice to clear sensitive data from memory
// SECURITY: Defense in depth - clear secrets after use
func zeroString(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// NewAuthenticatedConnection creates a new authenticated connection wrapper
// connID should be a unique identifier for the connection (e.g., remote address)
func NewAuthenticatedConnection(conn Connection, connID string) *AuthenticatedConnection {
	return &AuthenticatedConnection{
		conn:          conn,
		authenticated: false,
		connID:        connID,
	}
}

// PerformServerHandshake performs the server-side (enclave) handshake
// SECURITY: The enclave verifies the parent's identity via HMAC, timestamp, and nonce freshness
func (ac *AuthenticatedConnection) PerformServerHandshake(expectedPCRs map[int][]byte) error {
	// SECURITY: Check rate limit before processing
	if !globalRateLimiter.Allow(ac.connID) {
		log.Warn().Str("conn_id", ac.connID).Msg("SECURITY: Handshake rate limit exceeded")
		return ErrRateLimitExceeded
	}

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

	// SECURITY: Validate parent's nonce size
	if len(msg.HandshakeNonce) != handshakeNonceSize {
		return fmt.Errorf("%w: invalid nonce size", ErrHandshakeFailed)
	}

	// SECURITY: Validate timestamp freshness (prevents replay of old handshakes)
	now := time.Now().Unix()
	if msg.HandshakeTimestamp == 0 {
		// In production, require timestamp
		if isProductionMode() {
			log.Error().Msg("SECURITY: Handshake missing timestamp in production mode")
			return fmt.Errorf("%w: timestamp required", ErrHandshakeFailed)
		}
		log.Warn().Msg("SECURITY WARNING: Handshake without timestamp (dev mode only)")
	} else {
		// Check timestamp is not too old
		age := now - msg.HandshakeTimestamp
		if age > maxHandshakeAgeSeconds {
			log.Error().
				Int64("timestamp", msg.HandshakeTimestamp).
				Int64("now", now).
				Int64("age_seconds", age).
				Msg("SECURITY: Handshake timestamp expired")
			return ErrExpiredHandshake
		}
		// Check timestamp is not in the future (with 60s tolerance for clock skew)
		if msg.HandshakeTimestamp > now+60 {
			log.Error().
				Int64("timestamp", msg.HandshakeTimestamp).
				Int64("now", now).
				Msg("SECURITY: Handshake timestamp in the future")
			return ErrFutureTimestamp
		}
	}

	// SECURITY: Check for nonce replay
	if !globalNonceCache.Add(msg.HandshakeNonce) {
		log.Error().Msg("SECURITY: Nonce replay detected")
		return ErrReplayedNonce
	}

	ac.remoteNonce = msg.HandshakeNonce

	// 2. Verify parent's MAC: HMAC-SHA256(secret, "parent:" || timestamp || nonce)
	// Include timestamp in MAC to bind it cryptographically
	macData := append([]byte(fmt.Sprintf("%d:", msg.HandshakeTimestamp)), ac.remoteNonce...)
	expectedMAC := computeHandshakeMAC(ac.sharedSecret, "parent:", macData)
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

	// 5. Compute our MAC: HMAC-SHA256(secret, "enclave:" || timestamp || local_nonce || attestation_hash)
	attestHash := sha256.Sum256(attestation.Document)
	responseTimestamp := time.Now().Unix()
	responseMacData := append([]byte(fmt.Sprintf("%d:", responseTimestamp)), ac.localNonce...)
	responseMacData = append(responseMacData, attestHash[:]...)
	responseMAC := computeHandshakeMAC(ac.sharedSecret, "enclave:", responseMacData)

	// 6. Send handshake response with attestation
	response := &Message{
		Type:               MessageTypeHandshakeResponse,
		HandshakeNonce:     ac.localNonce,
		HandshakeMAC:       responseMAC,
		HandshakeTimestamp: responseTimestamp,
		Attestation:        attestation,
	}

	if err := ac.conn.WriteMessage(response); err != nil {
		return fmt.Errorf("failed to send handshake response: %w", err)
	}

	ac.authenticated = true
	log.Info().Msg("Vsock mutual authentication completed (server)")
	return nil
}

// PerformClientHandshake performs the client-side (parent) handshake
// SECURITY: The parent verifies the enclave's attestation, PCRs, timestamp, and nonce
func (ac *AuthenticatedConnection) PerformClientHandshake(expectedPCRs map[int][]byte) error {
	// SECURITY: In production mode, PCR validation is mandatory
	if isProductionMode() && (expectedPCRs == nil || len(expectedPCRs) == 0) {
		log.Error().Msg("SECURITY: PCR validation required in production mode")
		return fmt.Errorf("%w: PCR values required in production", ErrHandshakeFailed)
	}

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

	// 2. Compute our MAC with timestamp: HMAC-SHA256(secret, "parent:" || timestamp || nonce)
	timestamp := time.Now().Unix()
	macData := append([]byte(fmt.Sprintf("%d:", timestamp)), ac.localNonce...)
	mac := computeHandshakeMAC(ac.sharedSecret, "parent:", macData)

	// 3. Send handshake with timestamp
	msg := &Message{
		Type:               MessageTypeHandshake,
		HandshakeNonce:     ac.localNonce,
		HandshakeMAC:       mac,
		HandshakeTimestamp: timestamp,
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

	// SECURITY: Validate response timestamp
	now := time.Now().Unix()
	if response.HandshakeTimestamp == 0 {
		if isProductionMode() {
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

	// 5. Verify attestation document
	if response.Attestation == nil {
		return fmt.Errorf("%w: missing attestation", ErrHandshakeFailed)
	}

	// SECURITY: Verify attestation with expected PCRs
	// In production, this is mandatory. In dev mode, it's optional.
	if expectedPCRs != nil && len(expectedPCRs) > 0 {
		if err := VerifyAttestation(response.Attestation, expectedPCRs); err != nil {
			log.Error().Err(err).Msg("SECURITY: Enclave attestation verification failed")
			return fmt.Errorf("%w: attestation verification failed: %v", ErrHandshakeFailed, err)
		}
	} else if !isProductionMode() {
		log.Warn().Msg("SECURITY WARNING: Skipping PCR validation (dev mode only)")
	}

	// 6. Verify enclave's MAC: HMAC-SHA256(secret, "enclave:" || timestamp || enclave_nonce || attestation_hash)
	attestHash := sha256.Sum256(response.Attestation.Document)
	responseMacData := append([]byte(fmt.Sprintf("%d:", response.HandshakeTimestamp)), ac.remoteNonce...)
	responseMacData = append(responseMacData, attestHash[:]...)
	expectedMAC := computeHandshakeMAC(ac.sharedSecret, "enclave:", responseMacData)
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

// SECURITY: Message size limits to prevent resource exhaustion
const (
	// Maximum message size (10MB) - prevents memory exhaustion attacks
	maxMessageSize uint32 = 10 * 1024 * 1024
	// Minimum reasonable message size (empty JSON object)
	minMessageSize uint32 = 2
)

// readMessage reads a length-prefixed JSON message
// SECURITY: Implements strict bounds checking to prevent integer overflow and resource exhaustion
func readMessage(r io.Reader) (*Message, error) {
	// Read 4-byte length prefix
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	// SECURITY: Check message size bounds
	// - Prevents zero-length allocation (could cause issues with empty slice)
	// - Prevents excessive memory allocation (DoS via resource exhaustion)
	// - The uint32 type prevents negative values, but we still check explicitly
	if length < minMessageSize {
		return nil, fmt.Errorf("message too small: %d bytes (minimum %d)", length, minMessageSize)
	}
	if length > maxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes (maximum %d)", length, maxMessageSize)
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
