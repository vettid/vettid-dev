package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/mdlayher/vsock"
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

	// Error
	MessageTypeError MessageType = "error"
	MessageTypeOK    MessageType = "ok"
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

	// Error
	Error string `json:"error,omitempty"`
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
