package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/mdlayher/vsock"
	"github.com/rs/zerolog/log"
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
	Payload    []byte             `json:"payload,omitempty"`
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
	Credential        []byte             `json:"credential,omitempty"`
}

// CredentialRequest is the request to create a new credential
type CredentialRequest struct {
	EncryptedPIN []byte `json:"encrypted_pin"` // PIN encrypted to enclave's pubkey
	AuthType     string `json:"auth_type"`     // "pin", "password", "pattern"
}

// VsockClient handles communication with the enclave
type VsockClient struct {
	conn    net.Conn
	config  EnclaveConfig
	devMode bool
	readMu  sync.Mutex // Mutex for read operations
	writeMu sync.Mutex // Mutex for write operations
}

// NewVsockClient creates a new vsock client to communicate with the enclave
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

	return &VsockClient{
		conn:    conn,
		config:  cfg,
		devMode: devMode,
	}, nil
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
