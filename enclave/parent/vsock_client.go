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

	// General
	EnclaveMessageTypeOK              EnclaveMessageType = "ok"
	EnclaveMessageTypeError           EnclaveMessageType = "error"
)

// EnclaveMessage is the wire format for parent-enclave communication
type EnclaveMessage struct {
	Type       EnclaveMessageType `json:"type"`
	OwnerSpace string             `json:"owner_space,omitempty"`
	Subject    string             `json:"subject,omitempty"`
	ReplyTo    string             `json:"reply_to,omitempty"`
	StorageKey string             `json:"storage_key,omitempty"`
	Payload    []byte             `json:"payload,omitempty"`
	Error      string             `json:"error,omitempty"`
}

// VsockClient handles communication with the enclave
type VsockClient struct {
	conn    net.Conn
	config  EnclaveConfig
	devMode bool
	mu      sync.Mutex
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
func (c *VsockClient) SendMessage(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Send message
	if err := c.writeMessage(msg); err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	// Read response
	response, err := c.readMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return response, nil
}

// ReceiveMessage waits for a message from the enclave
func (c *VsockClient) ReceiveMessage(ctx context.Context) (*EnclaveMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.readMessage()
}

// SendResponse sends a response back to the enclave
func (c *VsockClient) SendResponse(msg *EnclaveMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()

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
