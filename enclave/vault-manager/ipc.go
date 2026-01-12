package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/rs/zerolog/log"
)

// ParentConnection manages IPC communication with the supervisor via stdin/stdout.
// Uses length-prefixed JSON framing: [4-byte BE length][JSON payload]
type ParentConnection struct {
	reader *bufio.Reader
	writer io.Writer

	readMu  sync.Mutex
	writeMu sync.Mutex
}

// NewParentConnection creates a connection to the parent supervisor.
// Reads from stdin, writes to stdout.
func NewParentConnection() *ParentConnection {
	return &ParentConnection{
		reader: bufio.NewReader(os.Stdin),
		writer: os.Stdout,
	}
}

// ReadMessage reads a message from the supervisor.
// Format: [4-byte big-endian length][JSON payload]
func (pc *ParentConnection) ReadMessage() (*IncomingMessage, error) {
	pc.readMu.Lock()
	defer pc.readMu.Unlock()

	// Read 4-byte length prefix
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(pc.reader, lengthBuf); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("parent connection closed: %w", err)
		}
		return nil, fmt.Errorf("failed to read length prefix: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf)

	// Sanity check on message size (max 10MB)
	if length > 10*1024*1024 {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	// Read JSON payload
	payload := make([]byte, length)
	if _, err := io.ReadFull(pc.reader, payload); err != nil {
		return nil, fmt.Errorf("failed to read payload: %w", err)
	}

	// Unmarshal message
	var msg IncomingMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	log.Debug().
		Int("length", int(length)).
		Str("type", string(msg.Type)).
		Str("id", msg.GetID()).
		Msg("Received message from supervisor")

	return &msg, nil
}

// WriteMessage sends a message to the supervisor.
// Format: [4-byte big-endian length][JSON payload]
func (pc *ParentConnection) WriteMessage(msg *OutgoingMessage) error {
	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	// Marshal message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Write 4-byte length prefix (big-endian)
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))

	if _, err := pc.writer.Write(lengthBuf); err != nil {
		return fmt.Errorf("failed to write length prefix: %w", err)
	}

	// Write JSON payload
	if _, err := pc.writer.Write(data); err != nil {
		return fmt.Errorf("failed to write payload: %w", err)
	}

	log.Debug().
		Int("length", len(data)).
		Str("type", string(msg.Type)).
		Str("request_id", msg.RequestID).
		Msg("Sent message to supervisor")

	return nil
}

// Close closes the parent connection.
// Note: stdin/stdout are managed by the OS, so this is mostly for interface compliance.
func (pc *ParentConnection) Close() {
	// Flush any buffered output
	if f, ok := pc.writer.(*os.File); ok {
		f.Sync()
	}
	// stdin/stdout will be closed when the process exits
}
