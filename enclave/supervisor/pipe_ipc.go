package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// PipeConnection manages IPC communication with a vault-manager process via pipes.
// It uses length-prefixed JSON framing: [4-byte BE length][JSON payload]
type PipeConnection struct {
	stdin  io.WriteCloser // Write to child's stdin
	stdout io.ReadCloser  // Read from child's stdout
	reader *bufio.Reader

	writeMu sync.Mutex
	readMu  sync.Mutex
}

// NewPipeConnection creates a new pipe connection wrapper
func NewPipeConnection(stdin io.WriteCloser, stdout io.ReadCloser) *PipeConnection {
	return &PipeConnection{
		stdin:  stdin,
		stdout: stdout,
		reader: bufio.NewReader(stdout),
	}
}

// WriteMessage sends a message to the vault-manager process via pipe.
// Format: [4-byte big-endian length][JSON payload]
func (pc *PipeConnection) WriteMessage(msg *Message) error {
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

	if _, err := pc.stdin.Write(lengthBuf); err != nil {
		return fmt.Errorf("failed to write length prefix: %w", err)
	}

	// Write JSON payload
	if _, err := pc.stdin.Write(data); err != nil {
		return fmt.Errorf("failed to write payload: %w", err)
	}

	log.Debug().
		Int("length", len(data)).
		Str("type", string(msg.Type)).
		Msg("Wrote message to pipe")

	return nil
}

// ReadMessage reads a message from the vault-manager process via pipe.
// Format: [4-byte big-endian length][JSON payload]
func (pc *PipeConnection) ReadMessage() (*Message, error) {
	pc.readMu.Lock()
	defer pc.readMu.Unlock()

	// Read 4-byte length prefix
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(pc.reader, lengthBuf); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("pipe closed: %w", err)
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
	var msg Message
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	log.Debug().
		Int("length", int(length)).
		Str("type", string(msg.Type)).
		Msg("Read message from pipe")

	return &msg, nil
}

// ReadMessageWithTimeout reads a message with a timeout
func (pc *PipeConnection) ReadMessageWithTimeout(timeout time.Duration) (*Message, error) {
	type result struct {
		msg *Message
		err error
	}

	resultChan := make(chan result, 1)

	go func() {
		msg, err := pc.ReadMessage()
		resultChan <- result{msg, err}
	}()

	select {
	case r := <-resultChan:
		return r.msg, r.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("read timeout after %v", timeout)
	}
}

// Close closes both pipes
func (pc *PipeConnection) Close() error {
	var errs []error

	if pc.stdin != nil {
		if err := pc.stdin.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close stdin: %w", err))
		}
	}

	if pc.stdout != nil {
		if err := pc.stdout.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close stdout: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("pipe close errors: %v", errs)
	}

	return nil
}

// SendAndReceive sends a message and waits for a response
func (pc *PipeConnection) SendAndReceive(msg *Message, timeout time.Duration) (*Message, error) {
	if err := pc.WriteMessage(msg); err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	response, err := pc.ReadMessageWithTimeout(timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to receive response: %w", err)
	}

	return response, nil
}
