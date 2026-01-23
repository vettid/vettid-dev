package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// ParentConnection handles IPC with the supervisor via stdin/stdout
type ParentConnection struct {
	reader  *bufio.Reader
	writer  *bufio.Writer
	readMu  sync.Mutex
	writeMu sync.Mutex
}

// NewParentConnection creates a new parent connection using stdin/stdout
func NewParentConnection() *ParentConnection {
	return &ParentConnection{
		reader: bufio.NewReader(os.Stdin),
		writer: bufio.NewWriter(os.Stdout),
	}
}

// ReadMessage reads a JSON message from the supervisor
func (pc *ParentConnection) ReadMessage() (*IncomingMessage, error) {
	pc.readMu.Lock()
	defer pc.readMu.Unlock()

	line, err := pc.reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read line: %w", err)
	}

	var msg IncomingMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	return &msg, nil
}

// WriteMessage writes a JSON message to the supervisor
func (pc *ParentConnection) WriteMessage(msg *OutgoingMessage) error {
	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	data = append(data, '\n')
	if _, err := pc.writer.Write(data); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return pc.writer.Flush()
}

// Close closes the connection
func (pc *ParentConnection) Close() error {
	// Nothing to close for stdin/stdout
	return nil
}
