package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/rs/zerolog/log"
)

// EnclaveMux is the parent's half of the multiplexed parent↔supervisor
// transport — the mirror of the supervisor's MuxConn.
//
// One reader goroutine and one writer goroutine each own a single
// direction of the fd: the reader only reads, the writer only writes.
// A slow or large write blocks only the writer goroutine, never the
// reader. (An earlier single-goroutine design alternated read and
// write; a large >1MB vault-state frame in flight then stalled the
// read path — the 2026-05-20 enclave slowdown.) Concurrent read() and
// write() on one socket fd is safe; the 16KB write chunking in
// writeEnclaveFrame remains the real fix for the Nitro vsock
// large-write bug. See MuxConn in the supervisor package for the full
// protocol rationale; this type carries *EnclaveMessage.
type EnclaveMux struct {
	conn net.Conn

	outbound chan *EnclaveMessage

	done      chan struct{}
	closeOnce sync.Once

	pendingMu sync.Mutex
	pending   map[string]chan *EnclaveMessage
	closed    bool
}

const muxWriteQueueSize = 1024

// newMuxID returns a fresh 16-byte hex transport correlation token.
func newMuxID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// NewEnclaveMux wraps a post-handshake raw connection for multiplexed
// use. The vsock mutual-auth handshake must already have completed.
func NewEnclaveMux(conn net.Conn) *EnclaveMux {
	return &EnclaveMux{
		conn:     conn,
		outbound: make(chan *EnclaveMessage, muxWriteQueueSize),
		done:     make(chan struct{}),
		pending:  make(map[string]chan *EnclaveMessage),
	}
}

// Send enqueues msg for the writer goroutine. Used for responses to
// enclave-initiated requests (the caller MUST echo the request's
// MuxID) and for fire-and-forget downward messages (evict_vault).
func (m *EnclaveMux) Send(msg *EnclaveMessage) error {
	select {
	case m.outbound <- msg:
		return nil
	case <-m.done:
		return fmt.Errorf("enclave mux closed")
	}
}

// SendRequest issues a parent-initiated request (a vault op) and blocks
// until the matching response arrives or ctx is done. A fresh MuxID is
// assigned if the caller didn't set one. Safe for concurrent callers.
func (m *EnclaveMux) SendRequest(ctx context.Context, req *EnclaveMessage) (*EnclaveMessage, error) {
	if req.MuxID == "" {
		req.MuxID = newMuxID()
	}
	ch := make(chan *EnclaveMessage, 1)

	m.pendingMu.Lock()
	if m.closed {
		m.pendingMu.Unlock()
		return nil, fmt.Errorf("enclave mux closed")
	}
	m.pending[req.MuxID] = ch
	m.pendingMu.Unlock()

	defer func() {
		m.pendingMu.Lock()
		delete(m.pending, req.MuxID)
		m.pendingMu.Unlock()
	}()

	select {
	case m.outbound <- req:
	case <-m.done:
		return nil, fmt.Errorf("enclave mux closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Run starts the writer goroutine and runs the reader loop on the
// calling goroutine until the connection fails. A frame whose MuxID is
// in our pending map goes to the waiting SendRequest; everything else
// (incl. any frame with no MuxID) goes to onRequest.
//
// onRequest MUST NOT block — it runs on the reader goroutine.
func (m *EnclaveMux) Run(onRequest func(*EnclaveMessage)) {
	go m.writeLoop()

	for {
		msg, err := readEnclaveFrame(m.conn)
		if err != nil {
			m.shutdown(err)
			return
		}

		if msg.MuxID != "" {
			m.pendingMu.Lock()
			ch, isResponse := m.pending[msg.MuxID]
			if isResponse {
				delete(m.pending, msg.MuxID)
			}
			m.pendingMu.Unlock()
			if isResponse {
				ch <- msg
				continue
			}
		}
		onRequest(msg)
	}
}

func (m *EnclaveMux) writeLoop() {
	for {
		select {
		case msg := <-m.outbound:
			if err := writeEnclaveFrame(m.conn, msg); err != nil {
				m.shutdown(fmt.Errorf("enclave mux write %s: %w", msg.Type, err))
				return
			}
		case <-m.done:
			return
		}
	}
}

// shutdown marks the mux closed exactly once: closes done (waking
// blocked senders and the writer), closes the connection (unblocking
// the peer goroutine's in-flight Read/Write), and fails every pending
// SendRequest.
func (m *EnclaveMux) shutdown(cause error) {
	m.closeOnce.Do(func() {
		m.pendingMu.Lock()
		m.closed = true
		pending := m.pending
		m.pending = make(map[string]chan *EnclaveMessage)
		m.pendingMu.Unlock()

		close(m.done)
		_ = m.conn.Close()

		for muxID, ch := range pending {
			select {
			case ch <- &EnclaveMessage{Type: EnclaveMessageTypeError, MuxID: muxID,
				Error: fmt.Sprintf("enclave mux connection lost: %v", cause)}:
			default:
			}
		}
		log.Debug().Err(cause).Int("woken", len(pending)).
			Msg("enclave mux: connection closed, drained pending requests")
	})
}

// readEnclaveFrame reads one length-prefixed JSON message. A plain
// blocking read — the reader goroutine does nothing else.
func readEnclaveFrame(conn net.Conn) (*EnclaveMessage, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < minMessageSize {
		return nil, fmt.Errorf("enclave mux: frame too small: %d bytes", length)
	}
	if length > maxMessageSize {
		return nil, fmt.Errorf("enclave mux: frame too large: %d bytes", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("enclave mux: read body: %w", err)
	}
	var msg EnclaveMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("enclave mux: unmarshal frame: %w", err)
	}
	return &msg, nil
}

// writeEnclaveFrame writes a length-prefixed JSON message, chunking
// the body at 16KB to dodge the Nitro vsock 32KB large-write bug.
func writeEnclaveFrame(w io.Writer, msg *EnclaveMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return fmt.Errorf("write length prefix: %w", err)
	}
	const vsockChunkSize = 16384
	for offset := 0; offset < len(data); offset += vsockChunkSize {
		end := offset + vsockChunkSize
		if end > len(data) {
			end = len(data)
		}
		if _, err := w.Write(data[offset:end]); err != nil {
			return fmt.Errorf("write message body: %w", err)
		}
	}
	return nil
}
