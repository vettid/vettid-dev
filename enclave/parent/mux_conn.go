package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// EnclaveMux is the parent's half of the multiplexed parent↔supervisor
// transport. It is the mirror of the supervisor's MuxConn: a single
// I/O goroutine owns the fd (so read() and write() syscalls are never
// concurrent — the Nitro vsock corruption hazard), senders only
// enqueue frames, and responses are correlated to waiters by MuxID.
//
// The parent INITIATES vault ops (forwardToEnclave → SendRequest) and
// RESPONDS to enclave-initiated requests (storage/KMS/etc. → Send,
// echoing the request's MuxID). See MuxConn in the supervisor package
// for the full protocol rationale; this type carries *EnclaveMessage
// instead of *Message but is otherwise identical.
type EnclaveMux struct {
	conn net.Conn

	outbound chan *EnclaveMessage

	// ioMu fences a started frame read against kicks (see readFrame).
	ioMu sync.Mutex

	pendingMu sync.Mutex
	pending   map[string]chan *EnclaveMessage
	closed    bool
}

// errMuxIdle is the sentinel readFrame returns when the idle read
// deadline expired before any byte of a new frame arrived.
var errMuxIdle = errors.New("mux: idle")

const (
	muxWriteQueueSize = 1024
	muxIdlePoll       = 25 * time.Millisecond
)

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
		pending:  make(map[string]chan *EnclaveMessage),
	}
}

// Send enqueues msg for the I/O goroutine to write. Used for responses
// to enclave-initiated requests (the caller MUST echo the request's
// MuxID) and for fire-and-forget downward messages (evict_vault).
func (m *EnclaveMux) Send(msg *EnclaveMessage) error {
	m.pendingMu.Lock()
	closed := m.closed
	m.pendingMu.Unlock()
	if closed {
		return fmt.Errorf("enclave mux closed")
	}
	select {
	case m.outbound <- msg:
		m.kick()
		return nil
	default:
		select {
		case m.outbound <- msg:
			m.kick()
			return nil
		case <-time.After(5 * time.Second):
			return fmt.Errorf("enclave mux outbound queue full")
		}
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
		m.kick()
	default:
		select {
		case m.outbound <- req:
			m.kick()
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, fmt.Errorf("enclave mux outbound queue full")
		}
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// kick wakes the I/O goroutine so a just-enqueued frame is written
// without waiting out the idle poll.
func (m *EnclaveMux) kick() {
	m.ioMu.Lock()
	m.conn.SetReadDeadline(time.Now())
	m.ioMu.Unlock()
}

// Run is the single I/O goroutine. It drains queued outbound frames,
// reads one inbound frame, and dispatches: a frame whose MuxID is in
// our pending map goes to the waiting SendRequest; everything else
// (including any frame with no MuxID) goes to onRequest.
//
// onRequest MUST NOT block — it runs on this goroutine.
func (m *EnclaveMux) Run(onRequest func(*EnclaveMessage)) {
	for {
		m.flushOutbound()

		m.conn.SetReadDeadline(time.Now().Add(muxIdlePoll))
		if len(m.outbound) > 0 {
			continue
		}

		msg, err := m.readFrame()
		if errors.Is(err, errMuxIdle) {
			continue
		}
		if err != nil {
			m.failAll(err)
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

func (m *EnclaveMux) flushOutbound() {
	for {
		select {
		case msg := <-m.outbound:
			if err := writeEnclaveFrame(m.conn, msg); err != nil {
				log.Error().Err(err).Str("type", string(msg.Type)).
					Msg("enclave mux: outbound write failed")
				return
			}
		default:
			return
		}
	}
}

// readFrame reads one length-prefixed message. The read deadline
// armed by Run bounds ONLY the wait for the first byte; once a frame
// has started, ioMu fences the rest of the read against kicks so the
// stream can never desync mid-message.
func (m *EnclaveMux) readFrame() (*EnclaveMessage, error) {
	var first [1]byte
	n0, err := m.conn.Read(first[:])
	if n0 == 0 {
		if err != nil && isTimeoutErr(err) {
			return nil, errMuxIdle
		}
		if err != nil {
			return nil, err
		}
		return nil, errMuxIdle
	}

	m.ioMu.Lock()
	defer m.ioMu.Unlock()
	m.conn.SetReadDeadline(time.Time{})

	lenBuf := [4]byte{first[0]}
	if _, err := io.ReadFull(m.conn, lenBuf[1:]); err != nil {
		return nil, fmt.Errorf("enclave mux: read length prefix: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < minMessageSize {
		return nil, fmt.Errorf("enclave mux: frame too small: %d bytes", length)
	}
	if length > maxMessageSize {
		return nil, fmt.Errorf("enclave mux: frame too large: %d bytes", length)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(m.conn, body); err != nil {
		return nil, fmt.Errorf("enclave mux: read body: %w", err)
	}

	var msg EnclaveMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("enclave mux: unmarshal frame: %w", err)
	}
	return &msg, nil
}

// failAll wakes every blocked SendRequest with a synthetic error when
// the connection drops, and marks the mux closed.
func (m *EnclaveMux) failAll(cause error) {
	m.pendingMu.Lock()
	pending := m.pending
	m.pending = make(map[string]chan *EnclaveMessage)
	m.closed = true
	m.pendingMu.Unlock()

	for muxID, ch := range pending {
		select {
		case ch <- &EnclaveMessage{Type: EnclaveMessageTypeError, MuxID: muxID,
			Error: fmt.Sprintf("enclave mux connection lost: %v", cause)}:
		default:
		}
	}
	log.Debug().Err(cause).Int("woken", len(pending)).
		Msg("enclave mux: connection reader exited, drained pending requests")
}

// writeEnclaveFrame writes a length-prefixed JSON message, chunking
// the body at 16KB to dodge the Nitro vsock 32KB write-zeroing bug.
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

// isTimeoutErr reports whether err is a read-deadline expiry.
func isTimeoutErr(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}
