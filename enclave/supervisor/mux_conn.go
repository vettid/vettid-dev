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

// MuxConn multiplexes the single parent↔supervisor connection so the
// supervisor can process many vault ops concurrently instead of one
// at a time.
//
// CORRELATION. The protocol is symmetric. Whoever INITIATES a request
// stamps a fresh unique MuxID; the responder echoes it verbatim. A
// frame whose MuxID matches a live local pending entry is a response
// to one of our own SendRequest calls — route it to the waiting
// channel. Anything else (including any frame with no MuxID) is a
// peer-initiated request — hand it to onRequest. 16 random bytes
// makes a MuxID collision a 2^-128 event.
//
// I/O MODEL. One reader goroutine and one writer goroutine, each
// owning a single direction of the fd. The reader only ever reads;
// the writer only ever writes. This is ordinary full-duplex socket
// I/O — a slow or large write blocks ONLY the writer goroutine, never
// the reader, so responses keep flowing while a big frame goes out.
//
// An earlier single-goroutine design alternated reading and writing
// on one goroutine; a large (>1MB) vault-state frame in flight then
// stalled the read path, and under bidirectional large-payload load
// throughput collapsed — the 2026-05-20 enclave slowdown. Two
// goroutines remove that failure mode entirely. Concurrent read() and
// write() on the same socket fd is safe (the pre-multiplex parent
// VsockClient ran that way in production for months); the 16KB write
// chunking in writeMessage remains the real fix for the Nitro vsock
// large-write bug and is unaffected.
//
// Senders (Send / SendRequest) only enqueue onto the outbound channel;
// the writer drains it in FIFO order, so a whole frame is written
// before the next starts and frames never interleave on the wire.
type MuxConn struct {
	conn net.Conn

	// outbound carries frames the writer goroutine still has to write.
	outbound chan *Message

	// done is closed exactly once when the connection is dead; it
	// unblocks any goroutine parked on Send / SendRequest / the writer.
	done      chan struct{}
	closeOnce sync.Once

	pendingMu sync.Mutex
	pending   map[string]chan *Message
	closed    bool
}

// muxWriteQueueSize bounds frames queued for the writer goroutine. A
// vault op produces a handful of frames; the parent fans in at most
// MaxVaults ops. 1024 is far above any real burst.
const muxWriteQueueSize = 1024

// newMuxID returns a fresh 16-byte hex transport correlation token.
func newMuxID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure means the host RNG is gone — the process
		// is doomed anyway. A zero token avoids a panic in a hot path.
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// NewMuxConn wraps a post-handshake raw connection for multiplexed use.
// The mutual-auth handshake must already have completed on conn.
func NewMuxConn(conn net.Conn) *MuxConn {
	return &MuxConn{
		conn:     conn,
		outbound: make(chan *Message, muxWriteQueueSize),
		done:     make(chan struct{}),
		pending:  make(map[string]chan *Message),
	}
}

// Send enqueues msg for the writer goroutine. Used for vault-op
// responses (the caller MUST echo the request's MuxID) and for
// fire-and-forget notifications (no MuxID). Returns an error only if
// the connection is closed.
func (m *MuxConn) Send(msg *Message) error {
	select {
	case m.outbound <- msg:
		return nil
	case <-m.done:
		return fmt.Errorf("mux connection closed")
	}
}

// SendRequest issues a supervisor-initiated request (storage, KMS,
// etc.) and blocks until the matching response arrives or ctx is done.
// A fresh MuxID is assigned if the caller didn't set one. Safe for
// concurrent callers — each gets its own pending channel.
func (m *MuxConn) SendRequest(ctx context.Context, req *Message) (*Message, error) {
	if req.MuxID == "" {
		req.MuxID = newMuxID()
	}
	ch := make(chan *Message, 1)

	m.pendingMu.Lock()
	if m.closed {
		m.pendingMu.Unlock()
		return nil, fmt.Errorf("mux connection closed")
	}
	m.pending[req.MuxID] = ch
	m.pendingMu.Unlock()

	// Always clear the pending entry — on response, ctx cancel, or
	// connection loss — so a slow/cancelled request can't leak the map.
	defer func() {
		m.pendingMu.Lock()
		delete(m.pending, req.MuxID)
		m.pendingMu.Unlock()
	}()

	select {
	case m.outbound <- req:
	case <-m.done:
		return nil, fmt.Errorf("mux connection closed")
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

// Run starts the writer goroutine and then runs the reader loop on the
// calling goroutine until the connection fails. It demuxes: a frame
// whose MuxID is in our pending map goes to the waiting SendRequest;
// everything else goes to onRequest.
//
// onRequest MUST NOT block — it runs on the reader goroutine, so a
// blocking handler stalls demuxing. Callers dispatch to a worker.
func (m *MuxConn) Run(onRequest func(*Message)) {
	go m.writeLoop()

	for {
		msg, err := readFrame(m.conn)
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
				ch <- msg // buffered cap-1 — never blocks the reader
				continue
			}
		}
		onRequest(msg)
	}
}

// writeLoop drains the outbound queue and writes each frame. A
// blocking write stalls only this goroutine — the reader keeps going.
func (m *MuxConn) writeLoop() {
	for {
		select {
		case msg := <-m.outbound:
			if err := writeMessage(m.conn, msg); err != nil {
				m.shutdown(fmt.Errorf("mux write %s: %w", msg.Type, err))
				return
			}
		case <-m.done:
			return
		}
	}
}

// shutdown marks the mux closed exactly once: it closes done (waking
// blocked senders and the writer), closes the connection (unblocking
// the peer goroutine's in-flight Read/Write), and fails every pending
// SendRequest so callers return promptly rather than hanging on ctx.
func (m *MuxConn) shutdown(cause error) {
	m.closeOnce.Do(func() {
		m.pendingMu.Lock()
		m.closed = true
		pending := m.pending
		m.pending = make(map[string]chan *Message)
		m.pendingMu.Unlock()

		close(m.done)
		_ = m.conn.Close()

		for muxID, ch := range pending {
			select {
			case ch <- &Message{Type: MessageTypeError, MuxID: muxID,
				Error: fmt.Sprintf("mux connection lost: %v", cause)}:
			default:
			}
		}
		log.Debug().Err(cause).Int("woken", len(pending)).
			Msg("mux: connection closed, drained pending requests")
	})
}

// readFrame reads one length-prefixed JSON message. A plain blocking
// read — the reader goroutine has nothing else to do, so there is no
// deadline or partial-read handling to get wrong.
func readFrame(conn net.Conn) (*Message, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < minMessageSize {
		return nil, fmt.Errorf("mux: frame too small: %d bytes", length)
	}
	if length > maxMessageSize {
		return nil, fmt.Errorf("mux: frame too large: %d bytes", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("mux: read body: %w", err)
	}
	var msg Message
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("mux: unmarshal frame: %w", err)
	}
	return &msg, nil
}
