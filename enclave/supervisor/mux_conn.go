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

// MuxConn multiplexes the single parent↔supervisor connection so the
// supervisor can process many vault ops concurrently instead of one
// at a time.
//
// Before this, the supervisor's read loop was strictly serial — read
// one message, fully process it (including every nested S3/KMS
// round-trip to the parent), write the response, read the next. Every
// vault op for every user funnelled through that loop; under load it
// was the throughput ceiling (Tier-2 concurrent-multiuser: 24 ops
// across 4 users took 24×latency because they could not overlap).
//
// CORRELATION. The protocol is symmetric. Whoever INITIATES a request
// stamps a fresh unique MuxID; the responder echoes it verbatim. A
// message whose MuxID matches a live local pending entry is a response
// to one of our own SendRequest calls — route it to the waiting
// channel. Anything else (including any message with no MuxID) is a
// peer-initiated request — hand it to onRequest. 16 random bytes makes
// a MuxID collision a 2^-128 event, so the in-pending-map test is a
// sound discriminator.
//
// CONCURRENCY / NITRO SAFETY. The Nitro hypervisor's vsock corrupts
// data when read() and write() syscalls run concurrently on the same
// fd (see vsockConnection in vsock.go). A naive "perpetually-blocked
// reader + concurrent writers" multiplex would do exactly that. So
// MuxConn uses a SINGLE I/O goroutine — Run — that owns the fd. It
// reads and writes; no other goroutine ever touches the fd for I/O.
// Reads and writes are therefore never concurrent at the syscall
// level. Senders (Send / SendRequest) only enqueue frames to an
// outbound channel; the I/O goroutine drains it between reads.
//
// The reader blocks for a new message with a short idle deadline; on
// expiry it loops back to flush queued writes. A kick (SetReadDeadline
// to now) lets a sender wake the reader immediately for low latency,
// but correctness never depends on it — the idle deadline is the
// backstop. A kick can only interrupt the wait for the FIRST byte of a
// message; once a frame has started, ioMu fences the rest of the read
// against kicks so the stream can never desync mid-message.
type MuxConn struct {
	conn net.Conn

	// outbound carries frames the I/O goroutine still has to write.
	outbound chan *Message

	// ioMu fences a committed (started) frame read against kicks: the
	// reader holds it from the first byte of a frame through the end
	// of that frame's body, and a kick takes it before touching the
	// read deadline. Without this a kick could interrupt io.ReadFull
	// mid-body and desync the stream.
	ioMu sync.Mutex

	pendingMu sync.Mutex
	pending   map[string]chan *Message
	closed    bool
}

// errMuxIdle is the internal sentinel readFrame returns when the idle
// read deadline expired before any byte of a new frame arrived — i.e.
// "nothing to read right now". The I/O loop treats it as a cue to go
// flush queued writes; the stream is still aligned.
var errMuxIdle = errors.New("mux: idle")

const (
	// muxWriteQueueSize bounds frames queued for the I/O goroutine. A
	// vault op produces a handful of frames; the parent fans in at
	// most MaxVaults ops. 1024 is far above any real burst.
	muxWriteQueueSize = 1024

	// muxIdlePoll is how long the reader blocks for a new frame before
	// surfacing queued writes. It is the latency backstop if a kick is
	// ever missed; kicks normally flush a response far sooner.
	muxIdlePoll = 25 * time.Millisecond
)

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
		pending:  make(map[string]chan *Message),
	}
}

// Send enqueues msg for the I/O goroutine to write. Used for vault-op
// responses (the caller MUST echo the request's MuxID) and for
// fire-and-forget notifications (no MuxID). Returns an error only if
// the connection is closed or the outbound queue is wedged.
func (m *MuxConn) Send(msg *Message) error {
	m.pendingMu.Lock()
	closed := m.closed
	m.pendingMu.Unlock()
	if closed {
		return fmt.Errorf("mux connection closed")
	}
	select {
	case m.outbound <- msg:
		m.kick()
		return nil
	default:
		// Queue full — abnormal. Block briefly rather than drop a
		// frame: a dropped response would wedge a peer waiter.
		select {
		case m.outbound <- msg:
			m.kick()
			return nil
		case <-time.After(5 * time.Second):
			return fmt.Errorf("mux outbound queue full")
		}
	}
}

// SendRequest issues a supervisor-initiated request (storage, KMS,
// etc.) and blocks until the matching response arrives or ctx is done.
// A fresh MuxID is assigned if the caller didn't set one. Safe for
// concurrent callers — each gets its own pending channel.
//
// A MessageTypeError response is returned as (resp, nil); the caller
// inspects resp.Type. Transport failures (closed conn, ctx) return a
// non-nil error.
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
	// enqueue failure — so a slow/cancelled request can't leak the map.
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
			return nil, fmt.Errorf("mux outbound queue full")
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
// without waiting out the idle poll. ioMu ensures the deadline is not
// moved while the reader is mid-frame (which would desync the stream).
func (m *MuxConn) kick() {
	m.ioMu.Lock()
	m.conn.SetReadDeadline(time.Now())
	m.ioMu.Unlock()
}

// Run is the single I/O goroutine. It owns the fd: it drains queued
// outbound frames, then reads one inbound frame (with the idle
// deadline), then dispatches it — a frame whose MuxID is in our
// pending map goes to the waiting SendRequest; everything else goes to
// onRequest.
//
// onRequest MUST NOT block — it runs on this goroutine. Callers hand
// the request to a worker goroutine and return immediately.
//
// Run returns when the connection read fails (peer closed / error);
// all outstanding SendRequest waiters are then woken with an error.
func (m *MuxConn) Run(onRequest func(*Message)) {
	for {
		m.flushOutbound()

		m.conn.SetReadDeadline(time.Now().Add(muxIdlePoll))
		// Re-check after arming the deadline: a frame enqueued (and
		// kicked) between flushOutbound and here would otherwise wait
		// out the full idle poll. This closes the kick race.
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
				ch <- msg // buffered cap-1: never blocks the reader
				continue
			}
		}
		onRequest(msg)
	}
}

// flushOutbound writes every currently-queued frame. Only the Run
// goroutine calls this, so conn.Write is never concurrent with the
// conn.Read in readFrame.
func (m *MuxConn) flushOutbound() {
	for {
		select {
		case msg := <-m.outbound:
			if err := writeMessage(m.conn, msg); err != nil {
				// Connection is dead. Stop draining; the next readFrame
				// will see the failure and failAll the waiters.
				log.Error().Err(err).Str("type", string(msg.Type)).
					Msg("mux: outbound write failed")
				return
			}
		default:
			return
		}
	}
}

// readFrame reads one length-prefixed message. The read deadline
// armed by Run bounds ONLY the wait for the first byte: if it fires
// first, readFrame returns errMuxIdle and the stream stays aligned.
// Once any byte has arrived, ioMu is taken and the deadline cleared so
// no kick can interrupt the rest of the frame — a frame is never
// abandoned half-read.
func (m *MuxConn) readFrame() (*Message, error) {
	// Phase 1: wait for the first byte. A kick (SetReadDeadline now)
	// interrupts this cleanly because no frame has started yet.
	var first [1]byte
	n0, err := m.conn.Read(first[:])
	if n0 == 0 {
		if err != nil && isTimeoutErr(err) {
			return nil, errMuxIdle
		}
		if err != nil {
			return nil, err
		}
		return nil, errMuxIdle // 0 bytes, no error — treat as idle
	}

	// Phase 2: a frame has started. Fence the rest against kicks and
	// read to completion with no deadline.
	m.ioMu.Lock()
	defer m.ioMu.Unlock()
	m.conn.SetReadDeadline(time.Time{})

	lenBuf := [4]byte{first[0]}
	if _, err := io.ReadFull(m.conn, lenBuf[1:]); err != nil {
		return nil, fmt.Errorf("mux: read length prefix: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < minMessageSize {
		return nil, fmt.Errorf("mux: frame too small: %d bytes", length)
	}
	if length > maxMessageSize {
		return nil, fmt.Errorf("mux: frame too large: %d bytes", length)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(m.conn, body); err != nil {
		return nil, fmt.Errorf("mux: read body: %w", err)
	}

	var msg Message
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("mux: unmarshal frame: %w", err)
	}
	return &msg, nil
}

// failAll wakes every blocked SendRequest with a synthetic error so
// callers return promptly when the connection drops rather than
// hanging on their context deadline. After failAll the mux is closed:
// new Send / SendRequest calls fail fast.
func (m *MuxConn) failAll(cause error) {
	m.pendingMu.Lock()
	pending := m.pending
	m.pending = make(map[string]chan *Message)
	m.closed = true
	m.pendingMu.Unlock()

	for muxID, ch := range pending {
		select {
		case ch <- &Message{Type: MessageTypeError, MuxID: muxID,
			Error: fmt.Sprintf("mux connection lost: %v", cause)}:
		default:
		}
	}
	log.Debug().Err(cause).Int("woken", len(pending)).
		Msg("mux: connection reader exited, drained pending requests")
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
