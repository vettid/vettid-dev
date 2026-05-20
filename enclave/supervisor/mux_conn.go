package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

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
// The protocol is symmetric. Each side has ONE reader goroutine and
// correlates by MuxID:
//
//   - Whoever INITIATES a request stamps a fresh unique MuxID.
//   - The responder echoes that MuxID verbatim.
//   - A message whose MuxID matches a live local pending entry is a
//     response to one of our own SendRequest calls — route it to the
//     waiting channel. Anything else is a request the peer initiated
//     — hand it to onRequest.
//
// 16 random bytes makes MuxID collisions (a peer-initiated request
// aliasing a live pending entry) a 2^-128 event, so the
// in-pending-map test is a sound discriminator.
//
// MuxConn owns the write mutex: many goroutines may Send/SendRequest
// concurrently; the actual socket write is serialized so frames never
// interleave. Reads are owned exclusively by Run's single goroutine.
type MuxConn struct {
	conn *AuthenticatedConnection

	writeMu sync.Mutex

	pendingMu sync.Mutex
	pending   map[string]chan *Message
	closed    bool
}

// newMuxID returns a fresh 16-byte hex transport correlation token.
func newMuxID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure means the host RNG is gone — the process
		// is doomed anyway. Returning a zero token avoids a panic in a
		// hot path; the worst case is one mis-correlated message before
		// the process dies.
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// NewMuxConn wraps an authenticated connection for multiplexed use.
func NewMuxConn(conn *AuthenticatedConnection) *MuxConn {
	return &MuxConn{
		conn:    conn,
		pending: make(map[string]chan *Message),
	}
}

// Send writes a message under the write mutex. Used for vault-op
// responses (a worker replying to a parent-initiated request) and any
// fire-and-forget notification. The caller is responsible for stamping
// MuxID — for a response that means echoing the request's MuxID.
func (m *MuxConn) Send(msg *Message) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	return m.conn.WriteMessage(msg)
}

// SendRequest issues a supervisor-initiated request (storage, KMS,
// etc.) and blocks until the matching response arrives or ctx is
// done. A fresh MuxID is assigned if the caller didn't set one. Safe
// for concurrent callers.
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
	// write failure — so a slow/cancelled request can't leak the map.
	defer func() {
		m.pendingMu.Lock()
		delete(m.pending, req.MuxID)
		m.pendingMu.Unlock()
	}()

	m.writeMu.Lock()
	err := m.conn.WriteMessage(req)
	m.writeMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("mux write %s: %w", req.Type, err)
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Run is the single reader. It pumps every message off the connection
// and dispatches: a message whose MuxID is in our pending map is a
// response to a SendRequest call and is delivered to that waiter;
// everything else is a peer-initiated request handed to onRequest.
//
// onRequest MUST NOT block — it runs on the reader goroutine, so a
// blocking handler stalls all demuxing. Callers dispatch to a worker.
//
// Returns when the connection read fails (peer closed / error); all
// outstanding SendRequest waiters are then woken with an error.
func (m *MuxConn) Run(onRequest func(*Message)) {
	for {
		msg, err := m.conn.ReadMessage()
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
				// Buffered channel (cap 1) — never blocks the reader.
				ch <- msg
				continue
			}
		}

		onRequest(msg)
	}
}

// failAll wakes every blocked SendRequest with a synthetic error so
// callers return promptly when the connection drops rather than
// hanging on their context deadline.
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
