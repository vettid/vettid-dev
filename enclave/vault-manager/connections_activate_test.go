package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

// fakeSendFn captures published messages so the test can assert how
// many times connection.activated was emitted to the local app.
type fakeSendFn struct {
	mu              sync.Mutex
	activatedCount  int32 // forApp emissions for connection.activated
	peerSignalCount int32 // peer-direction signal pushes (peer-accepted)
	rawSubjects     []string
}

func (f *fakeSendFn) send(msg *OutgoingMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rawSubjects = append(f.rawSubjects, msg.Subject)
	if msg.Type == MessageTypeNATSPublish {
		// forApp.connection.activated → owner-app event
		// MessageSpace.{peer}.forOwner.connection.signal → peer push
		switch {
		case containsForAppActivated(msg.Subject):
			atomic.AddInt32(&f.activatedCount, 1)
		case containsPeerSignal(msg.Subject):
			atomic.AddInt32(&f.peerSignalCount, 1)
		}
	}
	return nil
}

func containsForAppActivated(subject string) bool {
	// e.g. OwnerSpace.X.forApp.connection.activated
	return len(subject) > 0 && (subject == "OwnerSpace.test-owner.forApp.connection.activated" ||
		(len(subject) > 4 && subject[len(subject)-len("connection.activated"):] == "connection.activated" &&
			!containsPeerSignal(subject)))
}

func containsPeerSignal(subject string) bool {
	// e.g. MessageSpace.peer.forOwner.connection.signal
	return len(subject) > 0 && len(subject) > len("connection.signal") &&
		subject[len(subject)-len("connection.signal"):] == "connection.signal"
}

// setupConnectionsHandler builds a ConnectionsHandler against a fresh
// in-memory vault for racing tryActivate from two goroutines.
func setupConnectionsHandler(t *testing.T) (*ConnectionsHandler, *EncryptedStorage, *fakeSendFn, func()) {
	t.Helper()

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sqliteStore, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	encStorage := &EncryptedStorage{
		sqlite:     sqliteStore,
		ownerSpace: "test-owner",
	}
	send := &fakeSendFn{}
	publisher := NewVsockPublisher("test-owner", send.send)
	h := NewConnectionsHandler("test-owner", encStorage, nil, nil, publisher, nil)
	cleanup := func() { sqliteStore.Close() }
	return h, encStorage, send, cleanup
}

func seedReadyForActivation(t *testing.T, h *ConnectionsHandler, storageImpl *EncryptedStorage, connectionID string) {
	t.Helper()
	record := ConnectionRecord{
		ConnectionID:    connectionID,
		ConnectionType:  "peer",
		Status:          ConnStatusPeerReviewing,
		PeerOwnerSpace:  "peer-owner",
		PeerGUID:        "peer-owner",
		CredentialsType: "outbound",
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(15 * time.Minute),
		LocalDecision:   "",
		PeerDecision:    "",
	}
	data, _ := json.Marshal(record)
	if err := storageImpl.Put("connections/"+connectionID, data); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// TestTryActivate_RaceLocalAndPeer races a local accept (HandleRespond
// path) against a peer-accept signal (HandleConnectionSignal path) for
// the same connection. Activation must fire exactly once.
func TestTryActivate_RaceLocalAndPeer(t *testing.T) {
	const iterations = 50
	for i := 0; i < iterations; i++ {
		h, store, send, cleanup := setupConnectionsHandler(t)
		connectionID := "conn-race-" + time.Now().Format("150405.000000")
		seedReadyForActivation(t, h, store, connectionID)

		ctx := context.Background()
		var wg sync.WaitGroup

		// Goroutine 1: local respond accept (mirrors HandleRespond).
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.withConnectionRecord(connectionID, func(r *ConnectionRecord) (bool, error) {
				_, err := applyDecision(&r.LocalDecision, DecisionAccept)
				if err != nil {
					return false, err
				}
				computeStatus(r)
				return true, nil
			})
			if err != nil {
				t.Errorf("local apply: %v", err)
			}
			h.tryActivate(ctx, connectionID)
		}()

		// Goroutine 2: peer-accepted signal arriving (mirrors
		// HandleConnectionSignal → handlePeerAccepted).
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.withConnectionRecord(connectionID, func(r *ConnectionRecord) (bool, error) {
				_, err := applyDecision(&r.PeerDecision, DecisionAccept)
				if err != nil {
					return false, err
				}
				computeStatus(r)
				return true, nil
			})
			if err != nil {
				t.Errorf("peer apply: %v", err)
			}
			h.tryActivate(ctx, connectionID)
		}()

		wg.Wait()

		// Read final state.
		final, err := h.withConnectionRecord(connectionID, func(r *ConnectionRecord) (bool, error) { return false, nil })
		if err != nil {
			t.Fatalf("load final: %v", err)
		}
		if final.Status != ConnStatusActive {
			t.Fatalf("iter %d: expected Active, got %s", i, final.Status)
		}
		if final.ActivatedAt.IsZero() {
			t.Fatalf("iter %d: ActivatedAt should be set", i)
		}
		// Exactly one forApp activation emit.
		if got := atomic.LoadInt32(&send.activatedCount); got != 1 {
			t.Fatalf("iter %d: expected exactly 1 activated emission, got %d", i, got)
		}

		cleanup()
	}
}

// TestApplyDecision_NoFlip ensures an accept decision can't be
// silently overwritten with a reject (or vice versa) by a stale
// signal. The rule is: first decision wins, replays no-op, conflicts
// error.
func TestApplyDecision_NoFlip(t *testing.T) {
	var d string
	if changed, err := applyDecision(&d, DecisionAccept); err != nil || !changed {
		t.Fatalf("first accept: changed=%v err=%v", changed, err)
	}
	if changed, err := applyDecision(&d, DecisionAccept); err != nil || changed {
		t.Fatalf("repeat accept should be no-op: changed=%v err=%v", changed, err)
	}
	if _, err := applyDecision(&d, DecisionReject); err == nil {
		t.Fatalf("flipping accept→reject should error")
	}
}

// TestTryActivate_IdempotentAfterActive confirms that a second
// tryActivate run after the record is already active is a no-op (no
// extra emission, no error).
func TestTryActivate_IdempotentAfterActive(t *testing.T) {
	h, store, send, cleanup := setupConnectionsHandler(t)
	defer cleanup()
	connectionID := "conn-idem"
	seedReadyForActivation(t, h, store, connectionID)

	ctx := context.Background()

	// Apply both decisions in sequence.
	for _, decision := range []func(*ConnectionRecord){
		func(r *ConnectionRecord) { applyDecision(&r.LocalDecision, DecisionAccept) },
		func(r *ConnectionRecord) { applyDecision(&r.PeerDecision, DecisionAccept) },
	} {
		_, err := h.withConnectionRecord(connectionID, func(r *ConnectionRecord) (bool, error) {
			decision(r)
			computeStatus(r)
			return true, nil
		})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
	}

	// First activate.
	if _, _, err := h.tryActivate(ctx, connectionID); err != nil {
		t.Fatalf("first tryActivate: %v", err)
	}
	if got := atomic.LoadInt32(&send.activatedCount); got != 1 {
		t.Fatalf("after first tryActivate: expected 1, got %d", got)
	}

	// Repeat — should be a no-op.
	if _, _, err := h.tryActivate(ctx, connectionID); err != nil {
		t.Fatalf("second tryActivate: %v", err)
	}
	if got := atomic.LoadInt32(&send.activatedCount); got != 1 {
		t.Fatalf("after second tryActivate: expected 1, got %d", got)
	}
}
