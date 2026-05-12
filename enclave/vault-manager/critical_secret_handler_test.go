package main

// Tier-1 tests for critical-secret use-on-my-behalf (Phase 6).
//
// Scope: lifecycle + audit + perform-glue + rejection of un-whitelisted
// operations. The actual crypto-perform is a stub via a fake performer
// — the test exercises the wire, the storage, and the audit trail.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

type criticalTestHarness struct {
	t       *testing.T
	h       *CriticalSecretHandler
	store   *storage.SQLiteStorage
	encStor *EncryptedStorage
	msgs    []capturedMsg
	mu      sync.Mutex
}

type fakePerformer struct {
	expected string
	out      string
	called   bool
	mu       sync.Mutex
}

func (f *fakePerformer) Perform(_ context.Context, secretRef, operation, payload string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = true
	if f.expected != "" && payload != f.expected {
		return "", fmt.Errorf("unexpected payload: got %q want %q", payload, f.expected)
	}
	return f.out, nil
}

func newCriticalTestHarness(t *testing.T) *criticalTestHarness {
	t.Helper()
	th := &criticalTestHarness{t: t}

	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	store, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("storage init: %v", err)
	}
	th.store = store
	th.encStor = &EncryptedStorage{sqlite: store, ownerSpace: "test-owner"}

	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	rec := ConnectionRecord{
		ConnectionID: "conn-peer-a",
		PeerGUID:     "peer-a-guid",
		SharedSecret: secret,
		Status:       "active",
	}
	data, _ := json.Marshal(&rec)
	_ = th.encStor.Put("connections/conn-peer-a", data)
	idx, _ := json.Marshal([]string{"conn-peer-a"})
	_ = th.encStor.Put("connections/_index", idx)

	send := func(msg *OutgoingMessage) error {
		th.mu.Lock()
		defer th.mu.Unlock()
		th.msgs = append(th.msgs, capturedMsg{Subject: msg.Subject, Payload: append([]byte{}, msg.Payload...)})
		return nil
	}
	pub := NewVsockPublisher("test-owner", send)
	th.h = NewCriticalSecretHandler("test-owner", th.encStor, pub)
	th.h.SetAuditLog(NewAuditLog(th.encStor))
	return th
}

func (th *criticalTestHarness) close() { th.store.Close() }

func (th *criticalTestHarness) findLast(suffix string) *capturedMsg {
	th.mu.Lock()
	defer th.mu.Unlock()
	for i := len(th.msgs) - 1; i >= 0; i-- {
		if strings.HasSuffix(th.msgs[i].Subject, suffix) {
			m := th.msgs[i]
			return &m
		}
	}
	return nil
}

// TestCriticalUseHappyPath: request → approve → result returned.
func TestCriticalUseHappyPath(t *testing.T) {
	th := newCriticalTestHarness(t)
	defer th.close()

	// Receiver-side: a peer asks us to sign a payload.
	req := CriticalSecretUseRequest{
		RequestID: "cuse-1",
		ItemRef:   "sec-signing-key",
		ItemLabel: "My signing key",
		Operation: CriticalUseOpSign,
		Payload:   "aGVsbG8=", // base64("hello")
		Context:   "for billing invoice 123",
	}
	innerBytes, _ := json.Marshal(req)
	env := &decryptedPeerEnvelope{
		InnerPayload:   innerBytes,
		LocalConnID:    "conn-peer-a",
		FromOwnerSpace: "peer-a-guid",
		SentAt:         time.Now().Unix(),
	}
	if err := th.h.HandleIncomingUseRequest(context.Background(), env); err != nil {
		t.Fatalf("incoming use: %v", err)
	}

	// Verify pending was stored.
	if _, err := th.encStor.Get(criticalUseRequestsKeyPrefix + req.RequestID); err != nil {
		t.Fatalf("pending not stored: %v", err)
	}

	// Wire the performer + approve.
	fake := &fakePerformer{expected: "aGVsbG8=", out: "c2lnbmVk"} // base64("signed")
	th.h.SetPerformer(fake)

	approveBody, _ := json.Marshal(map[string]string{"request_id": req.RequestID})
	resp, _ := th.h.HandleApproveUse(&IncomingMessage{ID: "m1", Payload: approveBody})
	if resp.Type == MessageTypeError {
		t.Fatalf("approve errored: %s", string(resp.Payload))
	}
	if !fake.called {
		t.Errorf("performer was not invoked")
	}

	// Pending record must have been cleaned up.
	if _, err := th.encStor.Get(criticalUseRequestsKeyPrefix + req.RequestID); err == nil {
		t.Errorf("expected pending request cleared after approve")
	}

	// Outbound use-response published.
	pub := th.findLast(".forVault.critical_secret.use-response")
	if pub == nil {
		t.Fatalf("no use-response published")
	}
}

// TestCriticalUseRejectsNonWhitelistOp: a request for an op not in the
// whitelist (sign|decrypt|derive|auth) bounces with a clear error.
func TestCriticalUseRejectsNonWhitelistOp(t *testing.T) {
	th := newCriticalTestHarness(t)
	defer th.close()

	body, _ := json.Marshal(map[string]string{
		"connection_id": "conn-peer-a",
		"item_ref":      "sec-1",
		"operation":     "exfiltrate", // not whitelisted
		"payload":       "x",
	})
	resp, _ := th.h.HandleRequestUse(&IncomingMessage{ID: "m", Payload: body})
	if resp.Type != MessageTypeError {
		t.Fatalf("expected error response for non-whitelisted op, got %+v", resp)
	}
	if !strings.Contains(string(resp.Payload), "operation not whitelisted") {
		t.Errorf("error should mention whitelist, got %s", string(resp.Payload))
	}
}

// TestCriticalUseApproveWithoutPerformer: approving with no performer
// wired must NOT silently succeed — it should return an error so the
// operator notices the missing crypto glue.
func TestCriticalUseApproveWithoutPerformer(t *testing.T) {
	th := newCriticalTestHarness(t)
	defer th.close()

	pending := PendingCriticalUseRequest{
		RequestID:    "cuse-noperf",
		ConnectionID: "conn-peer-a",
		ItemRef:      "sec-x",
		Operation:    CriticalUseOpSign,
		Payload:      "deadbeef",
		ReceivedAt:   time.Now().Unix(),
	}
	d, _ := json.Marshal(&pending)
	_ = th.encStor.Put(criticalUseRequestsKeyPrefix+pending.RequestID, d)

	body, _ := json.Marshal(map[string]string{"request_id": pending.RequestID})
	resp, _ := th.h.HandleApproveUse(&IncomingMessage{ID: "m", Payload: body})

	// The op-level response should report success=false in the inner
	// payload, and the outbound use-response should be status=error.
	var inner map[string]interface{}
	_ = json.Unmarshal(resp.Payload, &inner)
	if inner["status"] != "error" {
		t.Errorf("expected status=error, got %+v", inner)
	}
}

// TestCriticalUseDeny: explicit deny clears the pending record and
// publishes a denial.
func TestCriticalUseDeny(t *testing.T) {
	th := newCriticalTestHarness(t)
	defer th.close()

	pending := PendingCriticalUseRequest{
		RequestID:    "cuse-deny",
		ConnectionID: "conn-peer-a",
		ItemRef:      "sec-x",
		Operation:    CriticalUseOpSign,
		Payload:      "x",
		ReceivedAt:   time.Now().Unix(),
	}
	d, _ := json.Marshal(&pending)
	_ = th.encStor.Put(criticalUseRequestsKeyPrefix+pending.RequestID, d)

	body, _ := json.Marshal(map[string]string{"request_id": pending.RequestID, "reason": "no_thanks"})
	resp, _ := th.h.HandleDenyUse(&IncomingMessage{ID: "m", Payload: body})
	if resp.Type == MessageTypeError {
		t.Fatalf("deny errored: %s", string(resp.Payload))
	}
	if _, err := th.encStor.Get(criticalUseRequestsKeyPrefix + pending.RequestID); err == nil {
		t.Errorf("expected pending request cleared after deny")
	}
	if pub := th.findLast(".forVault.critical_secret.use-response"); pub == nil {
		t.Errorf("expected denial publish")
	}
}
