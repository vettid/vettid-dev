package main

// Tier-1 lifecycle tests for the grant handler.
//
// Scope per plans/data-request-grants.md Phase 1:
//   - Grant creation + fetch happy path
//   - Expiry: read after expires_at returns denied + lazy state flip
//   - Max-uses: 6th fetch on a max=5 grant denied
//   - Revoke: post-revoke fetch denied + poison-pill emitted
//   - Cross-connection: peer B can't fetch peer A's grant_id
//   - Catalog deletion mid-grant: fetch returns "item gone"
//
// We bypass the envelope decryption layer at the receive side by
// hand-crafting *decryptedPeerEnvelope values — the Handle* methods
// that accept it don't care how it was produced. The publish side
// uses a real VsockPublisher backed by a capture sendFn so we can
// assert what the handler attempted to ship without setting up
// vsock+NATS, and decrypt the captured envelope with the
// connection's shared secret to read the inner payload.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

type capturedMsg struct {
	Subject string
	Payload []byte
}

type grantTestHarness struct {
	t       *testing.T
	h       *GrantHandler
	msgs    []capturedMsg
	mu      sync.Mutex
	store   *storage.SQLiteStorage
	encStor *EncryptedStorage
}

// newGrantTestHarness builds an in-memory SQLite-backed GrantHandler,
// seeds two connections + one personal-data field, and wires a
// capturing publisher so callers can inspect every outbound message.
func newGrantTestHarness(t *testing.T) *grantTestHarness {
	t.Helper()
	th := &grantTestHarness{t: t}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	store, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("storage init: %v", err)
	}
	th.store = store
	th.encStor = &EncryptedStorage{sqlite: store, ownerSpace: "test-owner"}

	for _, c := range []struct {
		ConnID   string
		PeerGUID string
	}{
		{"conn-peer-a", "peer-a-guid"},
		{"conn-peer-b", "peer-b-guid"},
	} {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatalf("rand: %v", err)
		}
		rec := ConnectionRecord{
			ConnectionID: c.ConnID,
			PeerGUID:     c.PeerGUID,
			SharedSecret: secret,
			Status:       "active",
		}
		data, _ := json.Marshal(&rec)
		if err := th.encStor.Put("connections/"+c.ConnID, data); err != nil {
			t.Fatalf("seed conn: %v", err)
		}
	}
	idx, _ := json.Marshal([]string{"conn-peer-a", "conn-peer-b"})
	if err := th.encStor.Put("connections/_index", idx); err != nil {
		t.Fatalf("seed conn index: %v", err)
	}

	field := PersonalDataField{
		ID:              "pdf-1",
		Name:            "contact.phone.mobile",
		DisplayName:     "Mobile Phone",
		Value:           "+15551234567",
		FieldType:       "PHONE",
		Discoverability: DiscoverabilityCataloged,
	}
	pdfData, _ := json.Marshal(&field)
	if err := th.encStor.Put("personal-data/contact.phone.mobile", pdfData); err != nil {
		t.Fatalf("seed pdf: %v", err)
	}

	send := func(msg *OutgoingMessage) error {
		th.mu.Lock()
		defer th.mu.Unlock()
		th.msgs = append(th.msgs, capturedMsg{Subject: msg.Subject, Payload: append([]byte{}, msg.Payload...)})
		return nil
	}
	pub := NewVsockPublisher("test-owner", send)
	th.h = NewGrantHandler("test-owner", th.encStor, pub)
	th.h.SetAuditLog(NewAuditLog(th.encStor))
	return th
}

func (th *grantTestHarness) close() {
	if th.store != nil {
		th.store.Close()
	}
}

// findLastSubject returns the most recent captured message whose
// subject ends with the given suffix.
func (th *grantTestHarness) findLastSubject(suffix string) *capturedMsg {
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

func (th *grantTestHarness) capturedSubjects() []string {
	th.mu.Lock()
	defer th.mu.Unlock()
	out := make([]string, 0, len(th.msgs))
	for _, m := range th.msgs {
		out = append(out, m.Subject)
	}
	return out
}

// decryptCapturedFetchResponse decodes a captured envelope and parses
// its inner GrantFetchResponse using the connection's shared secret.
func (th *grantTestHarness) decryptCapturedFetchResponse(connID string) GrantFetchResponse {
	th.t.Helper()
	msg := th.findLastSubject(".forVault.data.grant.fetch-response")
	if msg == nil {
		th.t.Fatalf("no fetch-response captured. subjects=%v", th.capturedSubjects())
	}
	var env EncryptedPeerEnvelope
	if err := json.Unmarshal(msg.Payload, &env); err != nil {
		th.t.Fatalf("parse envelope: %v", err)
	}
	connData, _ := th.encStor.Get("connections/" + connID)
	var conn ConnectionRecord
	_ = json.Unmarshal(connData, &conn)
	key, err := deriveConnectionKey(conn.SharedSecret)
	if err != nil {
		th.t.Fatalf("derive key: %v", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		th.t.Fatalf("decode nonce: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.EncryptedPayload)
	if err != nil {
		th.t.Fatalf("decode ct: %v", err)
	}
	combined := append([]byte{}, nonce...)
	combined = append(combined, ct...)
	plaintext, err := decryptXChaCha20(key, combined)
	if err != nil {
		th.t.Fatalf("decrypt: %v", err)
	}
	var resp GrantFetchResponse
	if err := json.Unmarshal(plaintext, &resp); err != nil {
		th.t.Fatalf("parse fetch-response: %v", err)
	}
	return resp
}

// seedActiveGrant writes a GrantRecord directly so individual tests
// don't have to walk the request → approve flow when their focus is
// fetch / revoke / expiry.
func (th *grantTestHarness) seedActiveGrant(connID, peerGUID, itemRef, mode string, expires int64, maxUses int) *GrantRecord {
	th.t.Helper()
	g := &GrantRecord{
		GrantID:       "grant-" + itemRef,
		OwnerGUID:     th.h.ownerSpace,
		RequesterGUID: peerGUID,
		ConnectionID:  connID,
		ItemKind:      GrantItemKindData,
		ItemRef:       itemRef,
		ItemLabel:     "Test " + itemRef,
		Mode:          mode,
		DeliverTo:     GrantDeliverSelf,
		ExpiresAt:     expires,
		MaxUses:       maxUses,
		Status:        GrantStatusActive,
		CreatedAt:     time.Now().Unix(),
	}
	if err := th.h.saveGrant(g); err != nil {
		th.t.Fatalf("save grant: %v", err)
	}
	if err := th.h.appendToIndex(grantsIndexKey, g.GrantID); err != nil {
		th.t.Fatalf("index grant: %v", err)
	}
	if err := th.h.appendToIndex("connections/"+connID+outboundGrantsIndexSuffix, g.GrantID); err != nil {
		th.t.Fatalf("index outbound: %v", err)
	}
	return g
}

// fakeEnv wraps inner JSON in a decryptedPeerEnvelope shaped like the
// message router would produce after a successful decrypt.
func fakeEnv(localConnID, fromPeerGUID string, inner interface{}) *decryptedPeerEnvelope {
	innerBytes, _ := json.Marshal(inner)
	return &decryptedPeerEnvelope{
		InnerPayload:   innerBytes,
		LocalConnID:    localConnID,
		FromOwnerSpace: fromPeerGUID,
		SentAt:         time.Now().Unix(),
	}
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

func TestGrantFetchHappyPath(t *testing.T) {
	th := newGrantTestHarness(t)
	defer th.close()

	g := th.seedActiveGrant("conn-peer-a", "peer-a-guid", "contact.phone.mobile", GrantModeRenewable, 0, 0)

	env := fakeEnv("conn-peer-a", "peer-a-guid", GrantFetch{
		RequestID: "fetch-1",
		GrantID:   g.GrantID,
	})
	if err := th.h.HandleIncomingFetch(context.Background(), env); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	resp := th.decryptCapturedFetchResponse("conn-peer-a")
	if resp.Status != "ok" {
		t.Fatalf("expected ok, got status=%q error=%q", resp.Status, resp.Error)
	}
	if resp.Value != "+15551234567" {
		t.Errorf("expected seeded value, got %q", resp.Value)
	}

	stored, err := th.h.loadGrant(g.GrantID)
	if err != nil {
		t.Fatalf("reload grant: %v", err)
	}
	if stored.UsesSoFar != 1 {
		t.Errorf("expected uses_so_far=1, got %d", stored.UsesSoFar)
	}
	if stored.LastFetchedAt == 0 {
		t.Errorf("expected last_fetched_at stamped")
	}
}

func TestGrantFetchExpired(t *testing.T) {
	th := newGrantTestHarness(t)
	defer th.close()

	past := time.Now().Add(-time.Hour).Unix()
	g := th.seedActiveGrant("conn-peer-a", "peer-a-guid", "contact.phone.mobile", GrantModeOneShot, past, 1)

	env := fakeEnv("conn-peer-a", "peer-a-guid", GrantFetch{
		RequestID: "fetch-1",
		GrantID:   g.GrantID,
	})
	_ = th.h.HandleIncomingFetch(context.Background(), env)

	resp := th.decryptCapturedFetchResponse("conn-peer-a")
	if resp.Status != "denied" || resp.Error != "grant_expired" {
		t.Errorf("expected denied/grant_expired, got status=%q error=%q", resp.Status, resp.Error)
	}
	stored, _ := th.h.loadGrant(g.GrantID)
	if stored.Status != GrantStatusExpired {
		t.Errorf("expected lazy flip to expired, got %q", stored.Status)
	}
}

func TestGrantMaxUsesExhausted(t *testing.T) {
	th := newGrantTestHarness(t)
	defer th.close()

	g := th.seedActiveGrant("conn-peer-a", "peer-a-guid", "contact.phone.mobile", GrantModeRenewable, 0, 5)

	for i := 1; i <= 5; i++ {
		env := fakeEnv("conn-peer-a", "peer-a-guid", GrantFetch{
			RequestID: fmt.Sprintf("fetch-%d", i),
			GrantID:   g.GrantID,
		})
		if err := th.h.HandleIncomingFetch(context.Background(), env); err != nil {
			t.Fatalf("fetch #%d: %v", i, err)
		}
	}
	stored, _ := th.h.loadGrant(g.GrantID)
	if stored.UsesSoFar != 5 {
		t.Fatalf("expected uses_so_far=5 after 5 fetches, got %d", stored.UsesSoFar)
	}

	envDeny := fakeEnv("conn-peer-a", "peer-a-guid", GrantFetch{
		RequestID: "fetch-6",
		GrantID:   g.GrantID,
	})
	_ = th.h.HandleIncomingFetch(context.Background(), envDeny)

	resp := th.decryptCapturedFetchResponse("conn-peer-a")
	if resp.Status != "denied" || resp.Error != "max_uses_exhausted" {
		t.Errorf("expected denied/max_uses_exhausted on 6th fetch, got %+v", resp)
	}

	stored2, _ := th.h.loadGrant(g.GrantID)
	if stored2.UsesSoFar != 5 {
		t.Errorf("expected uses_so_far=5 after denied 6th, got %d", stored2.UsesSoFar)
	}
}

func TestGrantRevokeFlow(t *testing.T) {
	th := newGrantTestHarness(t)
	defer th.close()

	g := th.seedActiveGrant("conn-peer-a", "peer-a-guid", "contact.phone.mobile", GrantModeRenewable, 0, 0)

	body, _ := json.Marshal(map[string]string{"grant_id": g.GrantID, "reason": "user_revoked"})
	resp, _ := th.h.HandleRevoke(&IncomingMessage{ID: "msg-1", Payload: body})
	if resp.Type == MessageTypeError {
		t.Fatalf("revoke errored: %s", string(resp.Payload))
	}

	stored, _ := th.h.loadGrant(g.GrantID)
	if stored.Status != GrantStatusRevoked {
		t.Errorf("expected status revoked, got %q", stored.Status)
	}
	if stored.RevokedAt == 0 {
		t.Errorf("expected revoked_at stamped")
	}
	if th.findLastSubject(".forVault.data.grant.revoked") == nil {
		t.Errorf("expected grant.revoked publish, got subjects=%v", th.capturedSubjects())
	}

	env := fakeEnv("conn-peer-a", "peer-a-guid", GrantFetch{
		RequestID: "post-revoke",
		GrantID:   g.GrantID,
	})
	_ = th.h.HandleIncomingFetch(context.Background(), env)
	respFetch := th.decryptCapturedFetchResponse("conn-peer-a")
	if respFetch.Status != "denied" || respFetch.Error != "grant_revoked" {
		t.Errorf("expected denied/grant_revoked on post-revoke fetch, got %+v", respFetch)
	}
}

func TestGrantCrossConnectionIsolation(t *testing.T) {
	th := newGrantTestHarness(t)
	defer th.close()

	g := th.seedActiveGrant("conn-peer-a", "peer-a-guid", "contact.phone.mobile", GrantModeRenewable, 0, 0)

	env := fakeEnv("conn-peer-b", "peer-b-guid", GrantFetch{
		RequestID: "evil-fetch",
		GrantID:   g.GrantID,
	})
	_ = th.h.HandleIncomingFetch(context.Background(), env)

	// The fetch-response goes back to peer B over their connection,
	// so decrypt with peer B's shared secret.
	resp := th.decryptCapturedFetchResponse("conn-peer-b")
	if resp.Status != "denied" || resp.Error != "requester_mismatch" {
		t.Errorf("expected denied/requester_mismatch, got %+v", resp)
	}

	stored, _ := th.h.loadGrant(g.GrantID)
	if stored.UsesSoFar != 0 {
		t.Errorf("legitimate grant's uses_so_far advanced from cross-peer attempt: %d", stored.UsesSoFar)
	}
}

func TestGrantItemDeletedMidGrant(t *testing.T) {
	th := newGrantTestHarness(t)
	defer th.close()

	g := th.seedActiveGrant("conn-peer-a", "peer-a-guid", "contact.phone.mobile", GrantModeRenewable, 0, 0)

	if err := th.encStor.Delete("personal-data/contact.phone.mobile"); err != nil {
		t.Fatalf("delete pdf: %v", err)
	}

	env := fakeEnv("conn-peer-a", "peer-a-guid", GrantFetch{
		RequestID: "stale-fetch",
		GrantID:   g.GrantID,
	})
	_ = th.h.HandleIncomingFetch(context.Background(), env)

	resp := th.decryptCapturedFetchResponse("conn-peer-a")
	if resp.Status != "denied" || resp.Error != "item_not_found" {
		t.Errorf("expected denied/item_not_found, got %+v", resp)
	}
	stored, _ := th.h.loadGrant(g.GrantID)
	if stored.UsesSoFar != 0 {
		t.Errorf("expected uses_so_far=0 after item-not-found, got %d", stored.UsesSoFar)
	}
}

func TestGrantItemMarkedPrivate(t *testing.T) {
	th := newGrantTestHarness(t)
	defer th.close()

	g := th.seedActiveGrant("conn-peer-a", "peer-a-guid", "contact.phone.mobile", GrantModeRenewable, 0, 0)

	field := PersonalDataField{
		ID:              "pdf-1",
		Name:            "contact.phone.mobile",
		Value:           "+15551234567",
		FieldType:       "PHONE",
		Discoverability: DiscoverabilityPrivate,
	}
	data, _ := json.Marshal(&field)
	_ = th.encStor.Put("personal-data/contact.phone.mobile", data)

	env := fakeEnv("conn-peer-a", "peer-a-guid", GrantFetch{
		RequestID: "private-fetch",
		GrantID:   g.GrantID,
	})
	_ = th.h.HandleIncomingFetch(context.Background(), env)

	resp := th.decryptCapturedFetchResponse("conn-peer-a")
	if resp.Status != "denied" || resp.Error != "item_marked_private" {
		t.Errorf("expected denied/item_marked_private, got %+v", resp)
	}
}

// TestGrantSecretFetchHappyPath: minor secret can be requested + fetched.
func TestGrantSecretFetchHappyPath(t *testing.T) {
	th := newGrantTestHarness(t)
	defer th.close()

	// Seed a minor secret.
	rec := SecretRecord{
		ID:              "sec-mobile-pass",
		Name:            "WiFi password",
		Value:           "hunter2",
		Category:        "Other",
		Discoverability: DiscoverabilityCataloged,
		CreatedAt:       time.Now().Unix(),
	}
	data, _ := json.Marshal(&rec)
	_ = th.encStor.Put("secrets/sec-mobile-pass", data)
	idx, _ := json.Marshal([]string{"sec-mobile-pass"})
	_ = th.encStor.Put("secrets/_index", idx)

	g := &GrantRecord{
		GrantID:       "grant-secret-1",
		OwnerGUID:     th.h.ownerSpace,
		RequesterGUID: "peer-a-guid",
		ConnectionID:  "conn-peer-a",
		ItemKind:      GrantItemKindSecret,
		ItemRef:       "sec-mobile-pass",
		ItemLabel:     "WiFi password",
		Mode:          GrantModeOneShot,
		MaxUses:       1,
		Status:        GrantStatusActive,
		CreatedAt:     time.Now().Unix(),
	}
	_ = th.h.saveGrant(g)
	_ = th.h.appendToIndex(grantsIndexKey, g.GrantID)

	env := fakeEnv("conn-peer-a", "peer-a-guid", GrantFetch{
		RequestID: "fetch-secret-1",
		GrantID:   g.GrantID,
	})
	_ = th.h.HandleIncomingFetch(context.Background(), env)

	resp := th.decryptCapturedFetchResponse("conn-peer-a")
	if resp.Status != "ok" {
		t.Fatalf("expected ok, got status=%q error=%q", resp.Status, resp.Error)
	}
	if resp.Value != "hunter2" {
		t.Errorf("expected hunter2, got %q", resp.Value)
	}
}

// TestSecretRequestRejectsCritical pins the load-bearing safety
// invariant from plans/data-request-grants.md Phase 4: a request for
// a secret whose ID is registered as a critical secret MUST be
// rejected, no value resolution attempted.
func TestSecretRequestRejectsCritical(t *testing.T) {
	th := newGrantTestHarness(t)
	defer th.close()

	// Register the ID as a critical secret in the metadata index.
	meta := []SecretMetadataRecord{{
		ID:              "sec-wallet-seed-1",
		Name:            "Wallet seed phrase",
		Category:        "SEED_PHRASE",
		Owner:           "user",
		Discoverability: DiscoverabilityCataloged,
		CreatedAt:       time.Now().Unix(),
	}}
	metaData, _ := json.Marshal(&meta)
	_ = th.encStor.Put("credential-secrets/_metadata", metaData)

	// Seed an active grant pointing at that ID. (In practice the grant
	// shouldn't ever be created in the first place — the catalog rows
	// are critical-flagged on the requester's side — but the resolver
	// is the load-bearing safety net and the test pins it here.)
	g := &GrantRecord{
		GrantID:       "grant-bad-critical",
		OwnerGUID:     th.h.ownerSpace,
		RequesterGUID: "peer-a-guid",
		ConnectionID:  "conn-peer-a",
		ItemKind:      GrantItemKindSecret,
		ItemRef:       "sec-wallet-seed-1",
		ItemLabel:     "Wallet seed phrase",
		Mode:          GrantModeOneShot,
		MaxUses:       1,
		Status:        GrantStatusActive,
		CreatedAt:     time.Now().Unix(),
	}
	_ = th.h.saveGrant(g)
	_ = th.h.appendToIndex(grantsIndexKey, g.GrantID)

	env := fakeEnv("conn-peer-a", "peer-a-guid", GrantFetch{
		RequestID: "fetch-critical",
		GrantID:   g.GrantID,
	})
	_ = th.h.HandleIncomingFetch(context.Background(), env)

	resp := th.decryptCapturedFetchResponse("conn-peer-a")
	if resp.Status != "denied" || resp.Error != "critical_secret_not_requestable" {
		t.Errorf("expected denied/critical_secret_not_requestable — value MUST NOT leak — got %+v", resp)
	}
	if resp.Value != "" {
		t.Errorf("CRITICAL FAILURE: critical secret value present in response: %q", resp.Value)
	}

	// The counter MUST NOT have advanced — a denied fetch should not
	// consume the grant's max-uses budget.
	stored, _ := th.h.loadGrant(g.GrantID)
	if stored.UsesSoFar != 0 {
		t.Errorf("expected uses_so_far=0 after critical-secret denial, got %d", stored.UsesSoFar)
	}
}

func TestApproveSingleGrantPerItemPeer(t *testing.T) {
	th := newGrantTestHarness(t)
	defer th.close()

	first := DataAccessRequest{
		RequestID: "req-1",
		ItemKind:  GrantItemKindData,
		ItemRef:   "contact.phone.mobile",
		ItemLabel: "Mobile",
		Mode:      GrantModeOneShot,
		DeliverTo: GrantDeliverSelf,
	}
	env := fakeEnv("conn-peer-a", "peer-a-guid", first)
	if err := th.h.HandleIncomingRequest(context.Background(), env); err != nil {
		t.Fatalf("incoming #1: %v", err)
	}
	approve, _ := json.Marshal(map[string]interface{}{"request_id": "req-1"})
	resp, _ := th.h.HandleApprove(&IncomingMessage{ID: "m1", Payload: approve})
	if resp.Type == MessageTypeError {
		t.Fatalf("approve #1: %s", string(resp.Payload))
	}
	ids1 := th.h.loadIndex("connections/conn-peer-a" + outboundGrantsIndexSuffix)
	if len(ids1) != 1 {
		t.Fatalf("expected 1 outbound grant after first approve, got %d", len(ids1))
	}

	second := DataAccessRequest{
		RequestID:        "req-2",
		ItemKind:         GrantItemKindData,
		ItemRef:          "contact.phone.mobile",
		ItemLabel:        "Mobile",
		Mode:             GrantModeRenewable,
		DeliverTo:        GrantDeliverSelf,
		RequestedMaxUses: 10,
	}
	env2 := fakeEnv("conn-peer-a", "peer-a-guid", second)
	if err := th.h.HandleIncomingRequest(context.Background(), env2); err != nil {
		t.Fatalf("incoming #2: %v", err)
	}
	approve2, _ := json.Marshal(map[string]interface{}{"request_id": "req-2"})
	resp2, _ := th.h.HandleApprove(&IncomingMessage{ID: "m2", Payload: approve2})
	if resp2.Type == MessageTypeError {
		t.Fatalf("approve #2: %s", string(resp2.Payload))
	}

	ids2 := th.h.loadIndex("connections/conn-peer-a" + outboundGrantsIndexSuffix)
	if len(ids2) != 1 {
		t.Errorf("expected still 1 outbound grant after re-approval, got %d", len(ids2))
	}
	g, err := th.h.loadGrant(ids2[0])
	if err != nil {
		t.Fatalf("load grant: %v", err)
	}
	if g.Mode != GrantModeRenewable {
		t.Errorf("expected mode renewable after re-approval, got %q", g.Mode)
	}
	if g.MaxUses != 10 {
		t.Errorf("expected max_uses=10 after re-approval, got %d", g.MaxUses)
	}
	if g.UsesSoFar != 0 {
		t.Errorf("expected uses_so_far reset to 0 on re-approval, got %d", g.UsesSoFar)
	}
}
