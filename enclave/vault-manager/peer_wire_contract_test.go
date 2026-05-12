package main

// Wire-contract tests for peer-broadcast subjects.
//
// Each `forVault.<event>` peer subject has a sender struct that
// BroadcastPublishedProfile-style helpers marshal, and a receiver
// struct that the matching Handle* method unmarshals. When the two
// drift (different field types under the same JSON tag, missing tag,
// or omitempty/required mismatch) the receive side silently fails:
// json.Unmarshal returns an error, the handler short-circuits, and
// the user-facing effect is a stale cached profile or a missing
// notification with no log to identify the dropped event class.
//
// History: ProfileUpdateNotification.Fields shipped as
// map[string]ProfileFieldValue while IncomingProfileUpdateNotification.Fields
// was typed as map[string]string. Every broadcast carrying at least
// one published field hit "cannot unmarshal object into Go struct
// field IncomingProfileUpdateNotification.fields of type string" and
// the whole profile-update — including the `profile` snapshot used to
// refresh connections/<id>/_peer_profile — was dropped. The fix landed
// in fb4048a (notifications.go); this test file is what makes sure
// the next instance of the same bug breaks the build.
//
// What to add when introducing a new peer subject: a new sender struct
// (or reuse an existing one) and a new test below that marshals it,
// unmarshals into the receiver-side struct, and asserts the load-bearing
// fields survive. If the subject reuses one type for both directions,
// a self-roundtrip test still catches tag/typing regressions.

import (
	"encoding/json"
	"strings"
	"testing"
)

// roundTrip marshals src, unmarshals into dst, and reports the source
// location of the caller on failure so the failing pair is obvious in
// CI output without scrolling.
func roundTrip(t *testing.T, label string, src interface{}, dst interface{}) {
	t.Helper()
	data, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("%s: marshal sender struct: %v", label, err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("%s: sender->receiver schema drift: %v\nwire: %s", label, err, string(data))
	}
}

func TestProfileUpdateBroadcastWire(t *testing.T) {
	sender := ProfileUpdateNotification{
		Fields: map[string]ProfileFieldValue{
			"contact.address.home": {Value: "123 Main St", UpdatedAt: "2026-05-10T20:00:00Z"},
			"contact.phone.mobile": {Value: "+15551234567", UpdatedAt: "2026-05-10T20:00:00Z"},
		},
		UpdatedAt:      "2026-05-10T20:00:00Z",
		Profile:        map[string]interface{}{"first_name": "Al", "public_key": "AAAA"},
		FromOwnerSpace: "af44310d-2051-46a1-afd8-ee275b53f804",
	}
	var receiver IncomingProfileUpdateNotification
	roundTrip(t, "profile-update", sender, &receiver)

	if receiver.FromOwnerSpace != sender.FromOwnerSpace {
		t.Errorf("from_owner_space lost: got %q want %q", receiver.FromOwnerSpace, sender.FromOwnerSpace)
	}
	if receiver.UpdatedAt != sender.UpdatedAt {
		t.Errorf("updated_at lost: got %q want %q", receiver.UpdatedAt, sender.UpdatedAt)
	}
	if len(receiver.Fields) != len(sender.Fields) {
		t.Errorf("fields count lost: got %d want %d", len(receiver.Fields), len(sender.Fields))
	}
	for k, want := range sender.Fields {
		got, ok := receiver.Fields[k]
		if !ok {
			t.Errorf("fields[%q] missing on receiver", k)
			continue
		}
		if got.Value != want.Value {
			t.Errorf("fields[%q].value: got %q want %q", k, got.Value, want.Value)
		}
		if got.UpdatedAt != want.UpdatedAt {
			t.Errorf("fields[%q].updated_at: got %q want %q", k, got.UpdatedAt, want.UpdatedAt)
		}
	}
	if len(receiver.Profile) == 0 {
		t.Error("profile snapshot lost — this is what refreshes the cached peer profile")
	}
}

// Empty Fields is the case that masked the drift bug for weeks: a
// broadcast with no published public fields serialized as `{}` and
// round-tripped fine against either receiver-side type. Keep this
// test so a future "tighten receiver Fields shape" change still works
// when peers have no public fields selected yet.
func TestProfileUpdateBroadcastWire_EmptyFields(t *testing.T) {
	sender := ProfileUpdateNotification{
		Fields:         map[string]ProfileFieldValue{},
		UpdatedAt:      "2026-05-10T20:00:00Z",
		Profile:        map[string]interface{}{"first_name": "Al"},
		FromOwnerSpace: "af44310d-2051-46a1-afd8-ee275b53f804",
	}
	var receiver IncomingProfileUpdateNotification
	roundTrip(t, "profile-update (empty fields)", sender, &receiver)
}

func TestRevocationNoticeWire(t *testing.T) {
	sender := RevocationNotification{
		ConnectionID: "conn-1234",
		RevokedAt:    "2026-05-10T20:00:00Z",
		Reason:       "user_revoked",
	}
	var receiver IncomingRevocationNotification
	roundTrip(t, "revoked", sender, &receiver)

	if receiver.ConnectionID != sender.ConnectionID {
		t.Errorf("connection_id lost: got %q want %q", receiver.ConnectionID, sender.ConnectionID)
	}
	if receiver.RevokedAt != sender.RevokedAt {
		t.Errorf("revoked_at lost: got %q want %q", receiver.RevokedAt, sender.RevokedAt)
	}
	if receiver.Reason != sender.Reason {
		t.Errorf("reason lost: got %q want %q", receiver.Reason, sender.Reason)
	}
}

// Single-typed peer subjects: sender and receiver use the same struct,
// so the failure mode isn't type drift — it's an accidentally-changed
// JSON tag or a switch from value type to pointer that breaks omitempty.
// These tests detect both by asserting field-by-field equality after
// round-trip.

func TestLocationUpdateWire(t *testing.T) {
	accuracy := float32(12.5)
	sender := IncomingLocationUpdate{
		EventID:        "loc:owner:1234567890",
		ConnectionID:   "conn-1234",
		FromOwnerSpace: "af44310d-2051-46a1-afd8-ee275b53f804",
		Latitude:       37.7749,
		Longitude:      -122.4194,
		Accuracy:       &accuracy,
		Timestamp:      1715369336,
		UpdatedAt:      "2026-05-10T20:00:00Z",
	}
	var receiver IncomingLocationUpdate
	roundTrip(t, "location-update", sender, &receiver)
	if receiver.Accuracy == nil || *receiver.Accuracy != *sender.Accuracy {
		t.Errorf("accuracy pointer round-trip failed (got %v want %v)", receiver.Accuracy, sender.Accuracy)
	}
	// FromOwnerSpace is the load-bearing receiver-side field for
	// resolving the local connection id (V1 2026-05-11). Pin it so
	// a future struct change that drops or renames the json tag
	// fails this test instead of silently breaking the V2 cache.
	if receiver.FromOwnerSpace != sender.FromOwnerSpace {
		t.Errorf("from_owner_space lost: got %q want %q", receiver.FromOwnerSpace, sender.FromOwnerSpace)
	}
	// The GPS-sample epoch ships as `captured_at`, NOT `timestamp` —
	// renamed 2026-05-11 because the parent's replay-prevention layer
	// drops any message whose top-level `timestamp` field is older
	// than 5 minutes. A renamed-back regression would let a peer
	// location older than 5 min sneak through replay-prevention as
	// a "fresh" message, AND would silently break location.send-once
	// once the field crossed the parent boundary.
	raw, _ := json.Marshal(sender)
	rawStr := string(raw)
	if !strings.Contains(rawStr, `"captured_at":`) {
		t.Errorf("expected captured_at on wire; got: %s", rawStr)
	}
	if strings.Contains(rawStr, `"timestamp":`) {
		t.Errorf("unexpected top-level `timestamp` field on the wire — replay-prevention will eat it: %s", rawStr)
	}
	// Compare value-equal fields (can't compare with pointer fields)
	if receiver.EventID != sender.EventID || receiver.Latitude != sender.Latitude ||
		receiver.Longitude != sender.Longitude || receiver.Timestamp != sender.Timestamp ||
		receiver.UpdatedAt != sender.UpdatedAt || receiver.ConnectionID != sender.ConnectionID {
		t.Errorf("location-update non-pointer fields lost\n got: %+v\nwant: %+v", receiver, sender)
	}
}

func TestLocationStopWire(t *testing.T) {
	sender := LocationStopBroadcast{
		EventID:        "loc-stop:owner:1234567890",
		FromOwnerSpace: "af44310d-2051-46a1-afd8-ee275b53f804",
		StoppedAt:      "2026-05-11T20:00:00Z",
	}
	var receiver LocationStopBroadcast
	roundTrip(t, "location-stop", sender, &receiver)
	if receiver != sender {
		t.Errorf("location-stop round-trip mismatch\n got: %+v\nwant: %+v", receiver, sender)
	}
	// FromOwnerSpace is the load-bearing receiver-side field for
	// resolving the local connection (V5). Pin it explicitly even
	// though the struct-eq check above already covers it — the
	// pinned assertion documents why the field matters.
	if receiver.FromOwnerSpace == "" {
		t.Error("from_owner_space lost — V5 receiver cannot resolve local connection without it")
	}
}

// TestEncryptedPeerEnvelopeShape pins the on-wire JSON shape of the
// envelope so a future struct change can't silently drop a field the
// parent's replay-prevention layer (or the receiver) depends on.
// We don't roundtrip through actual encryption here — that requires
// a live storage with a ConnectionRecord — but we DO verify the
// envelope JSON has the four load-bearing keys at the top level.
func TestEncryptedPeerEnvelopeShape(t *testing.T) {
	env := EncryptedPeerEnvelope{
		EventID:          "test-event",
		FromOwnerSpace:   "af44310d-2051-46a1-afd8-ee275b53f804",
		Timestamp:        1715369336,
		Nonce:            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		EncryptedPayload: "ZW5jcnlwdGVk",
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	got := string(raw)
	for _, key := range []string{
		`"from_owner_space":`, // receiver needs this to find the shared key
		`"timestamp":`,        // parent replay-prevention reads this top-level
		`"nonce":`,            // decrypt depends on this
		`"encrypted_payload":`,
	} {
		if !strings.Contains(got, key) {
			t.Errorf("envelope JSON missing %s — wire: %s", key, got)
		}
	}
	// Round-trip parse so a typo in the json tag also fails.
	var parsed EncryptedPeerEnvelope
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if parsed != env {
		t.Errorf("envelope round-trip mismatch\n got: %+v\nwant: %+v", parsed, env)
	}
}

func TestLocationRequestPingWire(t *testing.T) {
	sender := LocationRequestPing{
		EventID:        "loc-req:owner:1234567890",
		FromOwnerSpace: "af44310d-2051-46a1-afd8-ee275b53f804",
		RequestedAt:    "2026-05-11T20:00:00Z",
	}
	var receiver LocationRequestPing
	roundTrip(t, "location-request-ping", sender, &receiver)
	if receiver != sender {
		t.Errorf("location-request-ping round-trip mismatch\n got: %+v\nwant: %+v", receiver, sender)
	}
}

func TestPeerMessageWire(t *testing.T) {
	sender := PeerMessage{
		MessageID:        "msg-1234",
		SenderGUID:       "af44310d-2051-46a1-afd8-ee275b53f804",
		ConnectionID:     "conn-1234",
		EncryptedContent: "ciphertext-base64",
		Nonce:            "nonce-base64",
		ContentType:      "text/plain",
		SentAt:           "2026-05-10T20:00:00Z",
	}
	var receiver PeerMessage
	roundTrip(t, "message.incoming", sender, &receiver)
	if receiver != sender {
		t.Errorf("peer-message round-trip mismatch\n got: %+v\nwant: %+v", receiver, sender)
	}
}

func TestPeerReadReceiptWire(t *testing.T) {
	sender := PeerReadReceipt{
		MessageID:    "msg-1234",
		ConnectionID: "conn-1234",
		ReaderGUID:   "af44310d-2051-46a1-afd8-ee275b53f804",
		ReadAt:       "2026-05-10T20:00:00Z",
	}
	var receiver PeerReadReceipt
	roundTrip(t, "read-receipt", sender, &receiver)
	if receiver != sender {
		t.Errorf("peer-read-receipt round-trip mismatch\n got: %+v\nwant: %+v", receiver, sender)
	}
}

func TestCallEventWire(t *testing.T) {
	mline := 1
	sender := CallEvent{
		EventID:           "evt-1234",
		EventType:         "offer",
		CallerID:          "af44310d-2051-46a1-afd8-ee275b53f804",
		CalleeID:          "eb8472f6-09c6-4497-a78a-75eacda4d6e1",
		CallID:            "call-1234",
		CallerDisplayName: "Al",
		CallType:          "video",
		SDPOffer:          "v=0\r\no=- 1234...",
		Candidate:         "candidate:1 1 UDP 2122252543 192.168.1.1 50000 typ host",
		SDPMid:            "0",
		SDPMLineIndex:     &mline,
		Timestamp:         1715369336,
		Metadata:          map[string]string{"foo": "bar"},
	}
	var receiver CallEvent
	roundTrip(t, "call.*", sender, &receiver)

	if receiver.EventID != sender.EventID || receiver.CallID != sender.CallID || receiver.CallerID != sender.CallerID {
		t.Errorf("call-event identifying fields lost\n got: %+v\nwant: %+v", receiver, sender)
	}
	if receiver.SDPMLineIndex == nil || *receiver.SDPMLineIndex != mline {
		t.Errorf("sdp_m_line_index pointer round-trip failed (got %v want %d)", receiver.SDPMLineIndex, mline)
	}
	if receiver.SDPOffer != sender.SDPOffer {
		t.Error("sdp_offer lost")
	}
}

func TestBtcPaymentRequestWire(t *testing.T) {
	sender := BtcPaymentRequestContent{
		AmountSats: 100000,
		Address:    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		Memo:       "lunch",
		WalletID:   "wallet-1234",
		ExpiresAt:  "2026-05-10T21:00:00Z",
	}
	var receiver BtcPaymentRequestContent
	roundTrip(t, "btc-payment-request", sender, &receiver)
	if receiver != sender {
		t.Errorf("btc-payment-request round-trip mismatch\n got: %+v\nwant: %+v", receiver, sender)
	}
}

func TestBtcPaymentReceiptWire(t *testing.T) {
	sender := BtcPaymentReceiptContent{
		TxID:             "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
		AmountSats:       100000,
		FeeSats:          250,
		PaymentRequestID: "msg-1234",
		SenderGUID:       "af44310d-2051-46a1-afd8-ee275b53f804",
	}
	var receiver BtcPaymentReceiptContent
	roundTrip(t, "btc-payment-receipt", sender, &receiver)
	if receiver != sender {
		t.Errorf("btc-payment-receipt round-trip mismatch\n got: %+v\nwant: %+v", receiver, sender)
	}
}

func TestBtcAddressContentWire(t *testing.T) {
	sender := BtcAddressContent{
		Address:    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		Label:      "Personal",
		Network:    "mainnet",
		SenderGUID: "af44310d-2051-46a1-afd8-ee275b53f804",
	}
	var receiver BtcAddressContent
	roundTrip(t, "btc-address-request/response", sender, &receiver)
	if receiver != sender {
		t.Errorf("btc-address round-trip mismatch\n got: %+v\nwant: %+v", receiver, sender)
	}
}
