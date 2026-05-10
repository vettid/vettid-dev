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
		EventID:      "loc:owner:1234567890",
		ConnectionID: "conn-1234",
		Latitude:     37.7749,
		Longitude:    -122.4194,
		Accuracy:     &accuracy,
		Timestamp:    1715369336,
		UpdatedAt:    "2026-05-10T20:00:00Z",
	}
	var receiver IncomingLocationUpdate
	roundTrip(t, "location-update", sender, &receiver)
	if receiver.Accuracy == nil || *receiver.Accuracy != *sender.Accuracy {
		t.Errorf("accuracy pointer round-trip failed (got %v want %v)", receiver.Accuracy, sender.Accuracy)
	}
	// Compare value-equal fields (can't compare with pointer fields)
	if receiver.EventID != sender.EventID || receiver.Latitude != sender.Latitude ||
		receiver.Longitude != sender.Longitude || receiver.Timestamp != sender.Timestamp ||
		receiver.UpdatedAt != sender.UpdatedAt || receiver.ConnectionID != sender.ConnectionID {
		t.Errorf("location-update non-pointer fields lost\n got: %+v\nwant: %+v", receiver, sender)
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
