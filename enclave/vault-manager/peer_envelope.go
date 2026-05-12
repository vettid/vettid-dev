package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// EncryptedPeerEnvelope is the wire format for vault-to-vault
// broadcasts that carry sensitive content (location coordinates,
// call SDPs, BTC addresses/amounts, presence timing). The inner
// payload is encrypted with the per-connection shared secret derived
// during the E2E handshake, so the NATS broker (operator-controlled)
// sees only ciphertext and routing metadata.
//
// The envelope replaces direct JSON marshaling of peer broadcast
// structs at every sensitive call site. Subjects (forVault.location-
// update, forVault.call.offer, etc.) stay plaintext for routing.
//
// Plaintext fields:
//   - FromOwnerSpace: receiver needs this to find the local connection
//     and load the shared secret. Already exposed by the subject + the
//     pre-encryption schema; encrypting it would create a chicken-and-egg
//     problem at the receiver.
//   - Timestamp: send time, in epoch seconds. The parent's replay-
//     prevention layer reads any top-level `timestamp` field and drops
//     messages older than 5 minutes — providing it explicitly here
//     keeps that guardrail working on encrypted broadcasts.
//   - EventID: optional vault-side dedup key. Receivers MarkEventProcessed
//     on first decrypt; duplicates are dropped before re-running the
//     handler.
//
// Encrypted field (EncryptedPayload + Nonce):
//   The original inner payload (e.g. IncomingLocationUpdate, CallEvent,
//   BtcPaymentRequestContent) JSON-encoded then sealed with
//   XChaCha20-Poly1305 (same primitive direct messages already use).
//   Format: Nonce is base64 of the 24-byte nonce; EncryptedPayload is
//   base64 of (ciphertext + 16-byte Poly1305 tag).
type EncryptedPeerEnvelope struct {
	EventID          string `json:"event_id,omitempty"`
	FromOwnerSpace   string `json:"from_owner_space"`
	Timestamp        int64  `json:"timestamp"`
	Nonce            string `json:"nonce"`
	EncryptedPayload string `json:"encrypted_payload"`
}

// peerPublisher is the minimal publish surface the encrypt-and-publish
// helper depends on. *VsockPublisher implements it directly, and so
// does CallPublisher (calls.go) — interface keeps the helper usable
// from every peer-broadcast site without forcing a single concrete
// type on every handler struct.
type peerPublisher interface {
	PublishToVault(ctx context.Context, targetOwnerSpace string, eventType string, payload []byte) error
}

// encryptAndPublishToPeer encrypts payload with the connection's
// shared secret and publishes it to the peer's forVault.<eventType>
// subject. Use this for every peer broadcast that carries sensitive
// content — never PublishToVault directly with the raw struct.
//
// connID is the LOCAL connection id; we look up the connection record
// to get PeerGUID (routing target) and SharedSecret (encryption key).
// eventID, if non-empty, gates the receiver's dedup check.
func encryptAndPublishToPeer(
	ctx context.Context,
	storage *EncryptedStorage,
	publisher peerPublisher,
	ownerSpace string,
	connID string,
	eventType string,
	eventID string,
	payload []byte,
	sentAt int64,
) error {
	connData, err := storage.Get("connections/" + connID)
	if err != nil {
		return fmt.Errorf("load connection %s: %w", connID, err)
	}
	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return fmt.Errorf("parse connection %s: %w", connID, err)
	}
	if conn.PeerGUID == "" {
		return fmt.Errorf("connection %s has no peer GUID", connID)
	}
	if len(conn.SharedSecret) == 0 {
		return fmt.Errorf("connection %s has no shared secret (key exchange not complete)", connID)
	}

	key, err := deriveConnectionKey(conn.SharedSecret)
	if err != nil {
		return fmt.Errorf("derive connection key: %w", err)
	}
	sealed, err := encryptXChaCha20(key, payload)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	// encryptXChaCha20 returns nonce || ciphertext+tag.
	const nonceLen = 24
	if len(sealed) < nonceLen {
		return fmt.Errorf("ciphertext shorter than nonce length")
	}
	envelope := EncryptedPeerEnvelope{
		EventID:          eventID,
		FromOwnerSpace:   ownerSpace,
		Timestamp:        sentAt,
		Nonce:            base64.StdEncoding.EncodeToString(sealed[:nonceLen]),
		EncryptedPayload: base64.StdEncoding.EncodeToString(sealed[nonceLen:]),
	}
	envData, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	return publisher.PublishToVault(ctx, conn.PeerGUID, eventType, envData)
}

// encryptAndPublishToPeerByGUID is the peerGUID-keyed variant of
// encryptAndPublishToPeer. Some senders (calls, the BTC handlers
// when responding to incoming requests) only have the peer's
// owner-space GUID in scope, not the local connection ID. This
// helper resolves the local connection from the peer GUID first,
// then delegates.
func encryptAndPublishToPeerByGUID(
	ctx context.Context,
	storage *EncryptedStorage,
	publisher peerPublisher,
	ownerSpace string,
	peerGUID string,
	eventType string,
	eventID string,
	payload []byte,
	sentAt int64,
) error {
	connID := findLocalConnectionForPeer(storage, peerGUID)
	if connID == "" {
		return fmt.Errorf("no local connection for peer %s", peerGUID)
	}
	return encryptAndPublishToPeer(ctx, storage, publisher, ownerSpace, connID, eventType, eventID, payload, sentAt)
}

// decryptedPeerEnvelope is what a receiver gets back from
// decryptIncomingPeerEnvelope: the plaintext inner payload plus
// load-bearing envelope metadata (resolved local conn id, sender
// owner_space, optional event id).
type decryptedPeerEnvelope struct {
	InnerPayload   []byte
	LocalConnID    string
	FromOwnerSpace string
	EventID        string
	SentAt         int64
}

// decryptIncomingPeerEnvelope unwraps an EncryptedPeerEnvelope on the
// receiver side. Resolves the local connection from FromOwnerSpace,
// loads the shared secret, derives the symmetric key, decrypts.
//
// Errors are returned for: malformed JSON, missing from_owner_space,
// unknown peer (no local connection for that peer GUID), missing
// shared secret (key exchange not complete on receiver), and
// authentication failure (wrong key or tampered ciphertext).
func decryptIncomingPeerEnvelope(
	storage *EncryptedStorage,
	envelopeData []byte,
) (*decryptedPeerEnvelope, error) {
	var env EncryptedPeerEnvelope
	if err := json.Unmarshal(envelopeData, &env); err != nil {
		return nil, fmt.Errorf("parse envelope: %w", err)
	}
	if env.FromOwnerSpace == "" {
		return nil, fmt.Errorf("envelope missing from_owner_space")
	}

	connID := findLocalConnectionForPeer(storage, env.FromOwnerSpace)
	if connID == "" {
		return nil, fmt.Errorf("no local connection for peer %s", env.FromOwnerSpace)
	}
	connData, err := storage.Get("connections/" + connID)
	if err != nil {
		return nil, fmt.Errorf("load connection %s: %w", connID, err)
	}
	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return nil, fmt.Errorf("parse connection %s: %w", connID, err)
	}
	if len(conn.SharedSecret) == 0 {
		return nil, fmt.Errorf("connection %s has no shared secret", connID)
	}

	key, err := deriveConnectionKey(conn.SharedSecret)
	if err != nil {
		return nil, fmt.Errorf("derive connection key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.EncryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	combined := make([]byte, 0, len(nonce)+len(ciphertext))
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)
	plaintext, err := decryptXChaCha20(key, combined)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return &decryptedPeerEnvelope{
		InnerPayload:   plaintext,
		LocalConnID:    connID,
		FromOwnerSpace: env.FromOwnerSpace,
		EventID:        env.EventID,
		SentAt:         env.Timestamp,
	}, nil
}

// findLocalConnectionForPeer walks the connection index and returns
// the local connection id whose PeerGUID matches the argument.
// Package-level helper so handlers don't each carry their own copy.
func findLocalConnectionForPeer(storage *EncryptedStorage, peerGUID string) string {
	indexData, err := storage.Get("connections/_index")
	if err != nil {
		return ""
	}
	var connectionIDs []string
	if json.Unmarshal(indexData, &connectionIDs) != nil {
		return ""
	}
	for _, connID := range connectionIDs {
		data, err := storage.Get("connections/" + connID)
		if err != nil {
			continue
		}
		var conn ConnectionRecord
		if json.Unmarshal(data, &conn) != nil {
			continue
		}
		if conn.PeerGUID == peerGUID {
			return connID
		}
	}
	return ""
}
