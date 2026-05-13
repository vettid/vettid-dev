package main

// connection.authenticate — proof-of-credential challenge/response.
//
// A peer publishes a challenge nonce to us; we sign
// "vettid-conn-auth-v1|<our_owner_space>|<their_owner_space>|<nonce>"
// with our identity key and return the signature. The challenger
// verifies against our cached identity public key.
//
// Use cases:
//   - Phase 1: enrich the audit trail. Every successful auth round-trip
//     produces a "connection.authenticated" entry on both sides AND
//     an "identity_key.used" row tagged purpose=connection_authenticate.
//   - Phase 2 (later): wire this as the standard challenge for service-
//     vault interactions where the service needs cryptographic proof
//     a connection holds the credential before serving privileged ops.
//
// Auto-respond: today we sign without UI prompt — the cost of a
// signature is low and proof-of-credential is a well-bounded operation
// (the signed payload's domain separator "vettid-conn-auth-v1|..." can
// only be interpreted as an auth response, not reused for action
// invocations or contracts). Future revision could gate this behind a
// user toggle if abuse patterns appear.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	connectionAuthDomain = "vettid-conn-auth-v1"
)

// ConnectionAuthChallenge is the requester → owner payload.
type ConnectionAuthChallenge struct {
	RequestID string `json:"request_id"`
	Nonce     string `json:"nonce"`     // base64 random bytes
	Context   string `json:"context,omitempty"`
}

// ConnectionAuthResponse is the owner → requester payload.
// Status carries the explicit verdict from the receiver:
//   "signed"          — IdentityPubKey + Signature populated; requester verifies
//   "identity_locked" — receiver's identity key is currently locked (TTL expired);
//                       user needs to unlock their identity to prove it
//   "denied"          — receiver explicitly refused (future user-toggle)
type ConnectionAuthResponse struct {
	RequestID      string `json:"request_id"`
	Status         string `json:"status,omitempty"`
	IdentityPubKey string `json:"identity_pub_key,omitempty"` // base64 ed25519 pubkey
	Signature      string `json:"signature,omitempty"`         // base64 ed25519 sig over domain-separated payload
	SignedAt       string `json:"signed_at,omitempty"`         // RFC3339
}

// HandleAuthRequest is the receiver-side app op that sends a challenge.
// Payload: {"connection_id": "...", "context": "...?"}
func (mh *MessageHandler) HandleAuthRequest(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
		Context      string `json:"context,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "ConnectionAuthRequest"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request")
	}
	if req.ConnectionID == "" {
		return mh.errorResponse(msg.GetID(), "connection_id required")
	}
	var nonceBytes [24]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return mh.errorResponse(msg.GetID(), "rand failed")
	}
	challenge := ConnectionAuthChallenge{
		RequestID: newID("conn-auth-"),
		Nonce:     base64.StdEncoding.EncodeToString(nonceBytes[:]),
		Context:   req.Context,
	}
	payload, _ := json.Marshal(&challenge)
	if err := encryptAndPublishToPeer(
		context.Background(), mh.storage, mh.publisher, mh.ownerSpace,
		req.ConnectionID, "connection.authenticate.challenge", "conn-auth:"+challenge.RequestID,
		payload, time.Now().Unix(),
	); err != nil {
		return mh.errorResponse(msg.GetID(), "publish: "+err.Error())
	}
	// Store the challenge locally so we can verify the response when it
	// arrives. Key by request_id + connection_id; tiny record, no
	// indexing — pending challenges are short-lived (5 minutes max).
	pending := map[string]string{
		"connection_id": req.ConnectionID,
		"nonce":         challenge.Nonce,
		"sent_at":       time.Now().UTC().Format(time.RFC3339),
	}
	pendingData, _ := json.Marshal(pending)
	_ = mh.storage.Put("conn_auth_pending/"+challenge.RequestID, pendingData)

	if mh.auditLog != nil {
		mh.auditLog.Append(AuditEntry{
			ConnectionID: req.ConnectionID,
			EventType:    AuditTypeConnectionAuthenticateRequested,
			Direction:    AuditDirectionOutbound,
			Title:        "Requested authentication",
			Body:         req.Context,
			Refs:         map[string]string{"request_id": challenge.RequestID},
		})
	}
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":    true,
		"request_id": challenge.RequestID,
	})
	return mh.successResponse(msg.GetID(), respBytes)
}

// HandleIncomingAuthChallenge is the owner-side peer-subject handler.
// Decrypted envelope; we sign the canonical payload and emit a response.
func (mh *MessageHandler) HandleIncomingAuthChallenge(ctx context.Context, dec *decryptedPeerEnvelope) error {
	if dec == nil {
		return fmt.Errorf("nil envelope")
	}
	var challenge ConnectionAuthChallenge
	if err := json.Unmarshal(dec.InnerPayload, &challenge); err != nil {
		return fmt.Errorf("invalid auth challenge: %w", err)
	}
	if challenge.RequestID == "" || challenge.Nonce == "" {
		return fmt.Errorf("auth challenge missing required fields")
	}
	// Pull our identity public key + private key.
	idKey, err := mh.consumeIdentityKey()
	if err != nil {
		// Identity locked — emit an explicit identity_locked status so
		// the requester can surface "peer's identity is locked, ask
		// them to unlock and retry" rather than a generic verification
		// failure.
		log.Warn().Str("request_id", challenge.RequestID).Msg("auth challenge: identity locked")
		denial := ConnectionAuthResponse{
			RequestID: challenge.RequestID,
			Status:    "identity_locked",
		}
		payload, _ := json.Marshal(&denial)
		_ = encryptAndPublishToPeer(
			ctx, mh.storage, mh.publisher, mh.ownerSpace,
			dec.LocalConnID, "connection.authenticate.response", "conn-auth-resp:"+challenge.RequestID,
			payload, time.Now().Unix(),
		)
		return nil
	}
	defer zeroBytes(idKey)

	// Identity public key — derive from private if not cached.
	mh.vaultState.mu.RLock()
	idPub := append([]byte(nil), mh.vaultState.identityPublicKey...)
	mh.vaultState.mu.RUnlock()
	if len(idPub) == 0 {
		idPub = ed25519.PrivateKey(idKey).Public().(ed25519.PublicKey)
	}

	signingPayload := fmt.Sprintf("%s|%s|%s|%s",
		connectionAuthDomain,
		mh.ownerSpace,
		dec.FromOwnerSpace,
		challenge.Nonce,
	)
	sig := ed25519.Sign(idKey, []byte(signingPayload))
	mh.auditIdentityKey("connection_authenticate", dec.LocalConnID, map[string]string{
		"request_id":    challenge.RequestID,
		"challenger":    dec.FromOwnerSpace,
	})

	resp := ConnectionAuthResponse{
		RequestID:      challenge.RequestID,
		IdentityPubKey: base64.StdEncoding.EncodeToString(idPub),
		Signature:      base64.StdEncoding.EncodeToString(sig),
		SignedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	payload, _ := json.Marshal(&resp)
	if err := encryptAndPublishToPeer(
		ctx, mh.storage, mh.publisher, mh.ownerSpace,
		dec.LocalConnID, "connection.authenticate.response", "conn-auth-resp:"+challenge.RequestID,
		payload, time.Now().Unix(),
	); err != nil {
		log.Warn().Err(err).Str("request_id", challenge.RequestID).Msg("auth response publish failed")
	}
	if mh.auditLog != nil {
		mh.auditLog.Append(AuditEntry{
			ConnectionID: dec.LocalConnID,
			PeerGUID:     dec.FromOwnerSpace,
			EventType:    AuditTypeConnectionAuthenticated,
			Direction:    AuditDirectionOutbound,
			Title:        "Proved identity to peer",
			Refs:         map[string]string{"request_id": challenge.RequestID},
		})
	}
	// Notify the receiver's app that a verify just happened, so the
	// user knows a peer challenged them. Informational — no decision
	// needed since the response went out automatically.
	if mh.publisher != nil {
		appPayload, _ := json.Marshal(map[string]interface{}{
			"connection_id":  dec.LocalConnID,
			"challenger_guid": dec.FromOwnerSpace,
			"request_id":     challenge.RequestID,
			"context":        challenge.Context,
			"verified_at":    resp.SignedAt,
		})
		_ = mh.publisher.PublishToApp(ctx, "connection.identity-verify-challenged", appPayload)
	}
	return nil
}

// HandleIncomingAuthResponse is the requester-side handler. Verifies
// the signature against the peer's cached identity public key and
// emits the verdict to the app + audit.
func (mh *MessageHandler) HandleIncomingAuthResponse(ctx context.Context, dec *decryptedPeerEnvelope) error {
	if dec == nil {
		return fmt.Errorf("nil envelope")
	}
	var resp ConnectionAuthResponse
	if err := json.Unmarshal(dec.InnerPayload, &resp); err != nil {
		return fmt.Errorf("invalid auth response: %w", err)
	}
	// Pull the pending challenge we issued.
	pendingData, err := mh.storage.Get("conn_auth_pending/" + resp.RequestID)
	if err != nil || len(pendingData) == 0 {
		log.Warn().Str("request_id", resp.RequestID).Msg("auth response without pending record")
		return nil
	}
	var pending map[string]string
	if err := json.Unmarshal(pendingData, &pending); err != nil {
		return fmt.Errorf("corrupt pending record: %w", err)
	}
	_ = mh.storage.Delete("conn_auth_pending/" + resp.RequestID)

	// Explicit "identity_locked" from peer — they got the challenge
	// but their identity key TTL had expired. Surface a meaningful
	// reason rather than treating the empty-pubkey response as a
	// signature failure.
	if resp.Status == "identity_locked" {
		mh.auditAuthFailed(dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, "peer_identity_locked")
		return mh.publishAuthVerdict(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, false, "peer_identity_locked")
	}

	// Verify the peer's identity public key matches what we have cached
	// for the connection (prevents a man-in-the-middle from substituting
	// their own key).
	cached, err := mh.loadPeerIdentityKey(dec.LocalConnID)
	if err != nil {
		mh.auditAuthFailed(dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, "no_cached_peer_identity")
		return mh.publishAuthVerdict(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, false, "no_cached_peer_identity")
	}
	claimed, err := base64.StdEncoding.DecodeString(resp.IdentityPubKey)
	if err != nil || len(claimed) != ed25519.PublicKeySize {
		mh.auditAuthFailed(dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, "invalid_pubkey_encoding")
		return mh.publishAuthVerdict(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, false, "invalid_pubkey_encoding")
	}
	if !bytesEq(cached, claimed) {
		mh.auditAuthFailed(dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, "pubkey_mismatch")
		return mh.publishAuthVerdict(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, false, "pubkey_mismatch")
	}

	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		mh.auditAuthFailed(dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, "invalid_sig_encoding")
		return mh.publishAuthVerdict(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, false, "invalid_sig_encoding")
	}
	signingPayload := fmt.Sprintf("%s|%s|%s|%s",
		connectionAuthDomain,
		dec.FromOwnerSpace,
		mh.ownerSpace,
		pending["nonce"],
	)
	if !ed25519.Verify(claimed, []byte(signingPayload), sig) {
		mh.auditAuthFailed(dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, "signature_invalid")
		return mh.publishAuthVerdict(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, false, "signature_invalid")
	}

	// Verified.
	if mh.auditLog != nil {
		mh.auditLog.Append(AuditEntry{
			ConnectionID: dec.LocalConnID,
			PeerGUID:     dec.FromOwnerSpace,
			EventType:    AuditTypeConnectionAuthenticated,
			Direction:    AuditDirectionInbound,
			Title:        "Peer proved their identity",
			Refs:         map[string]string{"request_id": resp.RequestID},
		})
	}
	return mh.publishAuthVerdict(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, true, "")
}

func (mh *MessageHandler) auditAuthFailed(connID, peerGUID, requestID, reason string) {
	if mh.auditLog == nil {
		return
	}
	mh.auditLog.Append(AuditEntry{
		ConnectionID: connID,
		PeerGUID:     peerGUID,
		EventType:    AuditTypeConnectionAuthenticateFailed,
		Direction:    AuditDirectionInbound,
		Title:        "Authentication failed: " + reason,
		Refs:         map[string]string{"request_id": requestID},
	})
}

func (mh *MessageHandler) publishAuthVerdict(ctx context.Context, connID, peerGUID, requestID string, ok bool, reason string) error {
	if mh.publisher == nil {
		return nil
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"connection_id":  connID,
		"peer_guid":      peerGUID,
		"request_id":     requestID,
		"authenticated":  ok,
		"failure_reason": reason,
	})
	return mh.publisher.PublishToApp(ctx, "connection.authenticate-result", payload)
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
