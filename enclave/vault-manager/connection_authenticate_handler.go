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

// HandleIncomingAuthChallenge is the receiver-side peer-subject handler.
//
// 2026-05-13 redesign: the receiver no longer auto-signs with a TTL-
// cached identity key. That shortcut weakened the security property
// of "this human approved this signing right now" — the lightweight
// flow only proved "the vault is alive and the key was unlocked
// recently," which is what presence heartbeats already cover.
//
// New flow: store the challenge as pending + surface a full-screen
// prompt on the receiver's app. The user reviews who's asking and
// enters their password; vault decrypts the credential once, signs
// the nonce with the identity key, wipes the key, and emits the
// response. Every verify requires explicit awareness + authorization.
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

	// Persist the pending challenge so HandleApproveVerify can sign it
	// after the user authenticates with their password. Stored under
	// pending_verify_in/<request_id> on the RECEIVER side (mirrors the
	// pending_verify_out/<request_id> the requester writes for response
	// correlation).
	pending := map[string]string{
		"connection_id":  dec.LocalConnID,
		"requester_guid": dec.FromOwnerSpace,
		"nonce":          challenge.Nonce,
		"context":        challenge.Context,
		"received_at":    time.Now().UTC().Format(time.RFC3339),
	}
	pendingData, _ := json.Marshal(pending)
	if err := mh.storage.Put("pending_verify_in/"+challenge.RequestID, pendingData); err != nil {
		log.Warn().Err(err).Str("request_id", challenge.RequestID).Msg("failed to persist pending verify challenge")
	}

	if mh.auditLog != nil {
		mh.auditLog.Append(AuditEntry{
			ConnectionID: dec.LocalConnID,
			PeerGUID:     dec.FromOwnerSpace,
			EventType:    AuditTypeConnectionAuthenticateRequested,
			Direction:    AuditDirectionInbound,
			Title:        "Asked you to prove your identity",
			Body:         challenge.Context,
			Refs:         map[string]string{"request_id": challenge.RequestID},
		})
	}
	// Notify the receiver's app so the full-screen prompt opens.
	if mh.publisher != nil {
		appPayload, _ := json.Marshal(map[string]interface{}{
			"connection_id":  dec.LocalConnID,
			"challenger_guid": dec.FromOwnerSpace,
			"request_id":     challenge.RequestID,
			"context":        challenge.Context,
			"received_at":    pending["received_at"],
		})
		_ = mh.publisher.PublishToApp(ctx, "connection.identity-verify-challenged", appPayload)
	}
	return nil
}

// HandleApproveVerify is the receiver-side app op: user has entered
// their password to authorize signing the pending challenge. Mirrors
// the vote-casting password gate — decrypts the credential, pulls the
// identity key, signs the nonce ONCE, wipes the key, publishes the
// response. No TTL caching for this op: the key is consumed only for
// the duration of the signature computation.
//
// Payload mirrors vote.cast / credential.secret.get:
//   {request_id, encrypted_credential, encrypted_password_hash,
//    ephemeral_public_key, nonce, key_id}
func (mh *MessageHandler) HandleApproveVerify(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		RequestID             string `json:"request_id"`
		EncryptedCredential   string `json:"encrypted_credential"`
		EncryptedPasswordHash string `json:"encrypted_password_hash"`
		EphemeralPublicKey    string `json:"ephemeral_public_key"`
		Nonce                 string `json:"nonce"`
		KeyID                 string `json:"key_id"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "ApproveVerify"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid approve payload")
	}
	if req.RequestID == "" || req.EncryptedCredential == "" || req.EncryptedPasswordHash == "" || req.KeyID == "" {
		return mh.errorResponse(msg.GetID(), "password authorization required")
	}

	pendingData, err := mh.storage.Get("pending_verify_in/" + req.RequestID)
	if err != nil || len(pendingData) == 0 {
		return mh.errorResponse(msg.GetID(), "pending verify request not found")
	}
	var pending map[string]string
	if err := json.Unmarshal(pendingData, &pending); err != nil {
		return mh.errorResponse(msg.GetID(), "corrupt pending verify record")
	}

	// Decrypt + verify password → identity key. One-shot, no caching.
	// Reuses the same password-gate primitive vote.cast uses, which
	// pulls the identity key directly from the password-decrypted
	// credential blob rather than the in-memory TTL carve-out.
	cred, err := mh.credentialSecretHandler.decryptCredentialBlob(req.EncryptedCredential)
	if err != nil {
		return mh.errorResponse(msg.GetID(), "credential decrypt failed")
	}
	defer cred.SecureErase()
	if err := mh.credentialSecretHandler.verifyPasswordAgainstCredential(req.EncryptedPasswordHash, req.EphemeralPublicKey, req.Nonce, req.KeyID, cred); err != nil {
		return mh.errorResponse(msg.GetID(), "password verification failed")
	}
	idKey := append([]byte{}, cred.Identity.PrivateKey...)
	defer zeroBytes(idKey)
	idPub := append([]byte{}, cred.Identity.PublicKey...)
	if len(idPub) == 0 && len(idKey) >= ed25519.PublicKeySize {
		idPub = ed25519.PrivateKey(idKey).Public().(ed25519.PublicKey)
	}

	signingPayload := fmt.Sprintf("%s|%s|%s|%s",
		connectionAuthDomain,
		mh.ownerSpace,
		pending["requester_guid"],
		pending["nonce"],
	)
	sig := ed25519.Sign(idKey, []byte(signingPayload))
	mh.auditIdentityKey("connection_authenticate", pending["connection_id"], map[string]string{
		"request_id": req.RequestID,
		"challenger": pending["requester_guid"],
	})

	resp := ConnectionAuthResponse{
		RequestID:      req.RequestID,
		IdentityPubKey: base64.StdEncoding.EncodeToString(idPub),
		Signature:      base64.StdEncoding.EncodeToString(sig),
		SignedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	payload, _ := json.Marshal(&resp)
	if err := encryptAndPublishToPeer(
		context.Background(), mh.storage, mh.publisher, mh.ownerSpace,
		pending["connection_id"], "connection.authenticate.response", "conn-auth-resp:"+req.RequestID,
		payload, time.Now().Unix(),
	); err != nil {
		log.Warn().Err(err).Str("request_id", req.RequestID).Msg("auth response publish failed")
	}
	if mh.auditLog != nil {
		mh.auditLog.Append(AuditEntry{
			ConnectionID: pending["connection_id"],
			PeerGUID:     pending["requester_guid"],
			EventType:    AuditTypeConnectionAuthenticated,
			Direction:    AuditDirectionOutbound,
			Title:        "Signed identity proof for peer",
			Refs:         map[string]string{"request_id": req.RequestID},
		})
	}
	mh.mirrorVerifyEvent(EventTypeConnectionVerified, pending["connection_id"], "Signed identity proof for peer", map[string]string{
		"request_id": req.RequestID,
		"direction":  "outbound",
	})
	_ = mh.storage.Delete("pending_verify_in/" + req.RequestID)

	out, _ := json.Marshal(map[string]interface{}{"success": true})
	return mh.successResponse(msg.GetID(), out)
}

// HandleDenyVerify is the receiver-side app op: user explicitly
// refused to prove identity. Emit an explicit denial back so the
// requester sees a clear reason rather than a hang.
func (mh *MessageHandler) HandleDenyVerify(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		RequestID string `json:"request_id"`
		Reason    string `json:"reason,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "DenyVerify"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid deny payload")
	}
	pendingData, err := mh.storage.Get("pending_verify_in/" + req.RequestID)
	if err != nil || len(pendingData) == 0 {
		return mh.errorResponse(msg.GetID(), "pending verify request not found")
	}
	var pending map[string]string
	_ = json.Unmarshal(pendingData, &pending)

	denial := ConnectionAuthResponse{
		RequestID: req.RequestID,
		Status:    "denied_by_user",
	}
	payload, _ := json.Marshal(&denial)
	_ = encryptAndPublishToPeer(
		context.Background(), mh.storage, mh.publisher, mh.ownerSpace,
		pending["connection_id"], "connection.authenticate.response", "conn-auth-resp:"+req.RequestID,
		payload, time.Now().Unix(),
	)
	if mh.auditLog != nil {
		mh.auditLog.Append(AuditEntry{
			ConnectionID: pending["connection_id"],
			PeerGUID:     pending["requester_guid"],
			EventType:    AuditTypeConnectionAuthenticateFailed,
			Direction:    AuditDirectionOutbound,
			Title:        "Refused identity verification",
			Body:         req.Reason,
			Refs:         map[string]string{"request_id": req.RequestID},
		})
	}
	_ = mh.storage.Delete("pending_verify_in/" + req.RequestID)

	out, _ := json.Marshal(map[string]interface{}{"success": true})
	return mh.successResponse(msg.GetID(), out)
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
	if resp.Status == "denied_by_user" {
		mh.auditAuthFailed(dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, "denied_by_user")
		return mh.publishAuthVerdict(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, false, "denied_by_user")
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
	mh.mirrorVerifyEvent(EventTypeConnectionVerified, dec.LocalConnID, "Peer proved their identity", map[string]string{
		"request_id": resp.RequestID,
		"direction":  "inbound",
	})
	return mh.publishAuthVerdict(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp.RequestID, true, "")
}

func (mh *MessageHandler) auditAuthFailed(connID, peerGUID, requestID, reason string) {
	if mh.auditLog != nil {
		mh.auditLog.Append(AuditEntry{
			ConnectionID: connID,
			PeerGUID:     peerGUID,
			EventType:    AuditTypeConnectionAuthenticateFailed,
			Direction:    AuditDirectionInbound,
			Title:        "Authentication failed: " + reason,
			Refs:         map[string]string{"request_id": requestID},
		})
	}
	mh.mirrorVerifyEvent(EventTypeConnectionVerifyDenied, connID, "Authentication failed: "+reason, map[string]string{
		"request_id":     requestID,
		"failure_reason": reason,
	})
}

// mirrorVerifyEvent writes a hidden feed event so the global audit log
// shows verify-identity outcomes. The per-connection AuditLog row is
// still the source of truth for Connection History; the feed-event
// mirror is read-only by Settings → Privacy → Audit Log.
func (mh *MessageHandler) mirrorVerifyEvent(eventType EventType, connectionID, title string, refs map[string]string) {
	if mh.eventHandler == nil {
		return
	}
	meta := map[string]string{}
	for k, v := range refs {
		meta[k] = v
	}
	_ = mh.eventHandler.LogEvent(context.Background(), &Event{
		EventType:  eventType,
		SourceType: "connection",
		SourceID:   connectionID,
		Title:      title,
		Metadata:   meta,
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
