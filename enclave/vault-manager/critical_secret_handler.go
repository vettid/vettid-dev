package main

// Critical-secret "use on my behalf" — plans/data-request-grants.md
// Phase 6. Connections never receive critical-secret material (wallet
// seeds, signing keys, master credentials). Instead they request an
// owner-side OPERATION using one of their critical secrets, and the
// owner performs it locally under password gate, returning only the
// result (signature, decryption plaintext, derived value).
//
// Operations whitelist (locked down to a small surface):
//   - sign:    Ed25519 / Secp256k1 sign of an arbitrary payload
//   - decrypt: decrypt a peer-supplied ciphertext using the secret
//   - derive:  derive a child key / address from a seed
//   - auth:    produce a one-shot signed challenge for authentication
//
// Phase 6 scope: define the wire, the lifecycle (request → owner
// approves → operation runs → result returned), and the audit trail.
// The crypto-operation glue (the actual ed25519.Sign call, the
// password-gated credential decrypt) hooks into the existing
// wallet/signing layer in a follow-on; today's resolver returns a
// stub result so the contract is exercised end-to-end without
// touching credential bytes.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	criticalUseRequestsIndexKey  = "critical_use/_pending_index"
	criticalUseRequestsKeyPrefix = "critical_use/pending/"
	criticalAllowancesIndexKey   = "critical_use/_allowance_index"
	criticalAllowancesKeyPrefix  = "critical_use/allowances/"

	// CriticalUseOp* — the whitelist. Adding an op here requires a
	// matching case in performCriticalOperation AND a unit test.
	CriticalUseOpSign    = "sign"
	CriticalUseOpDecrypt = "decrypt"
	CriticalUseOpDerive  = "derive"
	CriticalUseOpAuth    = "auth"

	CriticalAllowanceStatusActive  = "active"
	CriticalAllowanceStatusUsed    = "used"
	CriticalAllowanceStatusRevoked = "revoked"
)

// CriticalSecretUseRequest is the wire payload from requester → owner.
// Operation is one of the CriticalUseOp* constants; Payload carries
// the operation input (bytes to sign / ciphertext to decrypt / derivation
// path / challenge). Context is a free-form string the requester
// supplies so the owner can decide informed ("for transaction
// 0x123..."); UI surfaces it in the approval prompt.
type CriticalSecretUseRequest struct {
	RequestID string `json:"request_id"`
	ItemRef   string `json:"item_ref"`   // critical-secret ID
	ItemLabel string `json:"item_label"` // user-facing label captured at request time
	Operation string `json:"operation"`
	Payload   string `json:"payload"`    // base64 or hex per op
	Context   string `json:"context,omitempty"`
}

// CriticalSecretUseResponse carries the operation result or denial.
// Status is one of "ok", "denied", "error". Result encoding mirrors
// Payload's encoding per operation (e.g. base64 signature for sign).
type CriticalSecretUseResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Result    string `json:"result,omitempty"`
	Error     string `json:"error,omitempty"`
}

// CriticalSecretAllowance is the owner-side record of "I let peer X
// use secret Y for op Z up to N times within window T". Differs from
// GrantRecord in that there's no fetchable value — only a use counter
// + window. Allow-once approvals don't create an allowance; they
// perform once and audit. Renewable approvals (Allow-for-window in
// the UI) do create one.
type CriticalSecretAllowance struct {
	AllowanceID    string `json:"allowance_id"`
	OwnerGUID      string `json:"owner_guid"`
	RequesterGUID  string `json:"requester_guid"`
	ConnectionID   string `json:"connection_id"`
	ItemRef        string `json:"item_ref"`
	ItemLabel      string `json:"item_label"`
	Operation      string `json:"operation"`
	ExpiresAt      int64  `json:"expires_at"`
	MaxUses        int    `json:"max_uses"`
	UsesSoFar      int    `json:"uses_so_far"`
	Status         string `json:"status"`
	CreatedAt      int64  `json:"created_at"`
	LastUsedAt     int64  `json:"last_used_at,omitempty"`
	RevokedAt      int64  `json:"revoked_at,omitempty"`
}

// PendingCriticalUseRequest mirrors an incoming use-request awaiting
// the owner's decision. Stored under critical_use/pending/<request_id>.
type PendingCriticalUseRequest struct {
	RequestID     string `json:"request_id"`
	RequesterGUID string `json:"requester_guid"`
	ConnectionID  string `json:"connection_id"`
	ItemRef       string `json:"item_ref"`
	ItemLabel     string `json:"item_label"`
	Operation     string `json:"operation"`
	Payload       string `json:"payload"`
	Context       string `json:"context,omitempty"`
	ReceivedAt    int64  `json:"received_at"`
}

// CriticalSecretHandler owns the lifecycle for use-on-my-behalf
// operations. Operates side-by-side with GrantHandler but tracks a
// disjoint set of records — the two flows never read each other's
// state.
type CriticalSecretHandler struct {
	ownerSpace   string
	storage      *EncryptedStorage
	publisher    *VsockPublisher
	auditLog     *AuditLog
	eventHandler *EventHandler

	// credSecretHandler exposes decryptCredentialBlob +
	// verifyPasswordAgainstCredential. We don't take an interface
	// because the underlying password-gate semantics are shared with
	// HandleGet — pivoting to a separate impl would duplicate a
	// load-bearing security check.
	credSecretHandler *CredentialSecretHandler

	// performer override for tests. Production sets this to nil and the
	// handler does the credential decrypt + sign inline.
	performer CriticalOperationPerformer

	mu sync.Mutex
}

// CriticalOperationPerformer is the seam between this handler and the
// real signing/decryption layer. Implementations must:
//   - Validate the operation is permitted for the named secret
//     (e.g. "sign" only against an Ed25519 / Secp256k1 keyed secret).
//   - Pull the secret material from the vault under password gate.
//   - Run the operation and return the result bytes encoded the same
//     way the request payload was encoded.
type CriticalOperationPerformer interface {
	Perform(ctx context.Context, secretRef, operation, payload string) (result string, err error)
}

func NewCriticalSecretHandler(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher) *CriticalSecretHandler {
	return &CriticalSecretHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
		publisher:  publisher,
	}
}

func (h *CriticalSecretHandler) SetAuditLog(a *AuditLog) { h.auditLog = a }
func (h *CriticalSecretHandler) SetEventHandler(e *EventHandler) { h.eventHandler = e }
func (h *CriticalSecretHandler) SetPerformer(p CriticalOperationPerformer) { h.performer = p }
func (h *CriticalSecretHandler) SetCredentialSecretHandler(c *CredentialSecretHandler) {
	h.credSecretHandler = c
}

// mirrorCriticalSecretUseEvent writes a hidden feed event so global
// Settings → Privacy → Audit Log shows critical-secret usage. The
// per-connection auditLog row remains authoritative for Connection
// History; this is a one-way index mirror, never read back.
func (h *CriticalSecretHandler) mirrorCriticalSecretUseEvent(eventType EventType, connectionID, title, body string, refs map[string]string) {
	if h.eventHandler == nil {
		return
	}
	meta := map[string]string{}
	for k, v := range refs {
		meta[k] = v
	}
	if body != "" {
		meta["context"] = body
	}
	_ = h.eventHandler.LogEvent(context.Background(), &Event{
		EventType:  eventType,
		SourceType: "connection",
		SourceID:   connectionID,
		Title:      title,
		Metadata:   meta,
	})
}

// HandleRequestUse is the receiver-side app op that publishes a
// forVault.critical_secret.use request to the owner.
func (h *CriticalSecretHandler) HandleRequestUse(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
		ItemRef      string `json:"item_ref"`
		ItemLabel    string `json:"item_label"`
		Operation    string `json:"operation"`
		Payload      string `json:"payload"`
		Context      string `json:"context,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "CriticalUseRequest"); err != nil {
		return errorMsg(msg.GetID(), "invalid use-request payload"), nil
	}
	if !isWhitelistedCriticalOp(req.Operation) {
		return errorMsg(msg.GetID(), "operation not whitelisted: "+req.Operation), nil
	}
	if req.ConnectionID == "" || req.ItemRef == "" {
		return errorMsg(msg.GetID(), "connection_id + item_ref required"), nil
	}
	wire := CriticalSecretUseRequest{
		RequestID: newID("cuse-"),
		ItemRef:   req.ItemRef,
		ItemLabel: req.ItemLabel,
		Operation: req.Operation,
		Payload:   req.Payload,
		Context:   req.Context,
	}
	payload, _ := json.Marshal(&wire)
	if err := encryptAndPublishToPeer(
		context.Background(), h.storage, h.publisher, h.ownerSpace,
		req.ConnectionID, "critical_secret.use", "cuse:"+wire.RequestID, payload, time.Now().Unix(),
	); err != nil {
		return errorMsg(msg.GetID(), "publish use-request: "+err.Error()), nil
	}
	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: req.ConnectionID,
			EventType:    AuditTypeCriticalSecretUseRequested,
			Direction:    AuditDirectionOutbound,
			Title:        fmt.Sprintf("Asked owner to %s using %s", req.Operation, safeLabel(req.ItemLabel, req.ItemRef)),
			Body:         req.Context,
			Refs: map[string]string{
				"request_id": wire.RequestID,
				"operation":  req.Operation,
				"item_ref":   req.ItemRef,
			},
		})
	}
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":    true,
		"request_id": wire.RequestID,
	})
	return successMsg(msg.GetID(), respBytes), nil
}

// HandleIncomingUseRequest is the owner-side handler for an incoming
// peer's critical_secret.use. Records as pending + forwards to the app
// for approval.
func (h *CriticalSecretHandler) HandleIncomingUseRequest(ctx context.Context, dec *decryptedPeerEnvelope) error {
	if dec == nil {
		return fmt.Errorf("nil envelope")
	}
	var req CriticalSecretUseRequest
	if err := json.Unmarshal(dec.InnerPayload, &req); err != nil {
		return fmt.Errorf("invalid use-request: %w", err)
	}
	if req.RequestID == "" || req.ItemRef == "" || !isWhitelistedCriticalOp(req.Operation) {
		return fmt.Errorf("malformed use-request")
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	pending := PendingCriticalUseRequest{
		RequestID:     req.RequestID,
		RequesterGUID: dec.FromOwnerSpace,
		ConnectionID:  dec.LocalConnID,
		ItemRef:       req.ItemRef,
		ItemLabel:     req.ItemLabel,
		Operation:     req.Operation,
		Payload:       req.Payload,
		Context:       req.Context,
		ReceivedAt:    time.Now().Unix(),
	}
	data, _ := json.Marshal(&pending)
	if err := h.storage.Put(criticalUseRequestsKeyPrefix+pending.RequestID, data); err != nil {
		return err
	}
	_ = h.appendToIndex(criticalUseRequestsIndexKey, pending.RequestID)

	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: dec.LocalConnID,
			PeerGUID:     dec.FromOwnerSpace,
			EventType:    AuditTypeCriticalSecretUseRequested,
			Direction:    AuditDirectionInbound,
			Title:        fmt.Sprintf("Asked you to %s using %s", req.Operation, safeLabel(req.ItemLabel, req.ItemRef)),
			Body:         req.Context,
			Refs: map[string]string{
				"request_id": req.RequestID,
				"operation":  req.Operation,
				"item_ref":   req.ItemRef,
			},
		})
	}
	if h.publisher != nil {
		appPayload, _ := json.Marshal(map[string]interface{}{
			"connection_id":  dec.LocalConnID,
			"requester_guid": dec.FromOwnerSpace,
			"request_id":     req.RequestID,
			"item_ref":       req.ItemRef,
			"item_label":     req.ItemLabel,
			"operation":      req.Operation,
			"context":        req.Context,
		})
		_ = h.publisher.PublishToApp(ctx, "connection.critical-secret-use-requested", appPayload)
	}
	return nil
}

// HandleApproveUse runs the operation under password gate and ships
// the result back. The password gate decrypts the credential blob,
// verifies the password hash matches Auth, then finds the named
// critical secret and performs the operation locally. Every approve
// requires fresh password — there is intentionally no TTL session
// for critical-secret ops (plans/data-request-grants.md Phase 6).
func (h *CriticalSecretHandler) HandleApproveUse(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		RequestID             string `json:"request_id"`
		EncryptedCredential   string `json:"encrypted_credential"`
		EncryptedPasswordHash string `json:"encrypted_password_hash"`
		EphemeralPublicKey    string `json:"ephemeral_public_key"`
		Nonce                 string `json:"nonce"`
		KeyID                 string `json:"key_id"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "CriticalUseApprove"); err != nil {
		return errorMsg(msg.GetID(), "invalid approve payload"), nil
	}
	// Password gate required for production paths. Tests inject a
	// performer (h.performer != nil) and skip the password fields —
	// the performer bypass is the test-only seam.
	if h.performer == nil && (req.EncryptedCredential == "" || req.EncryptedPasswordHash == "" || req.KeyID == "") {
		return errorMsg(msg.GetID(), "password authorization required: encrypted_credential + encrypted_password_hash + key_id"), nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	data, err := h.storage.Get(criticalUseRequestsKeyPrefix + req.RequestID)
	if err != nil {
		return errorMsg(msg.GetID(), "pending use-request not found"), nil
	}
	var pending PendingCriticalUseRequest
	if err := json.Unmarshal(data, &pending); err != nil {
		return errorMsg(msg.GetID(), "corrupt pending record"), nil
	}

	var result string
	var perfErr error
	if h.performer != nil {
		// Test-only override path.
		result, perfErr = h.performer.Perform(context.Background(), pending.ItemRef, pending.Operation, pending.Payload)
	} else if h.credSecretHandler == nil {
		perfErr = fmt.Errorf("credential-secret handler not wired; operation cannot proceed")
	} else {
		result, perfErr = h.performInline(req.EncryptedCredential, req.EncryptedPasswordHash, req.EphemeralPublicKey, req.Nonce, req.KeyID, &pending)
	}

	resp := CriticalSecretUseResponse{RequestID: pending.RequestID}
	if perfErr != nil {
		resp.Status = "error"
		resp.Error = perfErr.Error()
	} else {
		resp.Status = "ok"
		resp.Result = result
	}
	respBytes, _ := json.Marshal(&resp)
	if err := encryptAndPublishToPeer(
		context.Background(), h.storage, h.publisher, h.ownerSpace,
		pending.ConnectionID, "critical_secret.use-response", "cuse-resp:"+pending.RequestID, respBytes, time.Now().Unix(),
	); err != nil {
		log.Warn().Err(err).Str("request_id", pending.RequestID).Msg("critical-secret use-response publish failed")
	}

	evt := AuditTypeCriticalSecretUsed
	title := fmt.Sprintf("Performed %s using %s", pending.Operation, safeLabel(pending.ItemLabel, pending.ItemRef))
	if perfErr != nil {
		evt = AuditTypeCriticalSecretUseDenied
		title = fmt.Sprintf("Failed to %s using %s: %v", pending.Operation, safeLabel(pending.ItemLabel, pending.ItemRef), perfErr)
	}
	refs := map[string]string{
		"request_id": pending.RequestID,
		"operation":  pending.Operation,
		"item_ref":   pending.ItemRef,
	}
	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: pending.ConnectionID,
			PeerGUID:     pending.RequesterGUID,
			EventType:    evt,
			Direction:    AuditDirectionOutbound,
			Title:        title,
			Body:         pending.Context,
			Refs:         refs,
		})
	}
	h.mirrorCriticalSecretUseEvent(EventTypeCriticalSecretUsed, pending.ConnectionID, title, pending.Context, refs)

	_ = h.removeFromIndex(criticalUseRequestsIndexKey, pending.RequestID)
	_ = h.storage.Delete(criticalUseRequestsKeyPrefix + pending.RequestID)

	out, _ := json.Marshal(map[string]interface{}{
		"success": perfErr == nil,
		"status":  resp.Status,
		"error":   resp.Error,
	})
	return successMsg(msg.GetID(), out), nil
}

// HandleDenyUse rejects an incoming use-request.
func (h *CriticalSecretHandler) HandleDenyUse(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		RequestID string `json:"request_id"`
		Reason    string `json:"reason,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "CriticalUseDeny"); err != nil {
		return errorMsg(msg.GetID(), "invalid deny payload"), nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	data, err := h.storage.Get(criticalUseRequestsKeyPrefix + req.RequestID)
	if err != nil {
		return errorMsg(msg.GetID(), "pending use-request not found"), nil
	}
	var pending PendingCriticalUseRequest
	_ = json.Unmarshal(data, &pending)

	resp := CriticalSecretUseResponse{
		RequestID: req.RequestID,
		Status:    "denied",
		Error:     req.Reason,
	}
	respBytes, _ := json.Marshal(&resp)
	if err := encryptAndPublishToPeer(
		context.Background(), h.storage, h.publisher, h.ownerSpace,
		pending.ConnectionID, "critical_secret.use-response", "cuse-resp:"+req.RequestID, respBytes, time.Now().Unix(),
	); err != nil {
		log.Warn().Err(err).Msg("critical-secret deny publish failed")
	}

	denyTitle := fmt.Sprintf("Denied %s using %s", pending.Operation, safeLabel(pending.ItemLabel, pending.ItemRef))
	denyRefs := map[string]string{"request_id": req.RequestID, "operation": pending.Operation}
	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: pending.ConnectionID,
			PeerGUID:     pending.RequesterGUID,
			EventType:    AuditTypeCriticalSecretUseDenied,
			Direction:    AuditDirectionOutbound,
			Title:        denyTitle,
			Body:         req.Reason,
			Refs:         denyRefs,
		})
	}
	h.mirrorCriticalSecretUseEvent(EventTypeCriticalSecretUsed, pending.ConnectionID, denyTitle, req.Reason, denyRefs)
	_ = h.removeFromIndex(criticalUseRequestsIndexKey, req.RequestID)
	_ = h.storage.Delete(criticalUseRequestsKeyPrefix + req.RequestID)

	out, _ := json.Marshal(map[string]interface{}{"success": true})
	return successMsg(msg.GetID(), out), nil
}

// HandleIncomingUseResponse forwards the result (or denial) to the
// receiver's app so the requester can render it. The result string
// crosses one app boundary and is not persisted.
func (h *CriticalSecretHandler) HandleIncomingUseResponse(ctx context.Context, dec *decryptedPeerEnvelope) error {
	if dec == nil {
		return fmt.Errorf("nil envelope")
	}
	var resp CriticalSecretUseResponse
	if err := json.Unmarshal(dec.InnerPayload, &resp); err != nil {
		return fmt.Errorf("invalid use-response: %w", err)
	}
	if h.publisher != nil {
		appPayload, _ := json.Marshal(map[string]interface{}{
			"connection_id": dec.LocalConnID,
			"granter_guid":  dec.FromOwnerSpace,
			"request_id":    resp.RequestID,
			"status":        resp.Status,
			"result":        resp.Result,
			"error":         resp.Error,
		})
		_ = h.publisher.PublishToApp(ctx, "connection.critical-secret-use-response", appPayload)
	}
	respTitle := "Operation completed"
	respEvt := AuditTypeCriticalSecretUsed
	if resp.Status != "ok" {
		respTitle = "Operation refused"
		respEvt = AuditTypeCriticalSecretUseDenied
	}
	respRefs := map[string]string{"request_id": resp.RequestID}
	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: dec.LocalConnID,
			PeerGUID:     dec.FromOwnerSpace,
			EventType:    respEvt,
			Direction:    AuditDirectionInbound,
			Title:        respTitle,
			Body:         resp.Error,
			Refs:         respRefs,
		})
	}
	h.mirrorCriticalSecretUseEvent(EventTypeCriticalSecretUsed, dec.LocalConnID, respTitle, resp.Error, respRefs)
	return nil
}

func (h *CriticalSecretHandler) appendToIndex(key, id string) error {
	var ids []string
	if data, err := h.storage.Get(key); err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &ids)
	}
	for _, x := range ids {
		if x == id {
			return nil
		}
	}
	ids = append(ids, id)
	encoded, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return h.storage.Put(key, encoded)
}

func (h *CriticalSecretHandler) removeFromIndex(key, id string) error {
	data, err := h.storage.Get(key)
	if err != nil || len(data) == 0 {
		return nil
	}
	var ids []string
	if json.Unmarshal(data, &ids) != nil {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, x := range ids {
		if x != id {
			out = append(out, x)
		}
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return h.storage.Put(key, encoded)
}

// performInline decrypts the credential blob, verifies the password,
// finds the named critical secret, and runs the requested op.
// Phase 6 MVP supports `sign` and `auth` (Ed25519 over the payload /
// domain-separated challenge); `decrypt` and `derive` return a clear
// "not yet implemented" — each needs a per-secret-format binding that
// isn't wired here.
//
// Result encoding: base64 — the caller's wire payload is also base64.
func (h *CriticalSecretHandler) performInline(
	encryptedCred, encPwdHash, ephPub, nonce, keyID string,
	pending *PendingCriticalUseRequest,
) (string, error) {
	cred, err := h.credSecretHandler.decryptCredentialBlob(encryptedCred)
	if err != nil {
		return "", fmt.Errorf("decrypt credential: %w", err)
	}
	defer cred.SecureErase()

	if err := h.credSecretHandler.verifyPasswordAgainstCredential(encPwdHash, ephPub, nonce, keyID, cred); err != nil {
		return "", fmt.Errorf("password verification failed: %w", err)
	}

	// Find the named critical secret in cred.Secrets[].
	var secret *CredentialSecretEntry
	for i := range cred.Secrets {
		if cred.Secrets[i].ID == pending.ItemRef {
			secret = &cred.Secrets[i]
			break
		}
	}
	if secret == nil {
		return "", fmt.Errorf("critical secret %s not found in credential", pending.ItemRef)
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(pending.Payload)
	if err != nil {
		return "", fmt.Errorf("invalid base64 payload: %w", err)
	}

	switch pending.Operation {
	case CriticalUseOpSign:
		// Expect secret.Value to be an Ed25519 private key (32 or 64
		// bytes). Sign payload bytes directly — caller is responsible
		// for any domain separation in the payload itself.
		if len(secret.Value) != ed25519.PrivateKeySize && len(secret.Value) != ed25519.SeedSize {
			return "", fmt.Errorf("secret format not suitable for ed25519 sign (got %d bytes)", len(secret.Value))
		}
		priv := secret.Value
		if len(priv) == ed25519.SeedSize {
			priv = ed25519.NewKeyFromSeed(priv)
		}
		sig := ed25519.Sign(priv, payloadBytes)
		return base64.StdEncoding.EncodeToString(sig), nil

	case CriticalUseOpAuth:
		// Domain-separated auth challenge sign — same primitive, but
		// the payload is prefixed with "vettid-critical-auth-v1|<owner>|"
		// to prevent reuse against `sign`. The caller supplies the
		// challenge bytes only; we add the prefix here so neither side
		// can be confused about what's being signed.
		if len(secret.Value) != ed25519.PrivateKeySize && len(secret.Value) != ed25519.SeedSize {
			return "", fmt.Errorf("secret format not suitable for ed25519 auth (got %d bytes)", len(secret.Value))
		}
		priv := secret.Value
		if len(priv) == ed25519.SeedSize {
			priv = ed25519.NewKeyFromSeed(priv)
		}
		prefix := []byte(fmt.Sprintf("vettid-critical-auth-v1|%s|", h.ownerSpace))
		full := append([]byte{}, prefix...)
		full = append(full, payloadBytes...)
		sig := ed25519.Sign(priv, full)
		return base64.StdEncoding.EncodeToString(sig), nil

	case CriticalUseOpDecrypt:
		return "", fmt.Errorf("decrypt not yet implemented in Phase 6 MVP")
	case CriticalUseOpDerive:
		return "", fmt.Errorf("derive not yet implemented in Phase 6 MVP")
	}
	return "", fmt.Errorf("unknown operation: %s", pending.Operation)
}

func isWhitelistedCriticalOp(op string) bool {
	switch strings.ToLower(op) {
	case CriticalUseOpSign, CriticalUseOpDecrypt, CriticalUseOpDerive, CriticalUseOpAuth:
		return true
	}
	return false
}
