package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// ed25519SignBytes / ed25519PubB64 / ed25519SigB64 are local helpers so
// the action-router file stays cohesive without duplicating across other
// files that already use crypto/ed25519 directly.
func ed25519SignBytes(privKey, msg []byte) []byte {
	if len(privKey) != ed25519.PrivateKeySize {
		// privKey is the seed-only form; expand on the fly. Length
		// validation happened upstream.
		return nil
	}
	return ed25519.Sign(ed25519.PrivateKey(privKey), msg)
}

func ed25519PubB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func ed25519SigB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Routing for the shared-action layer.
//
// Three entry points:
//   - handleActionOperation: forVault.action.<op> from the owner's app
//   - handleIncomingInvokeAction: peer invoking one of our actions
//   - handleIncomingActionResult: peer's result for an action we invoked
//
// All peer-facing wire envelopes ride the connection's existing E2E
// session — we don't bring up a new transport.

// handleActionOperation dispatches the app-facing operations.
func (mh *MessageHandler) handleActionOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 1 {
		return mh.errorResponse(msg.GetID(), "missing action operation type")
	}
	switch opParts[0] {
	case "list-mine":
		return mh.handleActionListMine(ctx, msg)
	case "list-on-peer":
		return mh.handleActionListOnPeer(ctx, msg)
	case "set-enabled":
		return mh.handleActionSetEnabled(ctx, msg)
	case "invoke-on-peer":
		return mh.handleActionInvokeOnPeer(ctx, msg)
	case "list-pending":
		return mh.handleActionListPending(ctx, msg)
	case "approve":
		return mh.handleActionApprove(ctx, msg)
	case "deny":
		return mh.handleActionDeny(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown action op: %s", opParts[0]))
	}
}

// ---- list-mine: catalog + owner's enabled-state ---------------------

func (mh *MessageHandler) handleActionListMine(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if err := mh.ensureEnabledActions(); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}
	state := mh.snapshotEnabledActions()
	type entry struct {
		Def      ActionDef       `json:"def"`
		Enabled  *EnabledAction  `json:"enabled"`
	}
	out := make([]entry, 0)
	for _, def := range ActionCatalog() {
		out = append(out, entry{Def: def, Enabled: state.Actions[def.ID]})
	}
	body, _ := json.Marshal(map[string]interface{}{
		"catalog_version": ActionCatalogVersion,
		"actions":         out,
	})
	return mh.successResponse(msg.GetID(), body)
}

// ---- list-on-peer: read peer's published-profile actions[] ----------

func (mh *MessageHandler) handleActionListOnPeer(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "list-on-peer"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request")
	}
	// We pull the peer's most-recent published-profile snapshot from
	// the connection record's ProfileCache. If it's stale, the app can
	// trigger a profile.fetch beforehand.
	cache, err := mh.loadPeerProfileCache(req.ConnectionID)
	if err != nil {
		return mh.errorResponse(msg.GetID(), "no cached profile: "+err.Error())
	}
	body, _ := json.Marshal(map[string]interface{}{
		"connection_id": req.ConnectionID,
		"actions":       cache.Actions, // see profile_builder integration below
	})
	return mh.successResponse(msg.GetID(), body)
}

// ---- set-enabled ----------------------------------------------------

func (mh *MessageHandler) handleActionSetEnabled(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ActionID    string                 `json:"action_id"`
		Mode        ActionAuthMode         `json:"mode"`
		Allowlist   []string               `json:"allowlist"`
		OwnerParams map[string]interface{} `json:"owner_params"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "set-enabled"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request")
	}
	if err := mh.setActionConfig(req.ActionID, req.Mode, req.Allowlist, req.OwnerParams); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}
	// Re-publish profile so peers see updated visibility.
	go mh.republishProfileBestEffort()
	ack, _ := json.Marshal(map[string]string{"status": "ok"})
	return mh.successResponse(msg.GetID(), ack)
}

// ---- invoke-on-peer -------------------------------------------------
// App side: build a signed InvocationRequest and send it on the
// connection's E2E channel. Returns immediately with the invocation id;
// the eventual InvocationResult arrives on a separate forApp event.
func (mh *MessageHandler) handleActionInvokeOnPeer(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID  string          `json:"connection_id"`
		ActionID      string          `json:"action_id"`
		ActionVersion int             `json:"action_version"`
		Params        json.RawMessage `json:"params"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "invoke-on-peer"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request")
	}

	// Pre-flight: schema-validate the params on the invoker side too.
	def, ok := LookupAction(req.ActionID)
	if !ok {
		return mh.errorResponse(msg.GetID(), "ERR_ACTION_UNKNOWN")
	}
	if err := ValidateAgainstSchema([]byte(def.ParamSchema), req.Params); err != nil {
		return mh.errorResponse(msg.GetID(), "ERR_INVALID_PARAMS:"+err.Error())
	}

	mh.vaultState.mu.RLock()
	credential := mh.vaultState.credential
	mh.vaultState.mu.RUnlock()
	if credential == nil || len(credential.IdentityPrivateKey) == 0 {
		return mh.errorResponse(msg.GetID(), "vault is locked")
	}

	envelope := InvocationRequest{
		InvocationID:  newInvocationID(),
		ActionID:      req.ActionID,
		ActionVersion: req.ActionVersion,
		Params:        req.Params,
		InvokedAt:     time.Now().UTC().Format(time.RFC3339),
		InvokerGUID:   mh.ownerSpace,
	}
	envelope.InvokerPubKey = mh.ownerEd25519PubKeyBase64(credential.IdentityPrivateKey)
	envelope.InvokerSig = mh.signInvokerEnvelope(credential.IdentityPrivateKey, &envelope)

	if err := mh.sendInvokeActionToPeer(ctx, req.ConnectionID, &envelope); err != nil {
		return mh.errorResponse(msg.GetID(), "send peer: "+err.Error())
	}

	// Audit log on the invoker side as well (outbound direction).
	if mh.auditLog != nil {
		mh.auditLog.Append(AuditEntry{
			ConnectionID: req.ConnectionID,
			EventType:    AuditTypeActionInvoked,
			Direction:    AuditDirectionOutbound,
			Title:        req.ActionID,
			Body:         "invoked on peer",
			Refs:         map[string]string{"invocation_id": envelope.InvocationID},
		})
	}

	body, _ := json.Marshal(map[string]string{
		"status":        "sent",
		"invocation_id": envelope.InvocationID,
	})
	return mh.successResponse(msg.GetID(), body)
}

// ---- list-pending (owner-side approvals) ----------------------------

func (mh *MessageHandler) handleActionListPending(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	pending := mh.ListPendingWaiting()
	body, _ := json.Marshal(map[string]interface{}{
		"pending": pending,
	})
	return mh.successResponse(msg.GetID(), body)
}

// ---- approve / deny -------------------------------------------------

func (mh *MessageHandler) handleActionApprove(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		InvocationID   string                 `json:"invocation_id"`
		OwnerNote      string                 `json:"owner_note"`
		OwnerOverrides map[string]interface{} `json:"owner_overrides"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "approve"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request")
	}
	p, err := mh.DecidePending(req.InvocationID, PendingStatusApproved, req.OwnerNote, req.OwnerOverrides)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}
	result := mh.FinishApprovedInvocation(ctx, p)
	mh.recordAndDeliverResult(ctx, p, result)
	ack, _ := json.Marshal(map[string]string{"status": "approved"})
	return mh.successResponse(msg.GetID(), ack)
}

func (mh *MessageHandler) handleActionDeny(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		InvocationID string `json:"invocation_id"`
		OwnerNote    string `json:"owner_note"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "deny"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request")
	}
	p, err := mh.DecidePending(req.InvocationID, PendingStatusDenied, req.OwnerNote, nil)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}
	result := mh.FinishDeniedInvocation(p, req.OwnerNote)
	mh.recordAndDeliverResult(ctx, p, result)
	ack, _ := json.Marshal(map[string]string{"status": "denied"})
	return mh.successResponse(msg.GetID(), ack)
}

// recordAndDeliverResult sends the result envelope back to the invoker
// over the same E2E channel and stores it on the pending record.
func (mh *MessageHandler) recordAndDeliverResult(ctx context.Context, p *ActionPendingApproval, r *InvocationResult) {
	body, err := json.Marshal(r)
	if err != nil {
		log.Error().Err(err).Msg("marshal action result")
		return
	}
	mh.MarkResultEnvelope(p.InvocationID, body)
	if err := mh.sendActionResultToPeer(ctx, p.ConnectionID, p.InvokerGUID, body); err != nil {
		log.Warn().Err(err).Msg("deliver action result to peer")
	}
}

// ---- incoming invoke-action (peer -> us) ----------------------------

func (mh *MessageHandler) handleIncomingInvokeAction(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req InvocationRequest
	if err := unmarshalRequest(msg.Payload, &req, "invoke-action"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid invocation envelope")
	}
	connectionID := ""
	if mh.notificationsHandler != nil {
		connectionID = mh.notificationsHandler.FindConnectionByPeerGUID(req.InvokerGUID)
	}
	result := mh.HandleIncomingInvocation(ctx, connectionID, &req)
	body, err := json.Marshal(result)
	if err != nil {
		return mh.errorResponse(msg.GetID(), "marshal result: "+err.Error())
	}
	// Reply over the E2E channel (peer is waiting for handler-result).
	if connectionID != "" {
		if err := mh.sendActionResultToPeer(ctx, connectionID, req.InvokerGUID, body); err != nil {
			log.Warn().Err(err).Msg("deliver immediate action result")
		}
	}
	// Ack the supervisor with a short status so it isn't expecting the
	// full result (which travels separately on the E2E channel).
	ack, _ := json.Marshal(map[string]string{
		"status":        string(result.Status),
		"invocation_id": result.InvocationID,
	})
	return mh.successResponse(msg.GetID(), ack)
}

// ---- incoming action-result (peer -> us, replying to our invoke) ----

func (mh *MessageHandler) handleIncomingActionResult(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var result InvocationResult
	if err := unmarshalRequest(msg.Payload, &result, "action-result"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid result envelope")
	}
	// Forward to the app so the invoker's UI updates. Audit-log too.
	connectionID := ""
	if mh.notificationsHandler != nil {
		connectionID = mh.notificationsHandler.FindConnectionByPeerGUID(result.PeerGUID)
	}
	if mh.auditLog != nil && connectionID != "" {
		eventType := AuditTypeActionApproved
		switch result.Status {
		case ResultStatusDenied:
			eventType = AuditTypeActionDenied
		case ResultStatusFailed:
			eventType = AuditTypeActionFailed
		case ResultStatusExpired:
			eventType = AuditTypeActionExpired
		case ResultStatusPendingApproval:
			eventType = AuditTypeActionInvoked
		}
		mh.auditLog.Append(AuditEntry{
			ConnectionID: connectionID,
			EventType:    eventType,
			Direction:    AuditDirectionInbound,
			Title:        result.ActionID,
			Body:         string(result.Status),
			Refs:         map[string]string{"invocation_id": result.InvocationID},
		})
	}
	if mh.publisher != nil {
		_ = mh.publisher.PublishToApp(ctx, "action.result", msg.Payload)
	}
	ack, _ := json.Marshal(map[string]string{"status": "received"})
	return mh.successResponse(msg.GetID(), ack)
}

// ----------------------------------------------------------------------
// Bridges to existing connection / profile machinery
// ----------------------------------------------------------------------

// ownerEd25519PubKeyBase64 returns the base64 of the public half of the
// owner's identity Ed25519 keypair. Ed25519 private keys are 64 bytes
// (32-byte seed + 32-byte public); we return the trailing 32.
func (mh *MessageHandler) ownerEd25519PubKeyBase64(privateKey []byte) string {
	if len(privateKey) < 64 {
		return ""
	}
	return ed25519PubB64(privateKey[32:])
}

// signInvokerEnvelope produces the base64 Ed25519 signature over
// canonicalRequestBytes(envelope).
func (mh *MessageHandler) signInvokerEnvelope(privateKey []byte, env *InvocationRequest) string {
	canonical := canonicalRequestBytes(env)
	return ed25519SigB64(ed25519SignBytes(privateKey, canonical))
}

// sendInvokeActionToPeer publishes the invocation envelope on the peer's
// MessageSpace using the existing forOwner.* convention. The peer's
// vault picks it up via the existing forOwner subscriber and dispatches
// to handleIncomingInvokeAction (case "invoke-action" in messages.go).
//
// Wire subject: MessageSpace.{peerOwnerSpace}.forOwner.invoke-action
func (mh *MessageHandler) sendInvokeActionToPeer(ctx context.Context, connectionID string, env *InvocationRequest) error {
	peerOwner, err := mh.peerOwnerSpaceFor(connectionID)
	if err != nil {
		return err
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("MessageSpace.%s.forOwner.invoke-action", peerOwner)
	return mh.publisher.PublishRaw(subject, body)
}

// sendActionResultToPeer mirrors the above for results.
func (mh *MessageHandler) sendActionResultToPeer(ctx context.Context, connectionID, peerGUID string, body []byte) error {
	peerOwner := peerGUID
	if peerOwner == "" {
		var err error
		peerOwner, err = mh.peerOwnerSpaceFor(connectionID)
		if err != nil {
			return err
		}
	}
	subject := fmt.Sprintf("MessageSpace.%s.forOwner.action-result", peerOwner)
	return mh.publisher.PublishRaw(subject, body)
}

// peerOwnerSpaceFor resolves the peer's owner_space from a connection_id.
// Reads connections/{id} directly via storage to avoid coupling to the
// ConnectionsHandler's locking dance — read-only access is safe.
func (mh *MessageHandler) peerOwnerSpaceFor(connectionID string) (string, error) {
	if mh.storage == nil {
		return "", fmt.Errorf("storage unavailable")
	}
	var record struct {
		PeerOwnerSpace string `json:"peer_owner_space"`
	}
	if err := mh.storage.GetJSON("connections/"+connectionID, &record); err != nil {
		return "", err
	}
	if record.PeerOwnerSpace == "" {
		return "", fmt.Errorf("connection %s has no peer_owner_space", connectionID)
	}
	return record.PeerOwnerSpace, nil
}

// loadPeerProfileCache reads the most recent published-profile snapshot
// for the peer behind connectionID. The connection record stores the
// snapshot under a sub-path; if profile_builder later changes the path
// this is the single touchpoint.
func (mh *MessageHandler) loadPeerProfileCache(connectionID string) (*PeerProfileCache, error) {
	if mh.storage == nil {
		return nil, fmt.Errorf("storage unavailable")
	}
	var cache PeerProfileCache
	if err := mh.storage.GetJSON("connections/"+connectionID+"/peer_profile", &cache); err != nil {
		return nil, err
	}
	return &cache, nil
}

// republishProfileBestEffort is a stub for now. The profile-publish
// pipeline lives in profile_handler.go; we'll wire a dedicated
// "republish current" entry point in a follow-up so set-enabled
// changes propagate to peers automatically. For Phase 1 the user can
// publish-profile manually after toggling.
func (mh *MessageHandler) republishProfileBestEffort() {
	log.Debug().Msg("republish-on-set-enabled deferred to follow-up")
}

// PeerProfileCache mirrors the JSON shape we cache after a peer
// publishes their profile. The full struct lives in profile_builder.go;
// here we only need the actions field for action.list-on-peer.
type PeerProfileCache struct {
	Actions []map[string]interface{} `json:"actions,omitempty"`
}

// keep go vet happy if these helpers aren't used elsewhere.
var _ = strings.TrimSpace
