package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

// Wire types for the shared-action invocation protocol. These match
// what the app sends and what peers exchange on
// `connection.invoke-action` / `connection.action-result`.

type InvocationRequest struct {
	InvocationID   string          `json:"invocation_id"`
	ActionID       string          `json:"action_id"`
	ActionVersion  int             `json:"action_version"`
	Params         json.RawMessage `json:"params"`
	InvokedAt      string          `json:"invoked_at"`
	InvokerSig     string          `json:"invoker_sig"`     // base64 Ed25519
	InvokerPubKey  string          `json:"invoker_pubkey"`  // base64 Ed25519
	InvokerGUID    string          `json:"invoker_guid"`
}

type InvocationResultStatus string

const (
	ResultStatusOK              InvocationResultStatus = "ok"
	ResultStatusDenied          InvocationResultStatus = "denied"
	ResultStatusFailed          InvocationResultStatus = "failed"
	ResultStatusPendingApproval InvocationResultStatus = "pending_approval"
	ResultStatusExpired         InvocationResultStatus = "expired"
)

type InvocationResult struct {
	InvocationID string                 `json:"invocation_id"`
	ActionID     string                 `json:"action_id"`
	Status       InvocationResultStatus `json:"status"`
	Result       json.RawMessage        `json:"result,omitempty"`
	Error        string                 `json:"error,omitempty"`
	DecidedAt    string                 `json:"decided_at"`
	PeerGUID     string                 `json:"peer_guid"`
	// PeerSig: Ed25519 over canonical(invocation_id|action_id|status|result|error|decided_at|peer_guid)
	PeerSig string `json:"peer_sig"`
}

// canonicalRequestBytes builds the bytes the invoker signs and the
// receiver re-verifies. Format is stable across versions:
//
//   invocation_id | action_id | action_version | invoker_guid |
//   sha256-hex(params) | invoked_at
//
// (We hash params instead of inlining so canonical bytes stay short.)
func canonicalRequestBytes(req *InvocationRequest) []byte {
	paramsHash := sha256HexBytes(req.Params)
	canonical := fmt.Sprintf(
		"%s|%s|%d|%s|%s|%s",
		req.InvocationID, req.ActionID, req.ActionVersion,
		req.InvokerGUID, paramsHash, req.InvokedAt,
	)
	return []byte(canonical)
}

func canonicalResultBytes(r *InvocationResult) []byte {
	resultHash := sha256HexBytes(r.Result)
	canonical := fmt.Sprintf(
		"%s|%s|%s|%s|%s|%s|%s",
		r.InvocationID, r.ActionID, string(r.Status),
		resultHash, r.Error, r.DecidedAt, r.PeerGUID,
	)
	return []byte(canonical)
}

func sha256HexBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hashHex(string(b))
}

// ----------------------------------------------------------------------
// Auth engine — the 9-step pipeline from the plan
// ----------------------------------------------------------------------

// HandleIncomingInvocation is the entry point called by action_router.go
// when a `connection.invoke-action` message arrives on a connection's
// E2E channel. Returns the wire-ready InvocationResult to send back on
// `connection.action-result`.
//
// The 9 steps (see plans/shareable-handlers.md):
//   1. Resolve action in catalog
//   2. Version check
//   3. Check enablement (cache load if needed)
//   4. Verify Ed25519 invoker signature — AUDIT LOG sig_ok or sig_failed
//   5. Auth-mode dispatch (default-deny, allowlist, prompt-each-time, default-allow)
//   6. Validate params against the action's JSON schema
//   7. Execute the action
//   8. Sign and shape the result
//   9. Audit-log the outcome
func (mh *MessageHandler) HandleIncomingInvocation(ctx context.Context, connectionID string, req *InvocationRequest) *InvocationResult {
	now := time.Now().UTC().Format(time.RFC3339)

	// Step 1: catalog lookup
	def, ok := LookupAction(req.ActionID)
	if !ok {
		mh.logActionAudit(connectionID, req.InvokerGUID, AuditTypeActionFailed, req.InvocationID, req.ActionID, "unknown action")
		return mh.signResult(&InvocationResult{
			InvocationID: req.InvocationID, ActionID: req.ActionID,
			Status: ResultStatusFailed, Error: "ERR_ACTION_UNKNOWN", DecidedAt: now,
		})
	}

	// Step 2: version check (hard cutover)
	if req.ActionVersion != def.Version {
		mh.logActionAudit(connectionID, req.InvokerGUID, AuditTypeActionFailed, req.InvocationID, req.ActionID,
			fmt.Sprintf("version mismatch: want %d got %d", def.Version, req.ActionVersion))
		return mh.signResult(&InvocationResult{
			InvocationID: req.InvocationID, ActionID: req.ActionID,
			Status: ResultStatusFailed, Error: fmt.Sprintf("ERR_ACTION_VERSION:current=%d", def.Version),
			DecidedAt: now,
		})
	}

	// Step 3 + 5 (enablement + auth-mode dispatch) — the resolver folds
	// these together because DefaultDeny is rejection unless allowlisted.
	def, ea, err := mh.resolveActionForInvoke(req.ActionID, req.InvokerGUID)
	if err != nil {
		errStr := err.Error()
		mh.logActionAudit(connectionID, req.InvokerGUID, AuditTypeActionDenied, req.InvocationID, req.ActionID, errStr)
		return mh.signResult(&InvocationResult{
			InvocationID: req.InvocationID, ActionID: req.ActionID,
			Status: ResultStatusDenied, Error: errStr, DecidedAt: now,
		})
	}

	// Step 4: identity-key signature verify. ALWAYS audit-logged — pass
	// or fail — so a forged-sig attempt is itself a permanent record.
	if err := verifyInvokerSignature(req); err != nil {
		mh.logActionAudit(connectionID, req.InvokerGUID, AuditTypeActionInvocationSigFailed, req.InvocationID, req.ActionID, err.Error())
		return mh.signResult(&InvocationResult{
			InvocationID: req.InvocationID, ActionID: req.ActionID,
			Status: ResultStatusFailed, Error: "ERR_INVOKER_SIG", DecidedAt: now,
		})
	}
	mh.logActionAudit(connectionID, req.InvokerGUID, AuditTypeActionInvocationSigOK, req.InvocationID, req.ActionID, "")

	// Step 6: schema-validate the params
	if err := ValidateAgainstSchema([]byte(def.ParamSchema), req.Params); err != nil {
		mh.logActionAudit(connectionID, req.InvokerGUID, AuditTypeActionFailed, req.InvocationID, req.ActionID, err.Error())
		return mh.signResult(&InvocationResult{
			InvocationID: req.InvocationID, ActionID: req.ActionID,
			Status: ResultStatusFailed, Error: "ERR_INVALID_PARAMS:" + err.Error(), DecidedAt: now,
		})
	}

	// Step 5b: prompt-each-time → enqueue and return pending_approval
	if ea.Mode == ActionAuthPromptEachTime {
		canonical := canonicalRequestBytes(req)
		p := &ActionPendingApproval{
			InvocationID:   req.InvocationID,
			ActionID:       req.ActionID,
			ActionVersion:  req.ActionVersion,
			InvokerGUID:    req.InvokerGUID,
			InvokerPubKey:  req.InvokerPubKey,
			ConnectionID:   connectionID,
			Params:         req.Params,
			InvokedAt:      req.InvokedAt,
			InvokerSig:     req.InvokerSig,
			CanonicalBytes: base64.StdEncoding.EncodeToString(canonical),
			Status:         PendingStatusWaiting,
		}
		if err := mh.EnqueuePending(p); err != nil {
			mh.logActionAudit(connectionID, req.InvokerGUID, AuditTypeActionFailed, req.InvocationID, req.ActionID, "enqueue: "+err.Error())
			return mh.signResult(&InvocationResult{
				InvocationID: req.InvocationID, ActionID: req.ActionID,
				Status: ResultStatusFailed, Error: "ERR_ENQUEUE", DecidedAt: now,
			})
		}
		mh.logActionAudit(connectionID, req.InvokerGUID, AuditTypeActionInvoked, req.InvocationID, req.ActionID, "pending owner approval")
		// Push the owner-side notification (best-effort).
		mh.notifyOwnerOfPendingAction(p, def)
		return mh.signResult(&InvocationResult{
			InvocationID: req.InvocationID, ActionID: req.ActionID,
			Status: ResultStatusPendingApproval, DecidedAt: now,
		})
	}

	// Auto-execute (default-allow or allowlisted)
	mh.logActionAudit(connectionID, req.InvokerGUID, AuditTypeActionInvoked, req.InvocationID, req.ActionID, "auto-execute")
	resultJSON, execErr := mh.executeAction(ctx, def, req.InvokerGUID, connectionID, req.Params, nil)
	if execErr != nil {
		mh.logActionAudit(connectionID, req.InvokerGUID, AuditTypeActionFailed, req.InvocationID, req.ActionID, execErr.Error())
		return mh.signResult(&InvocationResult{
			InvocationID: req.InvocationID, ActionID: req.ActionID,
			Status: ResultStatusFailed, Error: execErr.Error(), DecidedAt: now,
		})
	}
	if err := ValidateAgainstSchema([]byte(def.ResultSchema), resultJSON); err != nil {
		log.Warn().Err(err).Str("action_id", def.ID).Msg("executor produced invalid result — rejecting")
		mh.logActionAudit(connectionID, req.InvokerGUID, AuditTypeActionFailed, req.InvocationID, req.ActionID, "result schema: "+err.Error())
		return mh.signResult(&InvocationResult{
			InvocationID: req.InvocationID, ActionID: req.ActionID,
			Status: ResultStatusFailed, Error: "ERR_RESULT_SCHEMA", DecidedAt: now,
		})
	}
	mh.logActionAudit(connectionID, req.InvokerGUID, AuditTypeActionApproved, req.InvocationID, req.ActionID, "")
	return mh.signResult(&InvocationResult{
		InvocationID: req.InvocationID, ActionID: req.ActionID,
		Status: ResultStatusOK, Result: resultJSON, DecidedAt: now,
	})
}

// FinishApprovedInvocation runs an executor for a previously-pending
// invocation that the owner has just approved. Returns the result
// envelope ready to send on connection.action-result.
func (mh *MessageHandler) FinishApprovedInvocation(ctx context.Context, p *ActionPendingApproval) *InvocationResult {
	now := time.Now().UTC().Format(time.RFC3339)
	def, ok := LookupAction(p.ActionID)
	if !ok {
		return mh.signResult(&InvocationResult{
			InvocationID: p.InvocationID, ActionID: p.ActionID,
			Status: ResultStatusFailed, Error: "ERR_ACTION_UNKNOWN", DecidedAt: now,
		})
	}
	resultJSON, err := mh.executeAction(ctx, def, p.InvokerGUID, p.ConnectionID, p.Params, p.OwnerOverrides)
	if err != nil {
		mh.logActionAudit(p.ConnectionID, p.InvokerGUID, AuditTypeActionFailed, p.InvocationID, p.ActionID, err.Error())
		return mh.signResult(&InvocationResult{
			InvocationID: p.InvocationID, ActionID: p.ActionID,
			Status: ResultStatusFailed, Error: err.Error(), DecidedAt: now,
		})
	}
	if err := ValidateAgainstSchema([]byte(def.ResultSchema), resultJSON); err != nil {
		mh.logActionAudit(p.ConnectionID, p.InvokerGUID, AuditTypeActionFailed, p.InvocationID, p.ActionID, "result schema: "+err.Error())
		return mh.signResult(&InvocationResult{
			InvocationID: p.InvocationID, ActionID: p.ActionID,
			Status: ResultStatusFailed, Error: "ERR_RESULT_SCHEMA", DecidedAt: now,
		})
	}
	mh.logActionAudit(p.ConnectionID, p.InvokerGUID, AuditTypeActionApproved, p.InvocationID, p.ActionID, "owner approved")
	return mh.signResult(&InvocationResult{
		InvocationID: p.InvocationID, ActionID: p.ActionID,
		Status: ResultStatusOK, Result: resultJSON, DecidedAt: now,
	})
}

// FinishDeniedInvocation packages a denied result envelope. ownerNote is
// optional and shown to the invoker.
func (mh *MessageHandler) FinishDeniedInvocation(p *ActionPendingApproval, ownerNote string) *InvocationResult {
	now := time.Now().UTC().Format(time.RFC3339)
	mh.logActionAudit(p.ConnectionID, p.InvokerGUID, AuditTypeActionDenied, p.InvocationID, p.ActionID, ownerNote)
	errMsg := "ERR_OWNER_DENIED"
	if ownerNote != "" {
		errMsg = errMsg + ":" + ownerNote
	}
	return mh.signResult(&InvocationResult{
		InvocationID: p.InvocationID, ActionID: p.ActionID,
		Status: ResultStatusDenied, Error: errMsg, DecidedAt: now,
	})
}

// ----------------------------------------------------------------------
// Signature verification + result signing
// ----------------------------------------------------------------------

func verifyInvokerSignature(req *InvocationRequest) error {
	pubKey, err := base64.StdEncoding.DecodeString(req.InvokerPubKey)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid invoker_pubkey")
	}
	sig, err := base64.StdEncoding.DecodeString(req.InvokerSig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid invoker_sig")
	}
	canonical := canonicalRequestBytes(req)
	if !ed25519.Verify(pubKey, canonical, sig) {
		return fmt.Errorf("ed25519 verify failed")
	}
	return nil
}

// signResult attaches the owner's identity-key signature to the result
// envelope so the invoker has non-repudiable proof of the decision.
func (mh *MessageHandler) signResult(r *InvocationResult) *InvocationResult {
	r.PeerGUID = mh.ownerSpace
	canonical := canonicalResultBytes(r)
	// Phase C: read the carved-out identity key directly.
	mh.vaultState.mu.RLock()
	idKey := append([]byte(nil), mh.vaultState.identityPrivateKey...)
	mh.vaultState.mu.RUnlock()
	if len(idKey) == 0 {
		// Vault locked — return unsigned. The wire layer will refuse to
		// send an unsigned envelope, but this still gives us a structured
		// failure to log.
		log.Warn().Str("invocation_id", r.InvocationID).Msg("cannot sign result: vault locked")
		return r
	}
	defer zeroBytes(idKey)
	r.PeerSig = base64.StdEncoding.EncodeToString(ed25519.Sign(idKey, canonical))
	return r
}

// ----------------------------------------------------------------------
// Audit + notification helpers
// ----------------------------------------------------------------------

func (mh *MessageHandler) logActionAudit(connectionID, peerGUID, eventType, invocationID, actionID, body string) {
	if mh.auditLog == nil || connectionID == "" {
		return
	}
	mh.auditLog.Append(AuditEntry{
		ConnectionID: connectionID,
		PeerGUID:     peerGUID,
		EventType:    eventType,
		Direction:    AuditDirectionInbound,
		Title:        actionID,
		Body:         body,
		Refs:         map[string]string{"invocation_id": invocationID},
	})
}

func (mh *MessageHandler) notifyOwnerOfPendingAction(p *ActionPendingApproval, def ActionDef) {
	// Best-effort: publish a forApp event the FeedNotificationService
	// listens for. The app's notification-service routes to a push
	// notification with inline Approve/Deny actions.
	body, _ := json.Marshal(map[string]interface{}{
		"invocation_id":   p.InvocationID,
		"action_id":       def.ID,
		"action_label":    def.Label,
		"invoker_guid":    p.InvokerGUID,
		"connection_id":   p.ConnectionID,
		"params_preview":  string(p.Params),
		"requested_at":    p.InvokedAt,
	})
	if mh.publisher != nil {
		_ = mh.publisher.PublishToApp(context.Background(), "action.pending-approval", body)
	}
}

// ----------------------------------------------------------------------
// Executor dispatch + Phase-1 implementations
// ----------------------------------------------------------------------

// executeAction runs the action's executor. ownerOverrides are
// owner-time tweaks captured during the approval flow (e.g. trim the
// shared field set before approving profile.fields.read).
func (mh *MessageHandler) executeAction(ctx context.Context, def ActionDef, invokerGUID, connectionID string, params json.RawMessage, ownerOverrides map[string]interface{}) (json.RawMessage, error) {
	switch def.ID {
	case ActionIDProfileFieldsRead:
		return mh.execProfileFieldsRead(invokerGUID, params, ownerOverrides)
	case ActionIDSecretsShare:
		return mh.execSecretsShare(invokerGUID, params, ownerOverrides)
	case ActionIDWalletRequestAddress:
		return mh.execWalletRequestAddress(invokerGUID, params)
	case ActionIDWalletRequestPayment:
		return mh.execWalletRequestPayment(invokerGUID, connectionID, params, ownerOverrides)
	case ActionIDVoteDelegateProxy:
		return mh.execVoteDelegateProxy(ctx, invokerGUID, params, ownerOverrides)
	case ActionIDConnectionHandoff:
		return mh.execConnectionHandoff(invokerGUID, params, ownerOverrides)
	case ActionIDAuditRecent:
		return mh.execAuditRecent(invokerGUID, connectionID, params)
	}
	return nil, fmt.Errorf("ERR_ACTION_NO_EXECUTOR: %s", def.ID)
}

// --- profile.fields.read ---
// Reads PersonalDataStore filtered by:
//   1. The owner's stored OwnerParams.allowed_fields (a hard cap)
//   2. The per-invocation params.field_ids (intersection)
//   3. ownerOverrides.allowed_fields (last-mile narrowing during approval)
func (mh *MessageHandler) execProfileFieldsRead(invokerGUID string, params json.RawMessage, ownerOverrides map[string]interface{}) (json.RawMessage, error) {
	var p struct {
		FieldIDs []string `json:"field_ids"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	allowed := mh.ownerAllowedFields(ActionIDProfileFieldsRead)
	requested := intersectStrings(p.FieldIDs, allowed)
	if override, ok := ownerOverrides["allowed_fields"].([]interface{}); ok {
		overrideStrs := make([]string, 0, len(override))
		for _, v := range override {
			if s, ok := v.(string); ok {
				overrideStrs = append(overrideStrs, s)
			}
		}
		requested = intersectStrings(requested, overrideStrs)
	}
	values := mh.fetchProfileFields(requested)
	out, _ := json.Marshal(map[string]interface{}{"values": values})
	return out, nil
}

// --- secrets.share ---
func (mh *MessageHandler) execSecretsShare(invokerGUID string, params json.RawMessage, ownerOverrides map[string]interface{}) (json.RawMessage, error) {
	var p struct {
		SecretID string `json:"secret_id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	plaintext, err := mh.fetchSecretPlaintext(p.SecretID)
	if err != nil {
		return nil, fmt.Errorf("ERR_SECRET_NOT_FOUND")
	}
	out, _ := json.Marshal(map[string]interface{}{
		"secret_id": p.SecretID,
		"plaintext": plaintext,
	})
	return out, nil
}

// --- wallet.request-address ---
// Returns the next BTC receive address.
func (mh *MessageHandler) execWalletRequestAddress(invokerGUID string, params json.RawMessage) (json.RawMessage, error) {
	addr, err := mh.deriveNextBTCAddress()
	if err != nil {
		return nil, fmt.Errorf("ERR_WALLET_UNAVAILABLE: %s", err.Error())
	}
	out, _ := json.Marshal(map[string]interface{}{
		"address": addr,
		"asset":   "BTC",
	})
	return out, nil
}

// --- wallet.request-payment ---
// Builds an UNSIGNED prepared tx the owner can review and broadcast
// later. Status is "prepared"; invoker sees the tx hex but the tx is
// not yet on-chain.
func (mh *MessageHandler) execWalletRequestPayment(invokerGUID, connectionID string, params json.RawMessage, ownerOverrides map[string]interface{}) (json.RawMessage, error) {
	var p struct {
		Asset      string `json:"asset"`
		AmountSats int64  `json:"amount_sats"`
		Memo       string `json:"memo"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	preparedHex, err := mh.prepareBTCSend(invokerGUID, p.AmountSats, p.Memo)
	if err != nil {
		return nil, fmt.Errorf("ERR_PREPARE_TX: %s", err.Error())
	}
	out, _ := json.Marshal(map[string]interface{}{
		"status":          "prepared",
		"prepared_tx_hex": preparedHex,
	})
	return out, nil
}

// --- vote.delegate-proxy ---
// Always status=prepared; the actual cast happens when the owner taps
// approve in the proposal-detail screen (the executor doesn't sign the
// vote — it just records the delegate intent).
func (mh *MessageHandler) execVoteDelegateProxy(ctx context.Context, invokerGUID string, params json.RawMessage, ownerOverrides map[string]interface{}) (json.RawMessage, error) {
	var p struct {
		ProposalID string `json:"proposal_id"`
		Choice     string `json:"choice"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	// Phase 1: record the delegate intent in the audit log; the actual
	// vote-cast still requires the owner to confirm in the voting UI.
	out, _ := json.Marshal(map[string]interface{}{
		"status":   "delegated",
		"voted_at": "",
	})
	return out, nil
}

// --- connection.handoff ---
// Creates an introduction invitation card; the owner must complete the
// share via the connection-create flow. Phase 1 returns an "initiated"
// status.
func (mh *MessageHandler) execConnectionHandoff(invokerGUID string, params json.RawMessage, ownerOverrides map[string]interface{}) (json.RawMessage, error) {
	out, _ := json.Marshal(map[string]interface{}{"status": "initiated"})
	return out, nil
}

// --- audit.recent ---
// Returns the last N audit events for the invoker's connection from the
// owner's perspective, scoped to events where the peer is the invoker.
func (mh *MessageHandler) execAuditRecent(invokerGUID, connectionID string, params json.RawMessage) (json.RawMessage, error) {
	var p struct {
		Limit int `json:"limit"`
	}
	_ = json.Unmarshal(params, &p)
	if p.Limit <= 0 || p.Limit > 200 {
		p.Limit = 50
	}
	if mh.auditLog == nil || connectionID == "" {
		return json.RawMessage(`{"events":[]}`), nil
	}
	events, _, err := mh.auditLog.List(storage.AuditListOptions{
		ConnectionID: connectionID,
		Limit:        p.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("audit list: %w", err)
	}
	body := map[string]interface{}{"events": events}
	out, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ----------------------------------------------------------------------
// Helper stubs that adapt to existing vault internals
// ----------------------------------------------------------------------

// ownerAllowedFields returns the OwnerParams["allowed_fields"] for an
// action. Empty slice if unconfigured (which means "no fields are
// shareable" — strict fail-closed).
func (mh *MessageHandler) ownerAllowedFields(actionID string) []string {
	if err := mh.ensureEnabledActions(); err != nil {
		return nil
	}
	actionAuthMu.RLock()
	defer actionAuthMu.RUnlock()
	ea := mh.enabledActions.Actions[actionID]
	if ea == nil {
		return nil
	}
	if v, ok := ea.OwnerParams["allowed_fields"].([]interface{}); ok {
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// fetchProfileFields reads from the personal-data store. Returns a map
// keyed by field ID. Phase 1 stub — returns the stored values for any
// IDs that exist; integration with PersonalDataStore is the follow-up
// task once we know which storage key the data lives under.
func (mh *MessageHandler) fetchProfileFields(fieldIDs []string) map[string]string {
	out := make(map[string]string, len(fieldIDs))
	if mh.storage == nil {
		return out
	}
	for _, id := range fieldIDs {
		var val string
		if err := mh.storage.GetJSON("personal_data/fields/"+id, &val); err == nil {
			out[id] = val
		}
	}
	return out
}

// fetchSecretPlaintext reads a single secret from the secrets store.
func (mh *MessageHandler) fetchSecretPlaintext(secretID string) (string, error) {
	if mh.storage == nil {
		return "", fmt.Errorf("storage unavailable")
	}
	var rec struct {
		Plaintext string `json:"plaintext"`
	}
	if err := mh.storage.GetJSON("secrets/"+secretID, &rec); err != nil {
		return "", err
	}
	return rec.Plaintext, nil
}

// deriveNextBTCAddress is a Phase-1 stub. The wallet handler already
// knows how to derive addresses; until we wire that in, return a
// placeholder that surfaces clearly in tests but won't be confused for
// a real address.
func (mh *MessageHandler) deriveNextBTCAddress() (string, error) {
	// TODO(actions): wire to wallet_handler.go GetAddress
	return "bcrt1q-stub-address-please-wire-wallet-handler", nil
}

// prepareBTCSend builds an unsigned prepared transaction. Phase-1 stub.
func (mh *MessageHandler) prepareBTCSend(invokerGUID string, amountSats int64, memo string) (string, error) {
	// TODO(actions): wire to wallet_handler.go BuildSendTx
	return "stub-prepared-tx-hex", nil
}

func intersectStrings(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(b))
	for _, x := range b {
		set[x] = struct{}{}
	}
	out := make([]string, 0)
	for _, x := range a {
		if _, ok := set[x]; ok {
			out = append(out, x)
		}
	}
	return out
}

// newInvocationID is the canonical generator. Mirrors newAuditEntryID
// so the formats match.
func newInvocationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("inv-%d", time.Now().UnixNano())
	}
	return "inv-" + hex.EncodeToString(b)
}

// trim is a small helper for one-line strings.Trim usage in the file.
var _ = strings.TrimSpace
