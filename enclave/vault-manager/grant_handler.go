package main

// Reference-based data-sharing between peer vaults.
//
// Owner side:
//   - HandleIncomingRequest receives a peer's DataAccessRequest, stores
//     it under pending_requests/<request_id>, and surfaces a prompt on
//     the owner's app via forApp.connection.data-request-received.
//   - HandleApprove turns a pending request into a live GrantRecord
//     and emits forVault.data.grant.created to the requester. HandleDeny
//     emits forVault.data.grant.denied.
//   - HandleIncomingFetch revalidates the grant on every receiver call,
//     resolves the current item value, encrypts it via the existing
//     peer envelope, and emits forVault.data.grant.fetch-response.
//   - HandleRevoke flips status + emits forVault.data.grant.revoked so
//     the receiver's UI greys out immediately.
//
// Receiver side:
//   - HandleRequest is the app op that publishes forVault.data.request
//     to the owner.
//   - HandleIncomingGrantCreated / GrantDenied / GrantRevoked mirror
//     state into received_grants/ and forward to the app.
//   - HandleFetchRemote is the app op that publishes a forVault.data.
//     grant.fetch and forwards the eventual response to the app via
//     the request_id correlation.
//   - HandleIncomingFetchResponse parses the response and forwards the
//     plaintext value to the app for in-session display only.
//
// All value bytes cross the wire under the EncryptedPeerEnvelope
// connection key — see peer_envelope.go.
//
// Phase 1 scope: ItemKind="data" only. Phase 4 will extend to
// minor secrets (with a hard reject of critical secrets). Phase 5
// extends DeliverTo to agent connectors. Phase 6 layers
// critical-secret use-on-behalf-of. See plans/data-request-grants.md.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Storage key prefixes used by the grant handler. The owner side owns
// grants/* and pending_requests/*; the receiver side owns received_grants/*.
// Per-connection indexes live under connections/<conn_id>/ so the
// connection-detail panels can list grants without scanning everything.
const (
	grantsIndexKey            = "grants/_index"
	grantsKeyPrefix           = "grants/"
	pendingRequestsIndexKey   = "pending_requests/_index"
	pendingRequestsKeyPrefix  = "pending_requests/"
	receivedGrantsIndexKey    = "received_grants/_index"
	receivedGrantsKeyPrefix   = "received_grants/"
	outboundGrantsIndexSuffix = "/_outbound_grants"
	inboundGrantsIndexSuffix  = "/_inbound_grants"

	// Requester-side record of requests we've sent — lets the
	// requester answer "what have I asked for, and was it answered?".
	// The owner side never sees these; they're updated in place when
	// the peer's grant.created / grant.denied echo arrives.
	outgoingRequestsIndexKey  = "outgoing_requests/_index"
	outgoingRequestsKeyPrefix = "outgoing_requests/"
	myRequestsIndexSuffix     = "/_my_requests"

	// Grant lifecycle states.
	GrantStatusActive  = "active"
	GrantStatusRevoked = "revoked"
	GrantStatusExpired = "expired"

	// Outgoing-request lifecycle (requester side).
	OutgoingRequestStatusPending  = "pending"
	OutgoingRequestStatusApproved = "approved"
	OutgoingRequestStatusDenied   = "denied"

	// Grant modes. one-shot expires on first fetch (MaxUses=1) and is
	// the default for unspecified requests. renewable / agent-renewable
	// are the Phase 5 surfaces.
	GrantModeOneShot         = "one-shot"
	GrantModeRenewable       = "renewable"
	GrantModeAgentRenewable  = "agent-renewable"

	GrantItemKindData   = "data"
	GrantItemKindSecret = "secret"

	GrantDeliverSelf = "self"
)

// GrantRecord is the owner-side authoritative record of an outbound
// grant. The receiver mirror (ReceivedGrantRecord) holds the same
// shape minus the OwnerGUID + control fields.
type GrantRecord struct {
	GrantID       string `json:"grant_id"`
	OwnerGUID     string `json:"owner_guid"`
	RequesterGUID string `json:"requester_guid"`
	ConnectionID  string `json:"connection_id"`
	ItemKind      string `json:"item_kind"`
	ItemRef       string `json:"item_ref"`
	ItemLabel     string `json:"item_label"`
	Mode          string `json:"mode"`
	DeliverTo     string `json:"deliver_to"`
	ExpiresAt     int64  `json:"expires_at"`
	MaxUses       int    `json:"max_uses"`
	UsesSoFar     int    `json:"uses_so_far"`
	Status        string `json:"status"`
	CreatedAt     int64  `json:"created_at"`
	LastFetchedAt int64  `json:"last_fetched_at,omitempty"`
	RevokedAt     int64  `json:"revoked_at,omitempty"`
	RevokeReason  string `json:"revoke_reason,omitempty"`
}

// ReceivedGrantRecord is the receiver-side mirror. No item value lives
// here — only enough to render the "Held in trust" UI and issue fetches.
type ReceivedGrantRecord struct {
	GrantID     string `json:"grant_id"`
	GranterGUID string `json:"granter_guid"`
	ConnectionID string `json:"connection_id"`
	ItemKind    string `json:"item_kind"`
	ItemRef     string `json:"item_ref"`
	ItemLabel   string `json:"item_label"`
	Mode        string `json:"mode"`
	ExpiresAt   int64  `json:"expires_at"`
	MaxUses     int    `json:"max_uses"`
	UsesSoFar   int    `json:"uses_so_far"`
	Status      string `json:"status"`
	GrantedAt   int64  `json:"granted_at"`
	LastFetched int64  `json:"last_fetched,omitempty"`
}

// PendingRequest mirrors an incoming DataAccessRequest awaiting the
// owner's decision. ApprovedGrantID is empty until owner approves; on
// approval the record moves out of pending_requests/ into grants/.
type PendingRequest struct {
	RequestID          string `json:"request_id"`
	RequesterGUID      string `json:"requester_guid"`
	ConnectionID       string `json:"connection_id"`
	ItemKind           string `json:"item_kind"`
	ItemRef            string `json:"item_ref"`
	ItemLabel          string `json:"item_label"`
	RequestedMode      string `json:"requested_mode"`
	RequestedExpiresAt int64  `json:"requested_expires_at"`
	RequestedMaxUses   int    `json:"requested_max_uses"`
	DeliverTo          string `json:"deliver_to"`
	Reason             string `json:"reason,omitempty"`
	ReceivedAt         int64  `json:"received_at"`
}

// OutgoingRequestRecord is the requester-side local record of a
// request we've SENT to a peer. Created on grant.request, updated to
// approved (with the grant_id) or denied when the peer's echo lands.
// Powers the "Requested" tab + the peer-catalog "already requested"
// badge — surfaces that are otherwise blind because the request only
// lives in the peer's vault until they answer.
type OutgoingRequestRecord struct {
	RequestID    string `json:"request_id"`
	ConnectionID string `json:"connection_id"`
	ItemKind     string `json:"item_kind"`
	ItemRef      string `json:"item_ref"`
	ItemLabel    string `json:"item_label"`
	Mode         string `json:"mode"`
	Reason       string `json:"reason,omitempty"`
	Status       string `json:"status"` // pending | approved | denied
	GrantID      string `json:"grant_id,omitempty"`      // set on approval
	DenialReason string `json:"denial_reason,omitempty"` // set on denial
	CreatedAt    int64  `json:"created_at"`
	RespondedAt  int64  `json:"responded_at,omitempty"`
}

// DataAccessRequest is the wire payload the requester ships to the
// owner. The owner stores it as PendingRequest after gating.
type DataAccessRequest struct {
	RequestID          string `json:"request_id"`
	ItemKind           string `json:"item_kind"`
	ItemRef            string `json:"item_ref"`
	ItemLabel          string `json:"item_label"`
	Mode               string `json:"mode"`
	DeliverTo          string `json:"deliver_to"`
	RequestedExpiresAt int64  `json:"requested_expires_at"`
	RequestedMaxUses   int    `json:"requested_max_uses"`
	Reason             string `json:"reason,omitempty"`
}

// GrantCreated is the wire payload the owner ships back when a request
// is approved. The receiver builds a ReceivedGrantRecord from it.
type GrantCreated struct {
	RequestID string `json:"request_id"`
	GrantID   string `json:"grant_id"`
	ItemKind  string `json:"item_kind"`
	ItemRef   string `json:"item_ref"`
	ItemLabel string `json:"item_label"`
	Mode      string `json:"mode"`
	ExpiresAt int64  `json:"expires_at"`
	MaxUses   int    `json:"max_uses"`
	GrantedAt int64  `json:"granted_at"`
}

// GrantDenied is emitted when the owner rejects a pending request.
type GrantDenied struct {
	RequestID string `json:"request_id"`
	Reason    string `json:"reason,omitempty"`
}

// GrantFetch is the receiver's resolution request — "please return the
// current value for grant_id." Owner re-validates everything on each call.
type GrantFetch struct {
	RequestID string `json:"request_id"`
	GrantID   string `json:"grant_id"`
}

// GrantFetchResponse carries the resolved value or an error explaining
// why the fetch was denied (expired, revoked, max-uses exceeded, item
// deleted from catalog).
type GrantFetchResponse struct {
	RequestID string `json:"request_id"`
	GrantID   string `json:"grant_id"`
	Status    string `json:"status"` // "ok" | "denied" | "error"
	Value     string `json:"value,omitempty"`
	Error     string `json:"error,omitempty"`
}

// GrantRevoked is the poison pill from owner → receiver.
type GrantRevoked struct {
	GrantID string `json:"grant_id"`
	Reason  string `json:"reason,omitempty"`
}

// GrantHandler owns the grant lifecycle on both owner and receiver sides
// of a connection. Methods named Handle* are message handlers; helper
// methods are lowercase. The handler is intentionally storage-bound, no
// in-memory state besides a mutex around index updates to keep
// concurrent app + peer paths honest.
type GrantHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
	publisher  *VsockPublisher
	auditLog   *AuditLog

	// indexMu serializes _index writes so concurrent grant creations /
	// revocations don't drop entries. Per-key Put through storage is
	// atomic; the read-modify-write on the index is the race window.
	indexMu sync.Mutex
}

// NewGrantHandler returns a GrantHandler. auditLog may be wired later
// via SetAuditLog so the construction order matches other handlers.
func NewGrantHandler(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher) *GrantHandler {
	return &GrantHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
		publisher:  publisher,
	}
}

// SetAuditLog wires the per-connection audit trail.
func (h *GrantHandler) SetAuditLog(a *AuditLog) { h.auditLog = a }

// newID generates a 16-byte random hex id for grants + requests.
// Cryptographically random — opaque to peers, no scheme to forge.
func newID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// ------------------------------------------------------------------
// Storage helpers
// ------------------------------------------------------------------

func (h *GrantHandler) loadGrant(grantID string) (*GrantRecord, error) {
	data, err := h.storage.Get(grantsKeyPrefix + grantID)
	if err != nil {
		return nil, err
	}
	var g GrantRecord
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("parse grant %s: %w", grantID, err)
	}
	return &g, nil
}

func (h *GrantHandler) saveGrant(g *GrantRecord) error {
	data, err := json.Marshal(g)
	if err != nil {
		return fmt.Errorf("marshal grant: %w", err)
	}
	if err := h.storage.Put(grantsKeyPrefix+g.GrantID, data); err != nil {
		return fmt.Errorf("put grant: %w", err)
	}
	return nil
}

func (h *GrantHandler) loadReceivedGrant(grantID string) (*ReceivedGrantRecord, error) {
	data, err := h.storage.Get(receivedGrantsKeyPrefix + grantID)
	if err != nil {
		return nil, err
	}
	var r ReceivedGrantRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse received grant %s: %w", grantID, err)
	}
	return &r, nil
}

func (h *GrantHandler) saveReceivedGrant(r *ReceivedGrantRecord) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal received grant: %w", err)
	}
	return h.storage.Put(receivedGrantsKeyPrefix+r.GrantID, data)
}

func (h *GrantHandler) loadOutgoingRequest(requestID string) (*OutgoingRequestRecord, error) {
	data, err := h.storage.Get(outgoingRequestsKeyPrefix + requestID)
	if err != nil {
		return nil, err
	}
	var r OutgoingRequestRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse outgoing request %s: %w", requestID, err)
	}
	return &r, nil
}

func (h *GrantHandler) saveOutgoingRequest(r *OutgoingRequestRecord) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal outgoing request: %w", err)
	}
	return h.storage.Put(outgoingRequestsKeyPrefix+r.RequestID, data)
}

func (h *GrantHandler) loadPending(requestID string) (*PendingRequest, error) {
	data, err := h.storage.Get(pendingRequestsKeyPrefix + requestID)
	if err != nil {
		return nil, err
	}
	var p PendingRequest
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse pending %s: %w", requestID, err)
	}
	return &p, nil
}

func (h *GrantHandler) savePending(p *PendingRequest) error {
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal pending: %w", err)
	}
	return h.storage.Put(pendingRequestsKeyPrefix+p.RequestID, data)
}

// appendToIndex inserts id (if not already present) into the JSON
// string array stored at key. indexMu must be held by the caller for
// any code path that mixes reads and writes — Append-only callers
// are still safe because storage.Put is atomic.
func (h *GrantHandler) appendToIndex(key string, id string) error {
	var ids []string
	if data, err := h.storage.Get(key); err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &ids)
	}
	for _, existing := range ids {
		if existing == id {
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

func (h *GrantHandler) removeFromIndex(key string, id string) error {
	data, err := h.storage.Get(key)
	if err != nil || len(data) == 0 {
		return nil
	}
	var ids []string
	if err := json.Unmarshal(data, &ids); err != nil {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, existing := range ids {
		if existing != id {
			out = append(out, existing)
		}
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return h.storage.Put(key, encoded)
}

func (h *GrantHandler) loadIndex(key string) []string {
	data, err := h.storage.Get(key)
	if err != nil || len(data) == 0 {
		return nil
	}
	var ids []string
	if json.Unmarshal(data, &ids) != nil {
		return nil
	}
	return ids
}

// resolveLocalConnectionForPeer mirrors location.go's findConnectionByPeerGUID
// and message router gates — we keep an inline copy here so the handler
// is self-contained and doesn't depend on notification-handler init order.
func (h *GrantHandler) resolveLocalConnectionForPeer(peerGUID string) string {
	indexData, err := h.storage.Get("connections/_index")
	if err != nil {
		return ""
	}
	var ids []string
	if json.Unmarshal(indexData, &ids) != nil {
		return ""
	}
	for _, id := range ids {
		d, err := h.storage.Get("connections/" + id)
		if err != nil {
			continue
		}
		var c ConnectionRecord
		if json.Unmarshal(d, &c) != nil {
			continue
		}
		if c.PeerGUID == peerGUID {
			return id
		}
	}
	return ""
}

// resolveItemValue returns the current value for the (kind, ref) pair.
// - GrantItemKindData: ref is the dotted namespace name (or composite
//   key including alias). Read from profile/<name> or personal-data/<name>.
// - GrantItemKindSecret: ref is the secret ID. Read from secrets/<key>
//   (scanning the index since key may include an alias suffix). HARD
//   REJECT if the same ID is registered under credential-secrets/_metadata
//   — critical secrets MUST NOT leave the owner's vault. The owner-side
//   "use on my behalf" path (Phase 6) is the only route for them.
//
// Returns ("", "item_not_found") if the item no longer exists, which
// is converted to a fetch denial. Other reasons:
//   item_kind_not_supported, item_marked_private, critical_secret_not_requestable.
func (h *GrantHandler) resolveItemValue(kind, ref string) (value string, reason string, err error) {
	if ref == "" {
		return "", "item_ref_empty", nil
	}
	switch kind {
	case GrantItemKindData:
		return h.resolveDataValue(ref)
	case GrantItemKindSecret:
		return h.resolveSecretValue(ref)
	default:
		return "", "item_kind_not_supported", nil
	}
}

func (h *GrantHandler) resolveDataValue(ref string) (string, string, error) {
	// First try exact key matches under profile/ and personal-data/.
	// Aliasless fields land here cleanly.
	candidates := []string{"profile/" + ref, "personal-data/" + ref}
	for _, key := range candidates {
		data, err := h.storage.Get(key)
		if err != nil || len(data) == 0 {
			continue
		}
		if v, reason, ok := tryDecodeDataValue(data); ok {
			return v, reason, nil
		}
	}

	// Aliased personal-data is stored under "personal-data/<ns>::<alias>"
	// (see fieldKey in personal_data.go). The grant's item_ref carries
	// only the namespace — the alias info is in item_label but not the
	// ref — so an exact lookup misses every aliased field. Mirror the
	// index-scan resolveSecretValue already does. Surfaced 2026-05-16
	// when "Relationship — Wife" / "Phone — Wife" grants resolved as
	// item_not_found, the vault denied the fetch with no use-count
	// increment, and the receiver's app saw nothing.
	idxData, err := h.storage.Get("personal-data/_index")
	if err == nil && len(idxData) > 0 {
		var keys []string
		if json.Unmarshal(idxData, &keys) == nil {
			for _, k := range keys {
				if k == ref || !strings.HasPrefix(k, ref+FieldKeySeparator) {
					// Already tried the exact match above; here we
					// only want composite-key matches.
					continue
				}
				data, err := h.storage.Get("personal-data/" + k)
				if err != nil || len(data) == 0 {
					continue
				}
				if v, reason, ok := tryDecodeDataValue(data); ok {
					return v, reason, nil
				}
			}
		}
	}

	return "", "item_not_found", nil
}

// tryDecodeDataValue parses either the PersonalDataField or the
// PersonalDataEntry shape and returns the (value, reason, found)
// triple resolveDataValue uses. Returns ok=false when the bytes
// don't look like either shape so the caller keeps searching.
func tryDecodeDataValue(data []byte) (string, string, bool) {
	var pdf PersonalDataField
	if json.Unmarshal(data, &pdf) == nil && pdf.Name != "" {
		if pdf.Discoverability == DiscoverabilityPrivate {
			return "", "item_marked_private", true
		}
		return pdf.Value, "", true
	}
	var pde PersonalDataEntry
	if json.Unmarshal(data, &pde) == nil && pde.Value != "" {
		return pde.Value, "", true
	}
	return "", "", false
}

// resolveSecretValue resolves a minor secret by ID. Critical secrets
// (registered under credential-secrets/_metadata) are hard-rejected so
// the data-request flow can never leak a credential or wallet seed.
// The matching TestSecretRequestRejectsCritical pins this invariant.
func (h *GrantHandler) resolveSecretValue(ref string) (string, string, error) {
	// Critical-secret hard cutoff: scan the credential-secrets metadata
	// before doing ANY value lookup. If the same ID is registered as a
	// critical secret, refuse — even if it also happens to live in
	// secrets/ for whatever reason.
	if h.isCriticalSecretID(ref) {
		return "", "critical_secret_not_requestable", nil
	}
	// Minor-secret storage uses secrets/<id> or secrets/<id>::<alias>.
	// Scan the index so we find a composite-keyed record without
	// requiring the requester to know the alias.
	idxData, err := h.storage.Get("secrets/_index")
	if err == nil && len(idxData) > 0 {
		var keys []string
		if json.Unmarshal(idxData, &keys) == nil {
			for _, k := range keys {
				if k != ref && !strings.HasPrefix(k, ref+FieldKeySeparator) {
					continue
				}
				data, err := h.storage.Get("secrets/" + k)
				if err != nil || len(data) == 0 {
					continue
				}
				var rec SecretRecord
				if json.Unmarshal(data, &rec) != nil {
					continue
				}
				if rec.Discoverability == DiscoverabilityPrivate {
					return "", "item_marked_private", nil
				}
				return rec.Value, "", nil
			}
		}
	}
	// Direct-key fallback (records inserted before the index was set
	// up, or test fixtures).
	if data, err := h.storage.Get("secrets/" + ref); err == nil && len(data) > 0 {
		var rec SecretRecord
		if json.Unmarshal(data, &rec) == nil {
			if rec.Discoverability == DiscoverabilityPrivate {
				return "", "item_marked_private", nil
			}
			return rec.Value, "", nil
		}
	}
	return "", "item_not_found", nil
}

// isCriticalSecretID returns true if the given ID appears in the
// critical-secrets metadata index. Reading the value would require
// password-gated credential decryption — we only need to know the ID
// exists to reject the request.
func (h *GrantHandler) isCriticalSecretID(id string) bool {
	data, err := h.storage.Get("credential-secrets/_metadata")
	if err != nil || len(data) == 0 {
		return false
	}
	var records []SecretMetadataRecord
	if json.Unmarshal(data, &records) != nil {
		return false
	}
	for _, r := range records {
		if r.ID == id {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------
// Owner side — receiving + decision flow
// ------------------------------------------------------------------

// HandleIncomingRequest is invoked when a peer publishes
// forVault.data.request to us. We store a PendingRequest record and
// forward to the app so the owner can decide.
func (h *GrantHandler) HandleIncomingRequest(ctx context.Context, dec *decryptedPeerEnvelope) error {
	if dec == nil {
		return fmt.Errorf("nil envelope")
	}
	var req DataAccessRequest
	if err := json.Unmarshal(dec.InnerPayload, &req); err != nil {
		return fmt.Errorf("invalid data-access request: %w", err)
	}
	if req.RequestID == "" || req.ItemKind == "" || req.ItemRef == "" {
		return fmt.Errorf("data-access request missing required fields")
	}

	h.indexMu.Lock()
	defer h.indexMu.Unlock()

	// Idempotency: if we already have this request_id pending, no-op.
	// The connection's NATS stream can replay during reconnects.
	if existing, err := h.loadPending(req.RequestID); err == nil && existing != nil {
		log.Debug().Str("request_id", req.RequestID).Msg("duplicate data-request; ignoring")
		return nil
	}

	pending := &PendingRequest{
		RequestID:          req.RequestID,
		RequesterGUID:      dec.FromOwnerSpace,
		ConnectionID:       dec.LocalConnID,
		ItemKind:           req.ItemKind,
		ItemRef:            req.ItemRef,
		ItemLabel:          req.ItemLabel,
		RequestedMode:      req.Mode,
		RequestedExpiresAt: req.RequestedExpiresAt,
		RequestedMaxUses:   req.RequestedMaxUses,
		DeliverTo:          req.DeliverTo,
		Reason:             req.Reason,
		ReceivedAt:         time.Now().Unix(),
	}
	if err := h.savePending(pending); err != nil {
		return err
	}
	if err := h.appendToIndex(pendingRequestsIndexKey, pending.RequestID); err != nil {
		return err
	}

	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: dec.LocalConnID,
			PeerGUID:     dec.FromOwnerSpace,
			EventType:    AuditTypeDataRequestReceived,
			Direction:    AuditDirectionInbound,
			Title:        "Requested access to " + safeLabel(req.ItemLabel, req.ItemRef),
			Refs: map[string]string{
				"request_id": req.RequestID,
				"item_kind":  req.ItemKind,
				"item_ref":   req.ItemRef,
			},
		})
	}

	if h.publisher != nil {
		appPayload, _ := json.Marshal(map[string]interface{}{
			"connection_id":         dec.LocalConnID,
			"requester_guid":        dec.FromOwnerSpace,
			"request_id":            req.RequestID,
			"item_kind":             req.ItemKind,
			"item_ref":              req.ItemRef,
			"item_label":            req.ItemLabel,
			"requested_mode":        req.Mode,
			"requested_expires_at":  req.RequestedExpiresAt,
			"requested_max_uses":    req.RequestedMaxUses,
			"deliver_to":            req.DeliverTo,
			"reason":                req.Reason,
		})
		if err := h.publisher.PublishToApp(ctx, "connection.data-request-received", appPayload); err != nil {
			log.Warn().Err(err).Msg("failed to notify app of data-request")
		}
	}
	return nil
}

// HandleApprove turns a pending request into a live grant. App-side op.
// Payload: {"request_id":..., "expires_at":?, "max_uses":?, "mode":?}
// — if expires_at / max_uses / mode are omitted, the request's values
// stand as-is. Mode is optionally downgraded (e.g. requester asked
// renewable, owner approves one-shot).
func (h *GrantHandler) HandleApprove(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		RequestID string `json:"request_id"`
		ExpiresAt int64  `json:"expires_at,omitempty"`
		MaxUses   int    `json:"max_uses,omitempty"`
		Mode      string `json:"mode,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "GrantApprove"); err != nil {
		return errorMsg(msg.GetID(), "invalid approve payload"), nil
	}
	if req.RequestID == "" {
		return errorMsg(msg.GetID(), "request_id required"), nil
	}

	h.indexMu.Lock()
	defer h.indexMu.Unlock()

	pending, err := h.loadPending(req.RequestID)
	if err != nil {
		return errorMsg(msg.GetID(), "pending request not found"), nil
	}

	mode := pending.RequestedMode
	if req.Mode != "" {
		mode = req.Mode
	}
	if mode == "" {
		mode = GrantModeOneShot
	}
	expires := pending.RequestedExpiresAt
	if req.ExpiresAt != 0 {
		expires = req.ExpiresAt
	}
	maxUses := pending.RequestedMaxUses
	if req.MaxUses != 0 {
		maxUses = req.MaxUses
	}
	if mode == GrantModeOneShot && maxUses == 0 {
		maxUses = 1
	}

	// Same (item, peer) → update existing grant rather than parallel.
	// Plan decision: one canonical grant per pairing; multiple requests
	// adjust expiry / max_uses on the live record.
	existing := h.findActiveGrant(pending.ConnectionID, pending.ItemKind, pending.ItemRef)
	var grant *GrantRecord
	now := time.Now().Unix()
	if existing != nil {
		existing.Mode = mode
		existing.ExpiresAt = expires
		existing.MaxUses = maxUses
		// Reset uses-so-far on re-approval so the receiver gets fresh budget.
		existing.UsesSoFar = 0
		grant = existing
	} else {
		grant = &GrantRecord{
			GrantID:       newID("grant-"),
			OwnerGUID:     h.ownerSpace,
			RequesterGUID: pending.RequesterGUID,
			ConnectionID:  pending.ConnectionID,
			ItemKind:      pending.ItemKind,
			ItemRef:       pending.ItemRef,
			ItemLabel:     pending.ItemLabel,
			Mode:          mode,
			DeliverTo:     pending.DeliverTo,
			ExpiresAt:     expires,
			MaxUses:       maxUses,
			Status:        GrantStatusActive,
			CreatedAt:     now,
		}
	}
	if err := h.saveGrant(grant); err != nil {
		return errorMsg(msg.GetID(), "failed to persist grant"), nil
	}
	if err := h.appendToIndex(grantsIndexKey, grant.GrantID); err != nil {
		return errorMsg(msg.GetID(), "failed to update grants index"), nil
	}
	if err := h.appendToIndex("connections/"+grant.ConnectionID+outboundGrantsIndexSuffix, grant.GrantID); err != nil {
		log.Warn().Err(err).Msg("failed to update outbound grants index")
	}

	// Drop the pending request now that it's resolved.
	_ = h.removeFromIndex(pendingRequestsIndexKey, pending.RequestID)
	_ = h.storage.Delete(pendingRequestsKeyPrefix + pending.RequestID)

	// Notify the requester.
	created := GrantCreated{
		RequestID: pending.RequestID,
		GrantID:   grant.GrantID,
		ItemKind:  grant.ItemKind,
		ItemRef:   grant.ItemRef,
		ItemLabel: grant.ItemLabel,
		Mode:      grant.Mode,
		ExpiresAt: grant.ExpiresAt,
		MaxUses:   grant.MaxUses,
		GrantedAt: grant.CreatedAt,
	}
	payload, _ := json.Marshal(&created)
	if err := encryptAndPublishToPeer(
		context.Background(), h.storage, h.publisher, h.ownerSpace,
		grant.ConnectionID, "data.grant.created", "grant-created:"+grant.GrantID, payload, now,
	); err != nil {
		log.Warn().Err(err).Str("grant_id", grant.GrantID).Msg("grant.created publish failed")
	}

	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: grant.ConnectionID,
			PeerGUID:     grant.RequesterGUID,
			EventType:    AuditTypeDataGranted,
			Direction:    AuditDirectionOutbound,
			Title:        "Granted access to " + safeLabel(grant.ItemLabel, grant.ItemRef),
			Refs: map[string]string{
				"grant_id":   grant.GrantID,
				"request_id": pending.RequestID,
				"item_kind":  grant.ItemKind,
				"item_ref":   grant.ItemRef,
			},
			Metadata: map[string]string{
				"mode":       grant.Mode,
				"expires_at": fmt.Sprintf("%d", grant.ExpiresAt),
				"max_uses":   fmt.Sprintf("%d", grant.MaxUses),
			},
		})
	}

	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":  true,
		"grant_id": grant.GrantID,
	})
	return successMsg(msg.GetID(), respBytes), nil
}

// HandleDeny rejects a pending request and notifies the requester.
// Payload: {"request_id":..., "reason":?}
func (h *GrantHandler) HandleDeny(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		RequestID string `json:"request_id"`
		Reason    string `json:"reason,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "GrantDeny"); err != nil {
		return errorMsg(msg.GetID(), "invalid deny payload"), nil
	}
	if req.RequestID == "" {
		return errorMsg(msg.GetID(), "request_id required"), nil
	}

	h.indexMu.Lock()
	defer h.indexMu.Unlock()

	pending, err := h.loadPending(req.RequestID)
	if err != nil {
		return errorMsg(msg.GetID(), "pending request not found"), nil
	}

	_ = h.removeFromIndex(pendingRequestsIndexKey, pending.RequestID)
	_ = h.storage.Delete(pendingRequestsKeyPrefix + pending.RequestID)

	denied := GrantDenied{RequestID: pending.RequestID, Reason: req.Reason}
	payload, _ := json.Marshal(&denied)
	if err := encryptAndPublishToPeer(
		context.Background(), h.storage, h.publisher, h.ownerSpace,
		pending.ConnectionID, "data.grant.denied", "grant-denied:"+pending.RequestID, payload, time.Now().Unix(),
	); err != nil {
		log.Warn().Err(err).Str("request_id", pending.RequestID).Msg("grant.denied publish failed")
	}

	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: pending.ConnectionID,
			PeerGUID:     pending.RequesterGUID,
			EventType:    AuditTypeDataGrantDenied,
			Direction:    AuditDirectionOutbound,
			Title:        "Denied access to " + safeLabel(pending.ItemLabel, pending.ItemRef),
			Refs: map[string]string{
				"request_id": pending.RequestID,
				"item_kind":  pending.ItemKind,
				"item_ref":   pending.ItemRef,
			},
		})
	}

	respBytes, _ := json.Marshal(map[string]interface{}{"success": true})
	return successMsg(msg.GetID(), respBytes), nil
}

// HandleRevoke flips a grant to revoked + emits the poison pill.
// Payload: {"grant_id":..., "reason":?}
func (h *GrantHandler) HandleRevoke(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		GrantID string `json:"grant_id"`
		Reason  string `json:"reason,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "GrantRevoke"); err != nil {
		return errorMsg(msg.GetID(), "invalid revoke payload"), nil
	}
	if req.GrantID == "" {
		return errorMsg(msg.GetID(), "grant_id required"), nil
	}

	h.indexMu.Lock()
	defer h.indexMu.Unlock()

	grant, err := h.loadGrant(req.GrantID)
	if err != nil {
		return errorMsg(msg.GetID(), "grant not found"), nil
	}
	if grant.Status != GrantStatusActive {
		// Idempotent revoke — succeed quietly.
		respBytes, _ := json.Marshal(map[string]interface{}{"success": true, "already_revoked": true})
		return successMsg(msg.GetID(), respBytes), nil
	}

	now := time.Now().Unix()
	grant.Status = GrantStatusRevoked
	grant.RevokedAt = now
	grant.RevokeReason = req.Reason
	if err := h.saveGrant(grant); err != nil {
		return errorMsg(msg.GetID(), "failed to persist revocation"), nil
	}

	revoke := GrantRevoked{GrantID: grant.GrantID, Reason: req.Reason}
	payload, _ := json.Marshal(&revoke)
	if err := encryptAndPublishToPeer(
		context.Background(), h.storage, h.publisher, h.ownerSpace,
		grant.ConnectionID, "data.grant.revoked", "grant-revoked:"+grant.GrantID, payload, now,
	); err != nil {
		log.Warn().Err(err).Str("grant_id", grant.GrantID).Msg("grant.revoked publish failed")
	}

	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: grant.ConnectionID,
			PeerGUID:     grant.RequesterGUID,
			EventType:    AuditTypeDataRevoked,
			Direction:    AuditDirectionOutbound,
			Title:        "Revoked access to " + safeLabel(grant.ItemLabel, grant.ItemRef),
			Refs: map[string]string{
				"grant_id":  grant.GrantID,
				"item_kind": grant.ItemKind,
				"item_ref":  grant.ItemRef,
			},
		})
	}

	respBytes, _ := json.Marshal(map[string]interface{}{"success": true})
	return successMsg(msg.GetID(), respBytes), nil
}

// HandleIncomingFetch is the owner-side handler for forVault.data.grant.fetch.
// Re-validates the grant on EVERY call: active, not expired, under
// max_uses, requester matches, item still exists. Increments use count
// on success and ships the encrypted value back via fetch-response.
func (h *GrantHandler) HandleIncomingFetch(ctx context.Context, dec *decryptedPeerEnvelope) error {
	if dec == nil {
		return fmt.Errorf("nil envelope")
	}
	var req GrantFetch
	if err := json.Unmarshal(dec.InnerPayload, &req); err != nil {
		return fmt.Errorf("invalid fetch: %w", err)
	}
	if req.GrantID == "" {
		return fmt.Errorf("fetch missing grant_id")
	}

	resp := GrantFetchResponse{RequestID: req.RequestID, GrantID: req.GrantID}

	h.indexMu.Lock()
	defer h.indexMu.Unlock()

	grant, err := h.loadGrant(req.GrantID)
	if err != nil {
		resp.Status = "denied"
		resp.Error = "grant_not_found"
		return h.sendFetchResponse(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp, "grant_not_found")
	}
	if grant.RequesterGUID != dec.FromOwnerSpace {
		// Cross-connection isolation: a different peer cannot resolve
		// our grant_id even if they somehow learn it.
		resp.Status = "denied"
		resp.Error = "requester_mismatch"
		return h.sendFetchResponse(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp, "requester_mismatch")
	}
	now := time.Now().Unix()
	if grant.Status == GrantStatusRevoked {
		resp.Status = "denied"
		resp.Error = "grant_revoked"
		return h.sendFetchResponse(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp, "grant_revoked")
	}
	if grant.ExpiresAt != 0 && now >= grant.ExpiresAt {
		grant.Status = GrantStatusExpired
		_ = h.saveGrant(grant)
		resp.Status = "denied"
		resp.Error = "grant_expired"
		return h.sendFetchResponse(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp, "grant_expired")
	}
	if grant.MaxUses != 0 && grant.UsesSoFar >= grant.MaxUses {
		resp.Status = "denied"
		resp.Error = "max_uses_exhausted"
		return h.sendFetchResponse(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp, "max_uses_exhausted")
	}

	value, reason, err := h.resolveItemValue(grant.ItemKind, grant.ItemRef)
	if err != nil {
		resp.Status = "error"
		resp.Error = "resolve_failed"
		return h.sendFetchResponse(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp, "resolve_failed")
	}
	if reason != "" {
		resp.Status = "denied"
		resp.Error = reason
		return h.sendFetchResponse(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp, reason)
	}

	grant.UsesSoFar++
	grant.LastFetchedAt = now
	_ = h.saveGrant(grant)

	resp.Status = "ok"
	resp.Value = value

	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: grant.ConnectionID,
			PeerGUID:     grant.RequesterGUID,
			EventType:    AuditTypeDataFetched,
			Direction:    AuditDirectionInbound,
			Title:        "Peer fetched " + safeLabel(grant.ItemLabel, grant.ItemRef),
			Refs: map[string]string{
				"grant_id":  grant.GrantID,
				"item_kind": grant.ItemKind,
				"item_ref":  grant.ItemRef,
			},
			Metadata: map[string]string{
				"uses_so_far": fmt.Sprintf("%d", grant.UsesSoFar),
			},
		})
	}
	return h.sendFetchResponse(ctx, dec.LocalConnID, dec.FromOwnerSpace, resp, "")
}

// sendFetchResponse encrypts + ships a GrantFetchResponse back to the
// receiver. denyReason is for audit only; the wire reason is on resp.
func (h *GrantHandler) sendFetchResponse(ctx context.Context, connID, peerGUID string, resp GrantFetchResponse, denyReason string) error {
	if denyReason != "" && h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: connID,
			PeerGUID:     peerGUID,
			EventType:    AuditTypeDataFetchDenied,
			Direction:    AuditDirectionInbound,
			Title:        "Denied fetch — " + denyReason,
			Refs: map[string]string{
				"grant_id": resp.GrantID,
			},
		})
	}
	payload, _ := json.Marshal(&resp)
	return encryptAndPublishToPeer(
		ctx, h.storage, h.publisher, h.ownerSpace,
		connID, "data.grant.fetch-response", "fetch-resp:"+resp.RequestID, payload, time.Now().Unix(),
	)
}

// findActiveGrant scans outbound grants for an existing active match.
// Caller must hold indexMu when this is part of a read-modify-write
// (HandleApprove does; lookup-only callers don't need it).
func (h *GrantHandler) findActiveGrant(connID, kind, ref string) *GrantRecord {
	ids := h.loadIndex("connections/" + connID + outboundGrantsIndexSuffix)
	for _, id := range ids {
		g, err := h.loadGrant(id)
		if err != nil {
			continue
		}
		if g.Status == GrantStatusActive && g.ItemKind == kind && g.ItemRef == ref {
			return g
		}
	}
	return nil
}

// ------------------------------------------------------------------
// Receiver side — sending + resolving
// ------------------------------------------------------------------

// HandleRequest is the app-side op that publishes a forVault.data.request
// to a connection. Payload mirrors DataAccessRequest plus connection_id.
func (h *GrantHandler) HandleRequest(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID       string `json:"connection_id"`
		ItemKind           string `json:"item_kind"`
		ItemRef            string `json:"item_ref"`
		ItemLabel          string `json:"item_label"`
		Mode               string `json:"mode"`
		DeliverTo          string `json:"deliver_to"`
		RequestedExpiresAt int64  `json:"requested_expires_at"`
		RequestedMaxUses   int    `json:"requested_max_uses"`
		Reason             string `json:"reason,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "GrantRequest"); err != nil {
		return errorMsg(msg.GetID(), "invalid request payload"), nil
	}
	if req.ConnectionID == "" || req.ItemKind == "" || req.ItemRef == "" {
		return errorMsg(msg.GetID(), "connection_id, item_kind, item_ref required"), nil
	}
	if req.Mode == "" {
		req.Mode = GrantModeOneShot
	}
	if req.DeliverTo == "" {
		req.DeliverTo = GrantDeliverSelf
	}

	wire := DataAccessRequest{
		RequestID:          newID("req-"),
		ItemKind:           req.ItemKind,
		ItemRef:            req.ItemRef,
		ItemLabel:          req.ItemLabel,
		Mode:               req.Mode,
		DeliverTo:          req.DeliverTo,
		RequestedExpiresAt: req.RequestedExpiresAt,
		RequestedMaxUses:   req.RequestedMaxUses,
		Reason:             req.Reason,
	}
	payload, _ := json.Marshal(&wire)
	if err := encryptAndPublishToPeer(
		context.Background(), h.storage, h.publisher, h.ownerSpace,
		req.ConnectionID, "data.request", "req:"+wire.RequestID, payload, time.Now().Unix(),
	); err != nil {
		return errorMsg(msg.GetID(), "failed to publish request: "+err.Error()), nil
	}

	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: req.ConnectionID,
			EventType:    AuditTypeDataRequestSent,
			Direction:    AuditDirectionOutbound,
			Title:        "Requested " + safeLabel(req.ItemLabel, req.ItemRef),
			Refs: map[string]string{
				"request_id": wire.RequestID,
				"item_kind":  req.ItemKind,
				"item_ref":   req.ItemRef,
			},
		})
	}

	// Persist a local record of the request we just sent. Until the
	// peer answers, the request only lives in their vault — this is
	// what lets the requester see it in the "Requested" tab and lets
	// the peer-catalog grey out already-requested items. Updated to
	// approved/denied when the grant.created / grant.denied echo lands.
	h.indexMu.Lock()
	outRec := &OutgoingRequestRecord{
		RequestID:    wire.RequestID,
		ConnectionID: req.ConnectionID,
		ItemKind:     req.ItemKind,
		ItemRef:      req.ItemRef,
		ItemLabel:    req.ItemLabel,
		Mode:         req.Mode,
		Reason:       req.Reason,
		Status:       OutgoingRequestStatusPending,
		CreatedAt:    time.Now().Unix(),
	}
	if err := h.saveOutgoingRequest(outRec); err != nil {
		log.Warn().Err(err).Msg("failed to persist outgoing request record")
	} else {
		_ = h.appendToIndex(outgoingRequestsIndexKey, outRec.RequestID)
		_ = h.appendToIndex("connections/"+req.ConnectionID+myRequestsIndexSuffix, outRec.RequestID)
	}
	h.indexMu.Unlock()

	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":    true,
		"request_id": wire.RequestID,
	})
	return successMsg(msg.GetID(), respBytes), nil
}

// HandleIncomingGrantCreated mirrors the owner's GrantCreated into our
// received_grants/ store and notifies the app.
func (h *GrantHandler) HandleIncomingGrantCreated(ctx context.Context, dec *decryptedPeerEnvelope) error {
	if dec == nil {
		return fmt.Errorf("nil envelope")
	}
	var created GrantCreated
	if err := json.Unmarshal(dec.InnerPayload, &created); err != nil {
		return fmt.Errorf("invalid grant-created: %w", err)
	}
	if created.GrantID == "" {
		return fmt.Errorf("grant-created missing grant_id")
	}

	h.indexMu.Lock()
	defer h.indexMu.Unlock()

	// Update or insert — re-approval on the same (item, peer) replaces
	// the existing mirror row.
	r := &ReceivedGrantRecord{
		GrantID:      created.GrantID,
		GranterGUID:  dec.FromOwnerSpace,
		ConnectionID: dec.LocalConnID,
		ItemKind:     created.ItemKind,
		ItemRef:      created.ItemRef,
		ItemLabel:    created.ItemLabel,
		Mode:         created.Mode,
		ExpiresAt:    created.ExpiresAt,
		MaxUses:      created.MaxUses,
		Status:       GrantStatusActive,
		GrantedAt:    created.GrantedAt,
	}
	if err := h.saveReceivedGrant(r); err != nil {
		return err
	}
	if err := h.appendToIndex(receivedGrantsIndexKey, r.GrantID); err != nil {
		return err
	}
	if err := h.appendToIndex("connections/"+r.ConnectionID+inboundGrantsIndexSuffix, r.GrantID); err != nil {
		log.Warn().Err(err).Msg("failed to update inbound grants index")
	}

	// Mark our local outgoing-request record as approved. Best effort —
	// a request from before this record existed (or one whose echo
	// dropped the request_id) simply won't have a row to update.
	if created.RequestID != "" {
		if outRec, err := h.loadOutgoingRequest(created.RequestID); err == nil && outRec != nil {
			outRec.Status = OutgoingRequestStatusApproved
			outRec.GrantID = created.GrantID
			outRec.RespondedAt = time.Now().Unix()
			_ = h.saveOutgoingRequest(outRec)
		}
	}

	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: r.ConnectionID,
			PeerGUID:     r.GranterGUID,
			EventType:    AuditTypeDataGranted,
			Direction:    AuditDirectionInbound,
			Title:        "Granted access to " + safeLabel(r.ItemLabel, r.ItemRef),
			Refs: map[string]string{
				"grant_id":   r.GrantID,
				"request_id": created.RequestID,
				"item_kind":  r.ItemKind,
				"item_ref":   r.ItemRef,
			},
		})
	}

	if h.publisher != nil {
		appPayload, _ := json.Marshal(map[string]interface{}{
			"connection_id": r.ConnectionID,
			"granter_guid":  r.GranterGUID,
			"grant_id":      r.GrantID,
			"request_id":    created.RequestID,
			"item_kind":     r.ItemKind,
			"item_label":    r.ItemLabel,
			"mode":          r.Mode,
			"expires_at":    r.ExpiresAt,
			"max_uses":      r.MaxUses,
		})
		if err := h.publisher.PublishToApp(ctx, "connection.data-grant-created", appPayload); err != nil {
			log.Warn().Err(err).Msg("failed to notify app of grant-created")
		}
	}
	return nil
}

// HandleIncomingGrantDenied forwards a denial notice to the app and
// records the audit row.
func (h *GrantHandler) HandleIncomingGrantDenied(ctx context.Context, dec *decryptedPeerEnvelope) error {
	if dec == nil {
		return fmt.Errorf("nil envelope")
	}
	var denied GrantDenied
	if err := json.Unmarshal(dec.InnerPayload, &denied); err != nil {
		return fmt.Errorf("invalid grant-denied: %w", err)
	}

	// Mark our local outgoing-request record as denied so the
	// "Requested" tab shows the outcome instead of a stuck "pending".
	if denied.RequestID != "" {
		h.indexMu.Lock()
		if outRec, err := h.loadOutgoingRequest(denied.RequestID); err == nil && outRec != nil {
			outRec.Status = OutgoingRequestStatusDenied
			outRec.DenialReason = denied.Reason
			outRec.RespondedAt = time.Now().Unix()
			_ = h.saveOutgoingRequest(outRec)
		}
		h.indexMu.Unlock()
	}

	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: dec.LocalConnID,
			PeerGUID:     dec.FromOwnerSpace,
			EventType:    AuditTypeDataGrantDenied,
			Direction:    AuditDirectionInbound,
			Title:        "Request denied",
			Body:         denied.Reason,
			Refs:         map[string]string{"request_id": denied.RequestID},
		})
	}
	if h.publisher != nil {
		appPayload, _ := json.Marshal(map[string]interface{}{
			"connection_id": dec.LocalConnID,
			"granter_guid":  dec.FromOwnerSpace,
			"request_id":    denied.RequestID,
			"reason":        denied.Reason,
		})
		_ = h.publisher.PublishToApp(ctx, "connection.data-grant-denied", appPayload)
	}
	return nil
}

// HandleIncomingGrantRevoked flips the receiver mirror to revoked and
// notifies the app so the UI greys out the row.
func (h *GrantHandler) HandleIncomingGrantRevoked(ctx context.Context, dec *decryptedPeerEnvelope) error {
	if dec == nil {
		return fmt.Errorf("nil envelope")
	}
	var revoked GrantRevoked
	if err := json.Unmarshal(dec.InnerPayload, &revoked); err != nil {
		return fmt.Errorf("invalid grant-revoked: %w", err)
	}
	h.indexMu.Lock()
	defer h.indexMu.Unlock()

	if r, err := h.loadReceivedGrant(revoked.GrantID); err == nil && r != nil {
		r.Status = GrantStatusRevoked
		_ = h.saveReceivedGrant(r)
	}
	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: dec.LocalConnID,
			PeerGUID:     dec.FromOwnerSpace,
			EventType:    AuditTypeDataRevoked,
			Direction:    AuditDirectionInbound,
			Title:        "Access revoked",
			Body:         revoked.Reason,
			Refs:         map[string]string{"grant_id": revoked.GrantID},
		})
	}
	if h.publisher != nil {
		appPayload, _ := json.Marshal(map[string]interface{}{
			"connection_id": dec.LocalConnID,
			"granter_guid":  dec.FromOwnerSpace,
			"grant_id":      revoked.GrantID,
			"reason":        revoked.Reason,
		})
		_ = h.publisher.PublishToApp(ctx, "connection.data-grant-revoked", appPayload)
	}
	return nil
}

// HandleRenew is the receiver-side app op that re-asks the owner for
// a fresh expiry on an existing grant. Reuses the request flow: we
// emit a new DataAccessRequest with the same item_ref and a flag
// indicating this is a renewal (Reason starts with "renew:").
// The owner sees a slightly different approval prompt and on approve
// the existing GrantRecord is updated in place (single-grant-per-
// (item, peer) policy already in HandleApprove).
func (h *GrantHandler) HandleRenew(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		GrantID            string `json:"grant_id"`
		RequestedExpiresAt int64  `json:"requested_expires_at,omitempty"`
		RequestedMaxUses   int    `json:"requested_max_uses,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "GrantRenew"); err != nil {
		return errorMsg(msg.GetID(), "invalid renew payload"), nil
	}
	r, err := h.loadReceivedGrant(req.GrantID)
	if err != nil {
		return errorMsg(msg.GetID(), "received grant not found"), nil
	}
	wire := DataAccessRequest{
		RequestID:          newID("renew-"),
		ItemKind:           r.ItemKind,
		ItemRef:            r.ItemRef,
		ItemLabel:          r.ItemLabel,
		Mode:               r.Mode,
		DeliverTo:          GrantDeliverSelf,
		RequestedExpiresAt: req.RequestedExpiresAt,
		RequestedMaxUses:   req.RequestedMaxUses,
		Reason:             "renew:" + req.GrantID,
	}
	payload, _ := json.Marshal(&wire)
	if err := encryptAndPublishToPeer(
		context.Background(), h.storage, h.publisher, h.ownerSpace,
		r.ConnectionID, "data.request", "req:"+wire.RequestID, payload, time.Now().Unix(),
	); err != nil {
		return errorMsg(msg.GetID(), "failed to publish renew: "+err.Error()), nil
	}
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":    true,
		"request_id": wire.RequestID,
	})
	return successMsg(msg.GetID(), respBytes), nil
}

// HandleFetchRemote is the receiver-side app op that issues a
// forVault.data.grant.fetch to the owner. The eventual fetch-response
// arrives asynchronously and is forwarded to the app via
// HandleIncomingFetchResponse.
func (h *GrantHandler) HandleFetchRemote(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		GrantID string `json:"grant_id"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "GrantFetchRemote"); err != nil {
		return errorMsg(msg.GetID(), "invalid fetch payload"), nil
	}
	if req.GrantID == "" {
		return errorMsg(msg.GetID(), "grant_id required"), nil
	}
	r, err := h.loadReceivedGrant(req.GrantID)
	if err != nil {
		return errorMsg(msg.GetID(), "grant not found locally"), nil
	}
	if r.Status != GrantStatusActive {
		return errorMsg(msg.GetID(), "grant_"+r.Status), nil
	}
	wire := GrantFetch{
		RequestID: newID("fetch-"),
		GrantID:   req.GrantID,
	}
	payload, _ := json.Marshal(&wire)
	if err := encryptAndPublishToPeer(
		context.Background(), h.storage, h.publisher, h.ownerSpace,
		r.ConnectionID, "data.grant.fetch", "fetch:"+wire.RequestID, payload, time.Now().Unix(),
	); err != nil {
		return errorMsg(msg.GetID(), "failed to publish fetch: "+err.Error()), nil
	}
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":    true,
		"request_id": wire.RequestID,
	})
	return successMsg(msg.GetID(), respBytes), nil
}

// HandleIncomingFetchResponse parses an owner's fetch-response and
// forwards the value (or denial) to the app. The plaintext value is
// passed through PublishToApp once — the app's ViewModel renders it
// in foreground state and never persists it to disk.
func (h *GrantHandler) HandleIncomingFetchResponse(ctx context.Context, dec *decryptedPeerEnvelope) error {
	if dec == nil {
		return fmt.Errorf("nil envelope")
	}
	var resp GrantFetchResponse
	if err := json.Unmarshal(dec.InnerPayload, &resp); err != nil {
		return fmt.Errorf("invalid fetch-response: %w", err)
	}

	// On the receiver side we update the mirror's LastFetched + UsesSoFar
	// so the UI can show "5/10 uses remaining" without round-tripping
	// to the owner. The authoritative counter is the owner's UsesSoFar.
	if resp.Status == "ok" {
		h.indexMu.Lock()
		if r, err := h.loadReceivedGrant(resp.GrantID); err == nil && r != nil {
			r.LastFetched = time.Now().Unix()
			r.UsesSoFar++
			_ = h.saveReceivedGrant(r)
		}
		h.indexMu.Unlock()
	} else if resp.Error == "grant_revoked" || resp.Error == "grant_expired" {
		// Owner-side state has moved on; mirror locally so subsequent
		// fetch attempts short-circuit without round-tripping.
		h.indexMu.Lock()
		if r, err := h.loadReceivedGrant(resp.GrantID); err == nil && r != nil {
			if resp.Error == "grant_revoked" {
				r.Status = GrantStatusRevoked
			} else {
				r.Status = GrantStatusExpired
			}
			_ = h.saveReceivedGrant(r)
		}
		h.indexMu.Unlock()
	}

	if h.publisher != nil {
		appPayload, _ := json.Marshal(map[string]interface{}{
			"connection_id": dec.LocalConnID,
			"granter_guid":  dec.FromOwnerSpace,
			"request_id":    resp.RequestID,
			"grant_id":      resp.GrantID,
			"status":        resp.Status,
			"value":         resp.Value,
			"error":         resp.Error,
		})
		_ = h.publisher.PublishToApp(ctx, "connection.data-grant-fetch-response", appPayload)
	}
	return nil
}

// ------------------------------------------------------------------
// Listing app ops (used by Connection Detail panels)
// ------------------------------------------------------------------

// HandleListOutbound lists owner-side grants for a connection (or all
// if no connection_id).
func (h *GrantHandler) HandleListOutbound(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id,omitempty"`
	}
	_ = unmarshalRequest(msg.Payload, &req, "GrantListOutbound")
	var ids []string
	if req.ConnectionID != "" {
		ids = h.loadIndex("connections/" + req.ConnectionID + outboundGrantsIndexSuffix)
	} else {
		ids = h.loadIndex(grantsIndexKey)
	}
	out := make([]*GrantRecord, 0, len(ids))
	now := time.Now().Unix()
	for _, id := range ids {
		g, err := h.loadGrant(id)
		if err != nil {
			continue
		}
		// Lazy expiry: surface expired status to the caller even if we
		// haven't persisted the flip yet.
		if g.Status == GrantStatusActive && g.ExpiresAt != 0 && now >= g.ExpiresAt {
			g.Status = GrantStatusExpired
		}
		out = append(out, g)
	}
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success": true,
		"grants":  out,
	})
	return successMsg(msg.GetID(), respBytes), nil
}

// HandleListInbound lists receiver-side received-grants for a
// connection (or all if no connection_id).
func (h *GrantHandler) HandleListInbound(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id,omitempty"`
	}
	_ = unmarshalRequest(msg.Payload, &req, "GrantListInbound")
	var ids []string
	if req.ConnectionID != "" {
		ids = h.loadIndex("connections/" + req.ConnectionID + inboundGrantsIndexSuffix)
	} else {
		ids = h.loadIndex(receivedGrantsIndexKey)
	}
	out := make([]*ReceivedGrantRecord, 0, len(ids))
	now := time.Now().Unix()
	for _, id := range ids {
		r, err := h.loadReceivedGrant(id)
		if err != nil {
			continue
		}
		if r.Status == GrantStatusActive && r.ExpiresAt != 0 && now >= r.ExpiresAt {
			r.Status = GrantStatusExpired
		}
		out = append(out, r)
	}
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":         true,
		"received_grants": out,
	})
	return successMsg(msg.GetID(), respBytes), nil
}

// HandleListPending lists pending requests awaiting owner decision.
func (h *GrantHandler) HandleListPending(msg *IncomingMessage) (*OutgoingMessage, error) {
	ids := h.loadIndex(pendingRequestsIndexKey)
	out := make([]*PendingRequest, 0, len(ids))
	for _, id := range ids {
		p, err := h.loadPending(id)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":  true,
		"pending":  out,
	})
	return successMsg(msg.GetID(), respBytes), nil
}

// HandleListMyRequests lists requests this vault has SENT to peers,
// with their current status (pending / approved / denied). Scoped to
// a connection if connection_id is provided — that's how the Them-tab
// "Requested" sub-tab and the peer-catalog "already requested" badge
// stay connection-specific.
func (h *GrantHandler) HandleListMyRequests(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id,omitempty"`
	}
	_ = unmarshalRequest(msg.Payload, &req, "GrantListMyRequests")
	var ids []string
	if req.ConnectionID != "" {
		ids = h.loadIndex("connections/" + req.ConnectionID + myRequestsIndexSuffix)
	} else {
		ids = h.loadIndex(outgoingRequestsIndexKey)
	}
	out := make([]*OutgoingRequestRecord, 0, len(ids))
	for _, id := range ids {
		r, err := h.loadOutgoingRequest(id)
		if err != nil {
			continue
		}
		out = append(out, r)
	}
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":     true,
		"my_requests": out,
	})
	return successMsg(msg.GetID(), respBytes), nil
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

// safeLabel returns label if non-empty, else ref. UI strings need
// something visible even when the requester forgot to include a label.
func safeLabel(label, ref string) string {
	if strings.TrimSpace(label) != "" {
		return label
	}
	return ref
}

func successMsg(id string, payload []byte) *OutgoingMessage {
	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeResponse,
		Payload:   payload,
	}
}

func errorMsg(id string, message string) *OutgoingMessage {
	body, _ := json.Marshal(map[string]string{"error": message})
	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeError,
		Payload:   body,
	}
}
