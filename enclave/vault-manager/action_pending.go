package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Durable pending-approval queue for prompt-each-time invocations.
// Persisted at actions/_pending in EncryptedStorage so the queue
// survives a vault lock or supervisor restart — owners pick up where
// they left off on the next unlock.
//
// Lifecycle:
//   1. Auth engine sees auth_mode=prompt-each-time → enqueueLocked.
//   2. Owner taps Approve / Deny in the push notification or in-app modal.
//      Auth engine looks up the entry, runs the executor (Approve) or
//      emits a denied result (Deny).
//   3. Background sweep (sweepExpired) marks anything older than the TTL
//      as expired and emits a final result envelope so the invoker isn't
//      left hanging.

const (
	pendingApprovalsKey = "actions/_pending"
	pendingApprovalsTTL = 7 * 24 * time.Hour
)

type ActionPendingApprovalStatus string

const (
	PendingStatusWaiting  ActionPendingApprovalStatus = "waiting"
	PendingStatusApproved ActionPendingApprovalStatus = "approved"
	PendingStatusDenied   ActionPendingApprovalStatus = "denied"
	PendingStatusExpired  ActionPendingApprovalStatus = "expired"
)

// ActionPendingApproval is the persisted record. Carries enough to:
//   1. Re-verify the invoker signature on resume.
//   2. Re-run schema validation.
//   3. Build the result envelope to send to the invoker.
type ActionPendingApproval struct {
	InvocationID    string                 `json:"invocation_id"`
	ActionID        string                 `json:"action_id"`
	ActionVersion   int                    `json:"action_version"`
	InvokerGUID     string                 `json:"invoker_guid"`
	InvokerPubKey   string                 `json:"invoker_pubkey"` // base64 Ed25519
	ConnectionID    string                 `json:"connection_id"`
	Params          json.RawMessage        `json:"params"`
	InvokedAt       string                 `json:"invoked_at"`
	InvokerSig      string                 `json:"invoker_sig"`     // base64
	CanonicalBytes  string                 `json:"canonical_bytes"` // base64 of the bytes invoker signed
	Status          ActionPendingApprovalStatus  `json:"status"`
	CreatedAt       int64                  `json:"created_at"`
	DecidedAt       int64                  `json:"decided_at,omitempty"`
	OwnerNote       string                 `json:"owner_note,omitempty"`
	ResultEnvelope  json.RawMessage        `json:"result_envelope,omitempty"` // captured after decide
	OwnerOverrides  map[string]interface{} `json:"owner_overrides,omitempty"` // owner-time tweaks (e.g. trim shared fields)
}

// ActionPendingApprovalQueue is the persisted blob.
type ActionPendingApprovalQueue struct {
	Version  int                         `json:"version"`
	Items    map[string]*ActionPendingApproval `json:"items"`
	UpdatedAt int64                      `json:"updated_at"`
}

var pendingMu sync.RWMutex

func (mh *MessageHandler) loadActionPendingApprovalsLocked() error {
	if mh.storage == nil {
		return fmt.Errorf("storage not initialized")
	}
	var q ActionPendingApprovalQueue
	err := mh.storage.GetJSON(pendingApprovalsKey, &q)
	if err == ErrKeyNotFound {
		q = ActionPendingApprovalQueue{Version: 1, Items: map[string]*ActionPendingApproval{}, UpdatedAt: time.Now().Unix()}
		_ = mh.storage.PutJSON(pendingApprovalsKey, &q)
	} else if err != nil {
		return fmt.Errorf("read pending approvals: %w", err)
	}
	if q.Items == nil {
		q.Items = map[string]*ActionPendingApproval{}
	}
	mh.pendingApprovals = &q
	return nil
}

func (mh *MessageHandler) ensureActionPendingApprovals() error {
	pendingMu.RLock()
	loaded := mh.pendingApprovals != nil
	pendingMu.RUnlock()
	if loaded {
		return nil
	}
	pendingMu.Lock()
	defer pendingMu.Unlock()
	if mh.pendingApprovals == nil {
		return mh.loadActionPendingApprovalsLocked()
	}
	return nil
}

// EnqueuePending persists a new pending-approval record. Idempotent on
// invocation_id — re-enqueueing the same id is a no-op (handles invoker
// retries while the owner is offline).
func (mh *MessageHandler) EnqueuePending(p *ActionPendingApproval) error {
	if err := mh.ensureActionPendingApprovals(); err != nil {
		return err
	}
	pendingMu.Lock()
	defer pendingMu.Unlock()
	if existing, ok := mh.pendingApprovals.Items[p.InvocationID]; ok {
		log.Debug().Str("invocation_id", p.InvocationID).
			Str("status", string(existing.Status)).
			Msg("pending approval already enqueued — ignoring duplicate")
		return nil
	}
	if p.Status == "" {
		p.Status = PendingStatusWaiting
	}
	if p.CreatedAt == 0 {
		p.CreatedAt = time.Now().Unix()
	}
	mh.pendingApprovals.Items[p.InvocationID] = p
	mh.pendingApprovals.UpdatedAt = time.Now().Unix()
	return mh.storage.PutJSON(pendingApprovalsKey, mh.pendingApprovals)
}

// LookupPending returns the record by invocation id (or nil).
func (mh *MessageHandler) LookupPending(invocationID string) *ActionPendingApproval {
	if err := mh.ensureActionPendingApprovals(); err != nil {
		return nil
	}
	pendingMu.RLock()
	defer pendingMu.RUnlock()
	return mh.pendingApprovals.Items[invocationID]
}

// ListPending returns all entries with status=waiting (cap on caller).
func (mh *MessageHandler) ListPendingWaiting() []*ActionPendingApproval {
	if err := mh.ensureActionPendingApprovals(); err != nil {
		return nil
	}
	pendingMu.RLock()
	defer pendingMu.RUnlock()
	out := make([]*ActionPendingApproval, 0)
	for _, p := range mh.pendingApprovals.Items {
		if p.Status == PendingStatusWaiting {
			out = append(out, p)
		}
	}
	return out
}

// DecidePending marks an entry approved or denied and persists it. The
// caller (action_invoker.go ExecuteApproved / ExecuteDenied) is then
// responsible for emitting the result envelope and updating
// ResultEnvelope on the record if it wants the post-mortem trail.
func (mh *MessageHandler) DecidePending(invocationID string, status ActionPendingApprovalStatus, ownerNote string, ownerOverrides map[string]interface{}) (*ActionPendingApproval, error) {
	if err := mh.ensureActionPendingApprovals(); err != nil {
		return nil, err
	}
	pendingMu.Lock()
	defer pendingMu.Unlock()
	p := mh.pendingApprovals.Items[invocationID]
	if p == nil {
		return nil, fmt.Errorf("ERR_PENDING_NOT_FOUND: %s", invocationID)
	}
	if p.Status != PendingStatusWaiting {
		return p, fmt.Errorf("ERR_PENDING_ALREADY_DECIDED: %s (%s)", invocationID, p.Status)
	}
	p.Status = status
	p.DecidedAt = time.Now().Unix()
	p.OwnerNote = ownerNote
	if ownerOverrides != nil {
		p.OwnerOverrides = ownerOverrides
	}
	mh.pendingApprovals.UpdatedAt = time.Now().Unix()
	if err := mh.storage.PutJSON(pendingApprovalsKey, mh.pendingApprovals); err != nil {
		return p, err
	}
	return p, nil
}

// MarkResultEnvelope stores the final wire envelope on the record (for
// audit/post-mortem). Doesn't change Status.
func (mh *MessageHandler) MarkResultEnvelope(invocationID string, envelope []byte) {
	if err := mh.ensureActionPendingApprovals(); err != nil {
		return
	}
	pendingMu.Lock()
	defer pendingMu.Unlock()
	p := mh.pendingApprovals.Items[invocationID]
	if p == nil {
		return
	}
	p.ResultEnvelope = envelope
	mh.pendingApprovals.UpdatedAt = time.Now().Unix()
	_ = mh.storage.PutJSON(pendingApprovalsKey, mh.pendingApprovals)
}

// SweepExpiredPending marks any waiting entries older than the TTL as
// expired. Returns the slice of newly-expired entries so the caller can
// emit second-result envelopes.
func (mh *MessageHandler) SweepExpiredPending() []*ActionPendingApproval {
	if err := mh.ensureActionPendingApprovals(); err != nil {
		return nil
	}
	cutoff := time.Now().Add(-pendingApprovalsTTL).Unix()
	pendingMu.Lock()
	defer pendingMu.Unlock()
	expired := make([]*ActionPendingApproval, 0)
	for _, p := range mh.pendingApprovals.Items {
		if p.Status == PendingStatusWaiting && p.CreatedAt < cutoff {
			p.Status = PendingStatusExpired
			p.DecidedAt = time.Now().Unix()
			expired = append(expired, p)
		}
	}
	if len(expired) > 0 {
		mh.pendingApprovals.UpdatedAt = time.Now().Unix()
		_ = mh.storage.PutJSON(pendingApprovalsKey, mh.pendingApprovals)
	}
	return expired
}
