package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Domain separation constant for device connections (legacy, used only by
// the crypto helper below which the new flow no longer exercises).
const DomainDevice = "vettid-device-v1"

// Device message type constants for per-operation request/response after pairing.
// The pairing flow itself uses the NATS subject tree under MessageSpace.*.device.*
// (see vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md) and doesn't use these types.
const (
	DeviceMsgOpRequest        = "device_op_request"
	DeviceMsgOpResponse       = "device_op_response"
	DeviceMsgApprovalRequest  = "device_approval_request"
	DeviceMsgApprovalResponse = "device_approval_response"
)

// DeviceCapability tiers

// DeviceIndependentCapabilities returns operations the desktop can execute
// directly (still requires phone heartbeat to be fresh).
//
// Read-only ops live here. Anything that would mutate persistent vault
// state, expose a secret value, or sign on behalf of the user belongs
// in DevicePhoneRequiredCapabilities.
func DeviceIndependentCapabilities() []string {
	return []string{
		// Profile reads — own profile.get returns the user's name +
		// email + custom fields the user has set themselves; nothing
		// secret here. `profile.view` was the legacy op name; the
		// vault routes only `profile.get` now.
		"profile.get",
		"profile.view",
		"profile.photo.get",
		// Connection list + detail — same as Android: device can
		// browse peer connections without a phone round-trip.
		"connection.list",
		"connection.get",
		// Feed + audit + messages — read-only timelines.
		"feed.list",
		"feed.sync",
		"audit.query",
		"connection.audit.list",
		"connection.audit.search",
		"message.list",
		"message.read",
		// `message.read-receipt` is what mark_message_read on the
		// desktop and the equivalent Android path call when the user
		// opens an unread conversation — it's a fire-and-forget
		// acknowledgement that gets relayed to the peer's vault
		// (or, for agent connections, stamped locally). Gating it
		// behind phone approval meant the desktop fired an approval
		// prompt every time the user opened an unread thread, which
		// the user noticed during the 2026-05-25 agent-chat test.
		// `message.read` and `message.mark-read` were already here
		// but neither matches the actual op name dispatched by
		// handleMessageOperation (`read-receipt`); this row closes
		// that name-match gap.
		"message.read-receipt",
		// Agent + secret-catalog reads (catalog is metadata only).
		"agent.list",
		"secrets.catalog",
		// secret.list returns the user's secrets index (id, name,
		// alias, category, type, discoverability, timestamps) but no
		// values. The values stay phone-required until the session-
		// unlock grant (DeviceSession.SecretsUnlockedUntil) is wired
		// end-to-end. List/catalog read is safe because the user can
		// already see this in the published profile catalog peers
		// browse — no new disclosure.
		"secret.list",
		"secrets.list",
		"credential.secret.list",
		// Personal data reads — values are non-secret (the secret
		// material is under credential.* + secrets.*). Phone approval
		// added latency without a protection benefit.
		"personal-data.get",
		"personal-data.get-sort-order",
		// Screen-load bundle (profile + photo + personal-data in one
		// round-trip). Saves 3+ per-op overheads on desktop home.
		"vault.snapshot",
		// Wallet reads — balance + addresses + history are public
		// info; the signing op (wallet.sign / send.btc) is gated.
		"wallet.list",
		"wallet.get-balance",
		"wallet.get-address",
		// Vault dispatch is `wallet.get-history` (see
		// handleWalletOperation). The earlier `get-transaction-history`
		// entry was a typo that left desktop tx-history fetches
		// falling through to the phone-required path — every history
		// tap triggered an approval prompt for what's a public read.
		"wallet.get-history",
		// Device list — desktop can see "what desktops are paired to
		// my vault" without a phone round-trip.
		"device.list",
		// Call surface — desktop can browse history, fetch short-lived
		// TURN credentials at session init, and clear the
		// missed-call badge. None of these reveal call content
		// (signaling is e2e-encrypted; TURN creds are time-scoped
		// HMACs that only let webrtc traverse NATs). Without these
		// rows, every desktop call would block on a phone approval
		// just to set up media — defeats the point of having calls
		// on desktop at all.
		"call.history",
		"call.turn-credentials",
		"call.mark-seen",
		// Call control — start/accept/reject/end/signal. The vault
		// generates the X25519 keypair, encrypts peer signaling on
		// the wire, and holds the per-call shared secret; none of
		// these ops disclose call content or persistent state. Without
		// them, every desktop call setup would block on a phone tap
		// just to send an SDP offer — same security profile as the
		// read-side call ops above. Required for the desktop's vault-
		// routed call flow (`commands/calls.rs`'s `execute()` path).
		"call.start",
		"call.accept",
		"call.reject",
		"call.end",
		"call.signal",
		// Messaging — text send + mark-read. Sending a message reveals
		// no vault secret (it's user-typed text encrypted for the peer
		// connection's e2e key). The desktop is already authorized via
		// the device session — same trust level as composing on the
		// paired phone. Previously falling through to phone-required
		// meant every desktop text triggered an approval prompt on the
		// owner's phone (the user just *sent* the text from — bizarre
		// loop). message.mark-read fires read-receipts and was equally
		// non-sensitive.
		"message.send",
		"message.mark-read",
		// Wallet payment requests — the requestor is asking the peer
		// to send funds; no signing happens here. The signing op
		// (wallet.send) stays phone-required. Symmetric with how
		// Android handles the request side.
		"wallet.request-payment",
		// Outgoing-side grant ops — request, cancel, list-my-requests.
		// The owner of the requested item still approves on their own
		// vault; from this desktop's vault perspective, these are
		// purely outbound-state changes (the requestor's queue) and
		// reveal nothing new vs what message.send already exposes.
		// list-my-requests is the read-only fetch the Profile tab
		// uses; without it on this list, opening Profile triggered a
		// 30s phone-approval timeout and the UI appeared hung.
		"grant.request",
		"grant.cancel-request",
		"grant.list-my-requests",
		"grant.list-outbound",
		"grant.list-inbound",
		"grant.list-pending",
		// Verify-state reads + initiation. .get returns a cached
		// boolean + timestamp; .request publishes a signed nonce
		// challenge to the peer (cryptographic, no secret material
		// disclosed locally). The verify pill on the Profile tab
		// reads .get on mount — same as the grant list-my-requests
		// case above.
		"connection-authenticate.get",
		"connection-authenticate.list",
		"connection-authenticate.request",
		// Share-policy read — fetching one's own auto-allow rules
		// for a peer. No secret material; just policy metadata. The
		// `set` companion stays phone-required since it changes what
		// future requests will skip approval.
		"share-policy.get",
		// Presence-override read — fetching the current visibility
		// override for a peer. The `set` counterpart stays
		// phone-required so changing visibility still needs explicit
		// approval.
		"presence-override.get",
	}
}

// DevicePhoneRequiredCapabilities returns operations that require explicit
// phone approval before the vault will execute them.
func DevicePhoneRequiredCapabilities() []string {
	return []string{
		"secrets.retrieve",
		"secrets.add",
		"secrets.delete",
		"connection.create",
		"connection.revoke",
		"profile.update",
		"personal-data.update",
		"personal-data.delete",
		"credential.get",
		"credential.update",
		"pin.setup",
		"pin.unlock",
		"pin.change",
		"service.auth.request",
		"agent.approve",
		"wallet.sign",
		"wallet.send",
	}
}

// isIndependentCapability checks whether the given operation can be
// executed by a device connection without phone approval.
func isIndependentCapability(op string) bool {
	for _, cap := range DeviceIndependentCapabilities() {
		if cap == op {
			return true
		}
	}
	return false
}

// isPINOperation returns true if the operation is a PIN operation,
// which is NEVER accepted from a device connection.
func isPINOperation(op string) bool {
	return op == "pin.setup" || op == "pin.unlock" || op == "pin.change"
}

// PendingDeviceApproval tracks a device operation request awaiting phone approval.
type PendingDeviceApproval struct {
	RequestID    string    `json:"request_id"`
	ConnectionID string    `json:"connection_id"`
	Operation    string    `json:"operation"`
	Payload      []byte    `json:"payload"`
	CreatedAt    time.Time `json:"created_at"`
}

// DeviceHandler processes messages from desktop device connections.
//
// Device messages arrive via NATS on MessageSpace.{guid}.forOwner.device,
// are forwarded by the parent process to the enclave, and routed here
// by handleVaultOp when "forOwner" + "device" is detected in the subject.
//
// Each message is an AgentEnvelope containing:
//   - type: message type (device_connection_request, device_op_request, etc.)
//   - key_id: connection ID (used to look up the connection record)
//   - payload: encrypted with the connection's derived key
//   - sequence: monotonically increasing per connection
//
// Responses are published directly via VsockPublisher to the device's
// response topic, not through the standard reply path.
type DeviceHandler struct {
	ownerSpace       string
	storage          *EncryptedStorage
	publisher        *VsockPublisher
	eventHandler     *EventHandler
	connHandler      *ConnectionsHandler
	pendingApprovals map[string]*PendingDeviceApproval
	mu               sync.Mutex
	stopCleanup      chan struct{}

	// internalDispatch runs an independent-cap device op through the
	// same path the Android client uses (forVault.<op> → handleVaultOp).
	// Wired by MessageHandler init to mh.HandleMessage so device-routed
	// reads return real data instead of the placeholder ack the
	// independent branch used to send.
	internalDispatch func(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error)
}

// SetInternalDispatch wires the callback used by handleDeviceOpRequest
// to execute independent capabilities. Idempotent — last write wins.
func (dh *DeviceHandler) SetInternalDispatch(fn func(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error)) {
	dh.internalDispatch = fn
}

// NewDeviceHandler creates a new device handler.
func NewDeviceHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	publisher *VsockPublisher,
	eventHandler *EventHandler,
	connHandler *ConnectionsHandler,
) *DeviceHandler {
	dh := &DeviceHandler{
		ownerSpace:       ownerSpace,
		storage:          storage,
		publisher:        publisher,
		eventHandler:     eventHandler,
		connHandler:      connHandler,
		pendingApprovals: make(map[string]*PendingDeviceApproval),
		stopCleanup:      make(chan struct{}),
	}
	go dh.cleanExpiredSessions()
	return dh
}

// HandleDeviceMessage is the main router for device messages.
// It decrypts the envelope with the connection key and dispatches.
func (dh *DeviceHandler) HandleDeviceMessage(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var envelope AgentEnvelope
	if err := unmarshalRequest(msg.Payload, &envelope, "HandleDeviceMessage"); err != nil {
		log.Warn().Err(err).Msg("Failed to parse device envelope")
		return nil, nil
	}

	log.Debug().
		Str("type", envelope.Type).
		Str("key_id", envelope.KeyID).
		Uint64("sequence", envelope.Sequence).
		Msg("Received device message")

	// Pairing no longer uses this envelope channel — see DESKTOP-CONNECTION-FLOW.md.
	// Per-operation messages require a valid connection.
	connData, err := dh.storage.Get("connections/" + envelope.KeyID)
	if err != nil {
		log.Warn().Str("key_id", envelope.KeyID).Msg("Device connection not found")
		return nil, nil
	}

	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		log.Warn().Err(err).Msg("Failed to parse device connection record")
		return nil, nil
	}

	// Validate connection
	if !conn.IsDevice() {
		log.Warn().Str("type", conn.GetConnectionType()).Msg("Connection is not a device")
		return nil, nil
	}
	if conn.Status != "active" {
		log.Warn().Str("status", conn.Status).Msg("Device connection not active")
		return nil, nil
	}
	if conn.DeviceSession == nil || conn.DeviceSession.Status != "active" || conn.DeviceSession.SessionKeyID == "" {
		log.Warn().Msg("Device connection has no active session")
		return nil, nil
	}

	// Load the per-session key persisted at HandleDeviceAuthorizeSession
	// time. Device ops encrypt with the session key (rotated on extend),
	// not the long-lived connection-from-shared-secret key the agent
	// flow uses — those are different HKDF derivations and never
	// matched up, which is why every device op was timing out before
	// this fix. Key material stays in enclave memory + encrypted storage.
	keyPath := fmt.Sprintf("device_session_keys/%s/%s", conn.ConnectionID, conn.DeviceSession.SessionKeyID)
	connKey, err := dh.storage.Get(keyPath)
	if err != nil {
		log.Warn().Err(err).Str("path", keyPath).Msg("Failed to load device session key")
		return nil, nil
	}
	if len(connKey) != 32 {
		log.Warn().Int("len", len(connKey)).Msg("Loaded device session key has wrong length")
		return nil, nil
	}
	defer zeroBytes(connKey)

	// Decrypt payload
	encryptedPayload, err := extractPayloadBytes(envelope.Payload)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract device payload bytes")
		return nil, nil
	}

	plaintext, err := decryptXChaCha20(connKey, encryptedPayload)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decrypt device payload")
		return nil, nil
	}
	defer zeroBytes(plaintext)

	// Route by message type
	switch envelope.Type {
	case DeviceMsgOpRequest:
		return dh.handleDeviceOpRequest(ctx, &conn, plaintext, connKey, &envelope)
	default:
		log.Warn().Str("type", envelope.Type).Msg("Unknown device message type")
		return nil, nil
	}
}

// handleDeviceOpRequest checks session validity, phone heartbeat, and capability tier,
// then executes the operation or delegates to phone for approval.
func (dh *DeviceHandler) handleDeviceOpRequest(ctx context.Context, conn *ConnectionRecord, plaintext []byte, connKey []byte, envelope *AgentEnvelope) (*OutgoingMessage, error) {
	var req struct {
		RequestID string          `json:"request_id"`
		Operation string          `json:"operation"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(plaintext, &req); err != nil {
		log.Warn().Err(err).Msg("Failed to parse device op request")
		return nil, nil
	}

	// Check session validity
	if err := dh.checkSession(conn); err != nil {
		dh.publishDeviceResponse(conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
			"request_id": req.RequestID,
			"success":    false,
			"error":      err.Error(),
		})
		return nil, nil
	}

	// PIN operations are NEVER accepted from device connections
	if isPINOperation(req.Operation) {
		log.Warn().
			Str("connection_id", conn.ConnectionID).
			Str("operation", req.Operation).
			Msg("PIN operation rejected from device connection")

		dh.publishDeviceResponse(conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
			"request_id": req.RequestID,
			"success":    false,
			"error":      "PIN operations are not permitted from desktop devices",
		})
		return nil, nil
	}

	// Update session activity
	now := time.Now().Unix()
	if conn.DeviceSession != nil {
		conn.DeviceSession.LastActiveAt = now
	}
	connData, _ := json.Marshal(conn)
	dh.storage.Put("connections/"+conn.ConnectionID, connData)

	// Check capability tier. Secret value reads (secret.get / secrets.get)
	// are phone-required by default, but once this session has been
	// unlocked for secret access (via the phone-approved
	// secret.unlock-session op), they become independent until the
	// grant expires. The grant is capped at the session expiry so it
	// can't outlive the session it came from.
	independent := isIndependentCapability(req.Operation)
	if !independent && (req.Operation == "secret.get" || req.Operation == "secrets.get") {
		if conn.DeviceSession != nil && conn.DeviceSession.SecretsUnlockedUntil > now {
			independent = true
		}
	}
	if independent {
		// Re-enter the main vault-op router with a synthetic
		// forVault subject so the device op goes through the same
		// handler the Android client uses. This is what makes the
		// independent-cap tier actually return data — without it the
		// branch shipped a placeholder ack and the desktop saw
		// success=true / data=nil and surfaced "failed to load".
		if dh.internalDispatch == nil {
			log.Error().Str("op", req.Operation).Msg("internalDispatch not wired — independent device op cannot execute")
			dh.publishDeviceResponse(conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
				"request_id": req.RequestID,
				"operation":  req.Operation,
				"success":    false,
				"error":      "internal dispatch not configured",
			})
			return nil, nil
		}

		innerPayload := req.Payload
		if len(innerPayload) == 0 {
			innerPayload = json.RawMessage("{}")
		}
		syntheticMsg := &IncomingMessage{
			Type:       MessageTypeVaultOp,
			OwnerSpace: dh.ownerSpace,
			RequestID:  req.RequestID,
			Subject:    fmt.Sprintf("OwnerSpace.%s.forVault.%s", dh.ownerSpace, req.Operation),
			Payload:    innerPayload,
		}

		resp, err := dh.internalDispatch(ctx, syntheticMsg)
		respPayload := map[string]interface{}{
			"request_id": req.RequestID,
			"operation":  req.Operation,
		}
		switch {
		case err != nil:
			respPayload["success"] = false
			respPayload["error"] = err.Error()
		case resp == nil:
			respPayload["success"] = false
			respPayload["error"] = "no response from handler"
		case resp.Type == MessageTypeError:
			respPayload["success"] = false
			if resp.Error != "" {
				respPayload["error"] = resp.Error
			} else if len(resp.Payload) > 0 {
				// Some handlers stuff the error into Payload as
				// {"error":"..."}. Surface that string when present
				// so the desktop can show it without parsing.
				var inner struct {
					Error string `json:"error"`
				}
				if json.Unmarshal(resp.Payload, &inner) == nil && inner.Error != "" {
					respPayload["error"] = inner.Error
				} else {
					respPayload["error"] = "handler returned error"
				}
			} else {
				respPayload["error"] = "handler returned error"
			}
		default:
			respPayload["success"] = true
			if len(resp.Payload) > 0 {
				// Pass the handler's JSON payload through as `data`.
				// json.RawMessage marshals back to its original
				// bytes, so the desktop sees the same shape Android
				// does.
				respPayload["data"] = resp.Payload
			}
		}
		dh.publishDeviceResponse(conn, connKey, DeviceMsgOpResponse, respPayload)
		return nil, nil
	}

	// Phone-required operation — delegate to phone for approval
	dh.mu.Lock()
	dh.pendingApprovals[req.RequestID] = &PendingDeviceApproval{
		RequestID:    req.RequestID,
		ConnectionID: conn.ConnectionID,
		Operation:    req.Operation,
		Payload:      req.Payload,
		CreatedAt:    time.Now(),
	}
	dh.mu.Unlock()

	// Log the approval request
	if dh.eventHandler != nil {
		dh.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceApprovalRequested, conn.ConnectionID, "",
			fmt.Sprintf("Device requests approval for: %s", req.Operation))
	}

	// Publish approval request to phone via OwnerSpace
	deviceName := conn.PeerAlias
	if conn.DeviceMetadata != nil && conn.DeviceMetadata.Hostname != "" {
		deviceName = conn.DeviceMetadata.Hostname
	}

	approvalReq := map[string]interface{}{
		"request_id":    req.RequestID,
		"connection_id": conn.ConnectionID,
		"device_name":   deviceName,
		"operation":     req.Operation,
		"payload":       req.Payload,
		"timestamp":     time.Now().UTC(),
	}
	approvalBytes, _ := json.Marshal(approvalReq)

	approvalTopic := fmt.Sprintf("OwnerSpace.%s.forApp.device.approval.request.%s", dh.ownerSpace, req.RequestID)

	// Also notify desktop that approval is pending.
	dh.publishDeviceResponse(conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
		"request_id": req.RequestID,
		"success":    true,
		"status":     "pending_approval",
		"operation":  req.Operation,
	})

	// Publish the approval request to the phone as a standalone
	// vault-initiated NATS publish — NOT as this op's HandleMessage
	// return value. A nats_publish-typed message returned as the op
	// response is demuxed by the supervisor's pipe reader on Type
	// (startPipeReader) and routed to forwardToParent, so it never
	// reaches the ProcessMessage waiting on this op's PipeID — that
	// call then sits out its full 30s opTimeout holding the per-user
	// procMu and stalls every queued op for the user. (That was the
	// ~30s device-approval stall: a phone-required device op did
	// `return pubMsg, nil` here.) Returning nil lets the forOwner
	// router synthesize a proper PipeID-correlated ack.
	if err := dh.publisher.PublishRaw(approvalTopic, approvalBytes); err != nil {
		log.Warn().Err(err).Str("subject", approvalTopic).
			Msg("Failed to publish device approval request to phone")
	}

	return nil, nil
}

// HandlePhoneApprovalResponse processes the phone's approve/deny for delegated operations.
func (dh *DeviceHandler) HandlePhoneApprovalResponse(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var resp struct {
		RequestID string `json:"request_id"`
		Approved  bool   `json:"approved"`
		Reason    string `json:"reason,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &resp, "HandlePhoneApprovalResponse"); err != nil {
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeError,
			Payload:   json.RawMessage(`{"error":"invalid approval response"}`),
		}, nil
	}

	dh.mu.Lock()
	pending, ok := dh.pendingApprovals[resp.RequestID]
	if ok {
		delete(dh.pendingApprovals, resp.RequestID)
	}
	dh.mu.Unlock()

	if !ok {
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   json.RawMessage(`{"success":false,"error":"no pending approval found"}`),
		}, nil
	}

	// Look up connection to send response to desktop
	connData, err := dh.storage.Get("connections/" + pending.ConnectionID)
	if err != nil {
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeError,
			Payload:   json.RawMessage(`{"error":"connection not found"}`),
		}, nil
	}

	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeError,
			Payload:   json.RawMessage(`{"error":"failed to read connection"}`),
		}, nil
	}

	if conn.DeviceSession == nil || conn.DeviceSession.SessionKeyID == "" {
		log.Warn().Msg("Phone approval response — connection has no active session")
		return nil, nil
	}
	keyPath := fmt.Sprintf("device_session_keys/%s/%s", conn.ConnectionID, conn.DeviceSession.SessionKeyID)
	connKey, err := dh.storage.Get(keyPath)
	if err != nil || len(connKey) != 32 {
		log.Warn().Err(err).Str("path", keyPath).Msg("Failed to load device session key for approval response")
		return nil, nil
	}
	defer zeroBytes(connKey)

	if resp.Approved {
		// Log approval
		if dh.eventHandler != nil {
			dh.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceApprovalGranted, conn.ConnectionID, "",
				fmt.Sprintf("Phone approved device operation: %s", pending.Operation))
		}

		// Two paths for executing the approved op:
		//
		//   1. secret.unlock-session: the op IS setting the session
		//      grant — no underlying handler exists. Set
		//      SecretsUnlockedUntil inline, persist, respond.
		//
		//   2. Anything else: re-enter the vault router via
		//      internalDispatch so the actual op runs (mutation,
		//      response payload, etc). Without this, approved ops
		//      came back with status:"approved" but never produced
		//      a result — the desktop saw success but no data and
		//      no state change.
		if pending.Operation == "secret.unlock-session" {
			until := time.Now().Add(time.Duration(conn.DeviceSession.DurationSeconds) * time.Second).Unix()
			// Cap at session expiry so the grant can't outlive
			// the session it came from.
			if until > conn.DeviceSession.ExpiresAt {
				until = conn.DeviceSession.ExpiresAt
			}
			conn.DeviceSession.SecretsUnlockedUntil = until
			updated, _ := json.Marshal(&conn)
			if err := dh.storage.Put("connections/"+conn.ConnectionID, updated); err != nil {
				log.Warn().Err(err).Msg("Failed to persist secret-unlock grant (non-fatal)")
			}
			dh.publishDeviceResponse(&conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
				"request_id": pending.RequestID,
				"operation":  pending.Operation,
				"success":    true,
				"status":     "executed",
				"unlocked_until": until,
			})
		} else if dh.internalDispatch != nil {
			innerPayload := pending.Payload
			if len(innerPayload) == 0 {
				innerPayload = json.RawMessage("{}")
			}
			synthMsg := &IncomingMessage{
				Type:       MessageTypeVaultOp,
				OwnerSpace: dh.ownerSpace,
				RequestID:  pending.RequestID,
				Subject:    fmt.Sprintf("OwnerSpace.%s.forVault.%s", dh.ownerSpace, pending.Operation),
				Payload:    innerPayload,
			}
			execResp, execErr := dh.internalDispatch(ctx, synthMsg)
			respPayload := map[string]interface{}{
				"request_id": pending.RequestID,
				"operation":  pending.Operation,
			}
			switch {
			case execErr != nil:
				respPayload["success"] = false
				respPayload["error"] = execErr.Error()
			case execResp == nil:
				respPayload["success"] = false
				respPayload["error"] = "no response from handler"
			case execResp.Type == MessageTypeError:
				respPayload["success"] = false
				if execResp.Error != "" {
					respPayload["error"] = execResp.Error
				} else if len(execResp.Payload) > 0 {
					var inner struct {
						Error string `json:"error"`
					}
					if json.Unmarshal(execResp.Payload, &inner) == nil && inner.Error != "" {
						respPayload["error"] = inner.Error
					} else {
						respPayload["error"] = "handler returned error"
					}
				} else {
					respPayload["error"] = "handler returned error"
				}
			default:
				respPayload["success"] = true
				if len(execResp.Payload) > 0 {
					respPayload["data"] = execResp.Payload
				}
			}
			dh.publishDeviceResponse(&conn, connKey, DeviceMsgOpResponse, respPayload)
		} else {
			// Should be unreachable — internalDispatch is wired at
			// MessageHandler init. Fall through to the legacy ack so
			// the desktop at least sees the approval status if this
			// somehow fires.
			log.Error().Msg("Phone approval: internalDispatch not wired — falling back to legacy ack")
			dh.publishDeviceResponse(&conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
				"request_id": pending.RequestID,
				"success":    true,
				"status":     "approved",
				"operation":  pending.Operation,
			})
		}
	} else {
		// Log denial
		if dh.eventHandler != nil {
			dh.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceApprovalDenied, conn.ConnectionID, "",
				fmt.Sprintf("Phone denied device operation: %s", pending.Operation))
		}

		dh.publishDeviceResponse(&conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
			"request_id": pending.RequestID,
			"success":    false,
			"status":     "denied",
			"operation":  pending.Operation,
			"reason":     resp.Reason,
		})
	}

	respPayload, _ := json.Marshal(map[string]interface{}{
		"success":    true,
		"request_id": resp.RequestID,
		"approved":   resp.Approved,
	})

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respPayload,
	}, nil
}

// HandleListPendingApprovals returns the device-operation approvals
// currently awaiting this owner's decision.
//
// The approval REQUEST is delivered to the phone over a core-NATS
// forApp.* subject — no replay. A phone that was killed (or merely
// offline) when the desktop made the request never sees it. This op
// lets the phone pull the authoritative pending set from the vault on
// every NATS (re)connect and rebuild its approval UI, so a request is
// never silently lost. Subject: OwnerSpace.{guid}.forVault.device.approval-pending.
//
// Stale entries (older than 5 min — well past the desktop's ~60s wait)
// are filtered out so the phone isn't shown approvals no desktop is
// still waiting on. The 10-minute sweep in doCleanExpiredSessions is
// the hard bound; this is just presentation hygiene.
func (dh *DeviceHandler) HandleListPendingApprovals(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	const freshWindow = 5 * time.Minute
	now := time.Now()

	dh.mu.Lock()
	pending := make([]map[string]interface{}, 0, len(dh.pendingApprovals))
	for _, p := range dh.pendingApprovals {
		if now.Sub(p.CreatedAt) > freshWindow {
			continue
		}
		pending = append(pending, map[string]interface{}{
			"request_id":    p.RequestID,
			"connection_id": p.ConnectionID,
			"operation":     p.Operation,
			"payload":       p.Payload,
			"timestamp":     p.CreatedAt.UTC(),
		})
	}
	dh.mu.Unlock()

	respPayload, err := json.Marshal(map[string]interface{}{
		"success": true,
		"pending": pending,
	})
	if err != nil {
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeError,
			Payload:   json.RawMessage(`{"error":"failed to marshal pending approvals"}`),
		}, nil
	}
	log.Debug().Str("owner_space", dh.ownerSpace).Int("pending", len(pending)).
		Msg("device: served pending-approvals list to phone")
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respPayload,
	}, nil
}

// checkSession validates that the device session is active and not expired.
// Wall-clock expiry is the only bound — there's no heartbeat requirement
// under the new design (see DESKTOP-CONNECTION-FLOW.md).
func (dh *DeviceHandler) checkSession(conn *ConnectionRecord) error {
	if conn.DeviceSession == nil {
		return fmt.Errorf("no active device session")
	}

	session := conn.DeviceSession

	switch session.Status {
	case "revoked":
		return fmt.Errorf("session has been revoked")
	case "expired":
		return fmt.Errorf("session has expired")
	}

	// Check expiration
	now := time.Now().Unix()
	if now > session.ExpiresAt {
		session.Status = "expired"
		connData, _ := json.Marshal(conn)
		dh.storage.Put("connections/"+conn.ConnectionID, connData)

		if dh.eventHandler != nil {
			dh.eventHandler.LogConnectionEvent(context.Background(), EventTypeDeviceSessionExpired, conn.ConnectionID, "",
				"Device session expired")
		}
		return fmt.Errorf("session has expired")
	}

	return nil
}

// cleanExpiredSessions runs every minute and cleans up expired device sessions.
func (dh *DeviceHandler) cleanExpiredSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dh.doCleanExpiredSessions()
		case <-dh.stopCleanup:
			return
		}
	}
}

func (dh *DeviceHandler) doCleanExpiredSessions() {
	indexData, err := dh.storage.Get("connections/_index")
	if err != nil {
		return
	}

	var connectionIDs []string
	json.Unmarshal(indexData, &connectionIDs)

	now := time.Now().Unix()
	for _, connID := range connectionIDs {
		data, err := dh.storage.Get("connections/" + connID)
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		if !record.IsDevice() || record.DeviceSession == nil {
			continue
		}

		session := record.DeviceSession

		// Expire active sessions past their wall-clock deadline
		if session.Status == "active" && now > session.ExpiresAt {
			session.Status = "expired"

			// Wipe the session key from storage
			if session.SessionKeyID != "" {
				keyPath := fmt.Sprintf("device_session_keys/%s/%s", record.ConnectionID, session.SessionKeyID)
				_ = dh.storage.Delete(keyPath)
			}

			connData, _ := json.Marshal(record)
			dh.storage.Put("connections/"+record.ConnectionID, connData)

			if dh.eventHandler != nil {
				dh.eventHandler.LogConnectionEvent(context.Background(), EventTypeDeviceSessionExpired, record.ConnectionID, "",
					"Device session expired (cleanup)")
			}

			log.Info().
				Str("connection_id", record.ConnectionID).
				Str("session_id", session.SessionID).
				Msg("Device session expired during cleanup")
		}
	}

	// Clean up stale pending approvals (older than 10 minutes)
	dh.mu.Lock()
	for id, pending := range dh.pendingApprovals {
		if time.Since(pending.CreatedAt) > 10*time.Minute {
			delete(dh.pendingApprovals, id)
		}
	}
	dh.mu.Unlock()
}

// publishDeviceResponse encrypts and publishes a response to the device's topic.
func (dh *DeviceHandler) publishDeviceResponse(conn *ConnectionRecord, connKey []byte, msgType string, payload interface{}) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal device response")
		return
	}

	encrypted, err := encryptXChaCha20(connKey, payloadBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt device response")
		return
	}
	zeroBytes(payloadBytes)

	encPayloadJSON, _ := json.Marshal(encrypted)
	envBytes, _ := json.Marshal(AgentEnvelope{
		Type:      msgType,
		KeyID:     conn.ConnectionID,
		Payload:   encPayloadJSON,
		Timestamp: time.Now().UTC(),
	})

	// Publish on the forApp side (mirrors the activated/ended/revoked
	// pattern from device_pairing.go) so the parent's broad
	// `MessageSpace.*.forOwner.>` subscription doesn't re-ingest the
	// vault's own response and trip replay-detection. The NATS
	// credentials issued in nats_credentials.go already grant the
	// device account subscribe access to forApp.device.{conn}.> with
	// the matching comment ("operation responses for this
	// connection"), so this is the subject the architecture intended
	// — the prior `forOwner.device.{conn}` was a wire-contract bug
	// that produced steady replay-detected noise (which then tripped
	// deploy.sh's Phase 4.5 journal scan).
	topic := fmt.Sprintf("MessageSpace.%s.forApp.device.%s.response", dh.ownerSpace, conn.ConnectionID)
	dh.publisher.PublishRaw(topic, envBytes)
}

// Stop shuts down the background cleanup goroutine.
func (dh *DeviceHandler) Stop() {
	close(dh.stopCleanup)
}

// --- Crypto helpers ---

// decryptECIESDeviceDomain decrypts ECIES data from a device using the device domain.
// Format: ephemeral_pubkey (32) || nonce (24) || ciphertext+tag
func decryptECIESDeviceDomain(privateKey []byte, data []byte) ([]byte, error) {
	minSize := 32 + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	if len(data) < minSize {
		return nil, fmt.Errorf("ECIES data too short: need at least %d bytes, got %d", minSize, len(data))
	}

	ephPub := data[:32]
	nonce := data[32 : 32+chacha20poly1305.NonceSizeX]
	ciphertext := data[32+chacha20poly1305.NonceSizeX:]

	// SECURITY (#83): wire-side ephemeral pub key — refuse small-order
	// points before the ECDH so a malicious device can't probe the
	// vault's long-lived device key via contributory behavior.
	sharedSecret, err := safeX25519(privateKey, ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH key exchange: %w", err)
	}
	defer zeroBytes(sharedSecret)

	// HKDF with device domain (distinct from agent domain)
	r := hkdf.New(sha256.New, sharedSecret, []byte(DomainDevice), nil)
	encKey := make([]byte, 32)
	if _, err := io.ReadFull(r, encKey); err != nil {
		return nil, fmt.Errorf("HKDF derive: %w", err)
	}
	defer zeroBytes(encKey)

	// XChaCha20-Poly1305
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	// SECURITY (#72): try domainCryptoAADv1 first, fall back to nil
	// AAD for pre-#72 ciphertexts.
	plaintext, err := aeadOpenWithLegacyFallback(aead, nonce, ciphertext, domainCryptoAADv1)
	if err != nil {
		return nil, fmt.Errorf("ECIES decrypt: %w", err)
	}

	return plaintext, nil
}
