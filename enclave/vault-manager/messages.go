package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// MessageType represents the type of message from the supervisor
type MessageType string

const (
	// Vault operations
	MessageTypeVaultOp     MessageType = "vault_op"
	MessageTypeStorageGet  MessageType = "storage_get"
	MessageTypeStoragePut  MessageType = "storage_put"
	MessageTypeNATSPublish MessageType = "nats_publish"

	// HTTP proxy (vault-manager -> supervisor -> parent -> internet)
	MessageTypeHTTPRequest  MessageType = "http_request"
	MessageTypeHTTPResponse MessageType = "http_response"

	// Responses
	MessageTypeResponse        MessageType = "response"
	MessageTypeError           MessageType = "error"
	MessageTypeStorageResponse MessageType = "storage_response" // From parent for S3 operations

	// Routing handoff (vault-manager -> supervisor -> parent):
	// emitted after a successful credential.migration.start re-seal
	// so the parent can transfer ownership in the routing KV. Use
	// TargetInstanceID="" for release-for-reclaim semantics.
	MessageTypeRoutingHandoff MessageType = "routing_handoff"

	// Revoke ownership (supervisor -> vault-manager): the parent's
	// RoutingManager lost this user's routing claim. Intercepted in
	// receiveMessages and applied immediately (NOT routed through
	// HandleMessage) so it lands even while the main loop is blocked
	// mid-request. Sets ownershipRevoked, which fences off all
	// vault_state.enc persistence and refuses new ops. See the
	// split-brain fix (D2, 2026-05-14).
	MessageTypeRevokeOwnership MessageType = "revoke_ownership"
)

// IncomingMessage is a message from the supervisor/parent
// Field names match the supervisor's Message struct for JSON compatibility
type IncomingMessage struct {
	// Core fields - aligned with supervisor's Message struct
	Type       MessageType     `json:"type"`
	OwnerSpace string          `json:"owner_space,omitempty"`
	RequestID  string          `json:"request_id,omitempty"` // Matches supervisor's RequestID
	// PipeID is the supervisor's pipe-transport correlation token. The
	// main loop echoes it verbatim onto the op's response so the
	// supervisor's per-VaultProcess pipe reader can route that response
	// to the right waiting op. Opaque to handlers — do not interpret.
	PipeID     string          `json:"pipe_id,omitempty"`
	Subject    string          `json:"subject,omitempty"` // NATS subject
	ReplyTo    string          `json:"reply_to,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`

	// PayloadType holds the original message type from the app envelope.
	// The parent process preserves the envelope: {"type":"X","payload":{...}}
	// Central unwrapping in handleVaultOp extracts the type here and sets
	// Payload to just the inner content, so handlers get flat data.
	PayloadType string `json:"-"` // Not serialized — set by unwrapPayload

	// Attestation private key for PIN decryption
	// SECURITY: Only included for PIN operations, supervisor provides this
	AttestationPrivateKey []byte `json:"attestation_private_key,omitempty"`

	// Legacy field for backward compatibility
	ID string `json:"id,omitempty"` // Fallback if RequestID not set
}

// GetID returns the message ID, preferring RequestID over ID
func (m *IncomingMessage) GetID() string {
	if m.RequestID != "" {
		return m.RequestID
	}
	return m.ID
}

// OutgoingMessage is a message to the supervisor/parent
// Field names match the supervisor's Message struct for JSON compatibility
type OutgoingMessage struct {
	Type       MessageType     `json:"type"`
	OwnerSpace string          `json:"owner_space,omitempty"`
	RequestID  string          `json:"request_id,omitempty"` // Matches supervisor's RequestID
	// PipeID echoes the incoming op's supervisor pipe-transport token
	// (set by the main loop on op responses; see IncomingMessage.PipeID).
	PipeID     string          `json:"pipe_id,omitempty"`
	Subject    string          `json:"subject,omitempty"`
	ReplyTo    string          `json:"reply_to,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Error      string          `json:"error,omitempty"`

	// Routing handoff fields (see MessageTypeRoutingHandoff)
	TargetInstanceID string `json:"target_instance_id,omitempty"`
	NewPCR0          string `json:"new_pcr0,omitempty"`

	// Legacy field for backward compatibility
	ID string `json:"id,omitempty"`
}

// MessageHandler processes incoming messages
type MessageHandler struct {
	ownerSpace           string
	storage              *EncryptedStorage
	callHandler          *CallHandler
	secretsHandler       *SecretsHandler
	profileHandler       *ProfileHandler
	personalDataHandler  *PersonalDataHandler
	credentialHandler    *CredentialHandler
	messagingHandler     *MessagingHandler
	connectionsHandler       *ConnectionsHandler
	notificationsHandler     *NotificationsHandler
	credentialSecretHandler  *CredentialSecretHandler
	eventHandler             *EventHandler
	publisher                *VsockPublisher

	// Per-connection audit trail (docs/CONNECTION-AUDIT-TRAIL-PLAN.md).
	// auditLog is used by write-points across handlers; auditHandler
	// serves connection.audit.list / .search.
	auditLog     *AuditLog
	auditHandler *AuditHandler

	// NATS proxy for connection credential generation
	natsProxy *NATSProxy

	// HTTP proxy for external HTTP requests through parent
	httpProxy *HTTPProxy

	// Cryptographic state and handlers for Phase 4
	vaultState               *VaultState
	bootstrapHandler         *BootstrapHandler
	pinHandler               *PINHandler
	proteanCredentialHandler *ProteanCredentialHandler
	sealerProxy              *SealerProxy

	// Voting handler for vault-signed votes
	voteHandler *VoteHandler

	// Migration handler for migration status, acknowledgment, and recovery
	migrationHandler *MigrationHandler

	// Usability feature handlers
	invitationsHandler *InvitationsHandler
	capabilityHandler  *CapabilityHandler
	settingsHandler    *SettingsHandler

	// Service connection handlers (B2C)
	serviceConnectionHandler  *ServiceConnectionHandler
	serviceContractsHandler   *ServiceContractsHandler
	serviceDataHandler        *ServiceDataHandler
	serviceRequestsHandler    *ServiceRequestsHandler
	serviceResourcesHandler   *ServiceResourcesHandler
	serviceActivityHandler      *ServiceActivityHandler      // Phase 7: Activity & Transparency
	serviceNotificationsHandler *ServiceNotificationsHandler // Phase 8: Notifications & Trust
	serviceOfflineHandler       *ServiceOfflineHandler       // Phase 9: Offline Support

	// Combined datastore handler (Phase 4: Advanced Features)
	combinedDatastoreHandler  *CombinedDatastoreHandler
	datastoreAccessController *DatastoreAccessController
	datastoreAuditHandler     *DatastoreAuditHandler

	// Guide handler (welcome/tutorial events)
	guideHandler *GuideHandler

	// Location handler (location tracking)
	locationHandler *LocationHandler

	// Presence handler (opt-in online/offline signal to peers)
	presenceHandler *PresenceHandler

	// Grant handler (reference-based data sharing — Phase 1 of
	// plans/data-request-grants.md).
	grantHandler *GrantHandler

	// Critical-secret use-on-my-behalf — Phase 6.
	criticalSecretUseHandler *CriticalSecretHandler

	// Agent handlers (AI agent connections)
	agentHandler        *AgentHandler
	agentSecretsHandler *AgentSecretsHandler

	// LEASH token issuer (scoped, time-bound, version-bound delegation
	// JWTs for agent connections — see docs/LEASH-TOKEN-FORMAT.md).
	leashHandler *LeashHandler

	// Device handler (desktop device connections)
	deviceHandler *DeviceHandler

	// Bitcoin wallet handler
	walletHandler *WalletHandler

	// Handler authorization (user-controlled enable/share toggles +
	// per-connection grants). See handler_authorization.go. Populated
	// after PIN unlock; the gate is fail-closed before that.
	handlerAuthMu     sync.RWMutex
	handlerAuthState  *HandlerState
	handlerAuthGrants map[string]*ConnectionHandlerGrants

	// Shared-action layer (action_*.go). EnabledActions tracks per-action
	// auth-mode + allowlist for the new invoke-action wire protocol;
	// pendingApprovals is the durable queue of prompt-each-time
	// invocations awaiting owner decision.
	enabledActions   *EnabledActionState
	pendingApprovals *ActionPendingApprovalQueue

	// Auto-persist throttle. main.go's request loop persists after
	// every successful message, plus several handlers add their own
	// explicit persistVaultStateToS3() calls — a single user session
	// can produce hundreds of writes per minute against the same
	// vault_state.enc key. The bucket accumulated ~4800 noncurrent
	// versions of vault_state.enc (~1 GB) over 30 days as a result.
	// persistMu + lastPersistTime throttle non-forced calls to at
	// most one S3 PUT per persistDebounceInterval; the exported
	// PersistVaultStateToS3 (shutdown path) bypasses the throttle so
	// no data is left in memory at exit.
	persistMu       sync.Mutex
	lastPersistTime time.Time
}

// persistDebounceInterval bounds the rate of vault_state.enc writes.
// Set to 15 s as a balance: short enough that a crash during a single
// user session loses at most one session's-worth of edits since the
// last persist; long enough to coalesce bursts of mutations (profile
// updates, secret edits, message sends, presence ticks) that today
// each trigger their own redundant write.
const persistDebounceInterval = 15 * time.Second

// VsockPublisher implements CallPublisher using vsock to parent
type VsockPublisher struct {
	ownerSpace string
	sendFn     func(msg *OutgoingMessage) error

	// listDeviceConnections returns the connection IDs of every
	// currently-active device-type connection (paired desktops, agents).
	// Set after construction via SetDeviceLister — keeps the publisher's
	// constructor signature free of storage coupling so tests can mock
	// publishing without a real connection store. nil means no fan-out
	// (early boot or unit-test path).
	listDeviceConnections func() []string

	// Short-TTL cache so PublishToApp's hot path doesn't hit storage
	// on every call. Without this, high-frequency forApp events
	// (presence heartbeats, feed updates, profile broadcasts) would
	// re-scan `connections/_index` plus each `connections/{id}` per
	// publish — under load this serialized through the storage
	// mutex and pushed phone-side request/reply round-trips past
	// their 15 s timeout. A 5 s TTL means a newly-paired desktop
	// gets events ≤ 5 s late on first event, which is invisible to
	// the user, while taking the per-publish cost from O(N reads)
	// down to a single cached slice read.
	deviceCacheMu    sync.RWMutex
	deviceCacheList  []string
	deviceCacheUntil time.Time
}

const deviceListCacheTTL = 5 * time.Second

// NewVsockPublisher creates a new publisher that sends via vsock
func NewVsockPublisher(ownerSpace string, sendFn func(msg *OutgoingMessage) error) *VsockPublisher {
	return &VsockPublisher{
		ownerSpace: ownerSpace,
		sendFn:     sendFn,
	}
}

// SetDeviceLister wires the active-device-connection enumerator.
// Called once during MessageHandler init after storage is ready.
// Without this, PublishToApp behaves as before (OwnerSpace only).
func (p *VsockPublisher) SetDeviceLister(fn func() []string) {
	p.listDeviceConnections = fn
}

// PublishToApp sends an event to the owner's app via the forApp channel.
//
// Fan-out model (Phase 2 separation):
//   - Phones subscribe to OwnerSpace.{owner}.forApp.> — that's still
//     the single source of truth for the phone side.
//   - Desktops subscribe ONLY to MessageSpace.{owner}.forApp.device.
//     {conn}.> — they no longer share the OwnerSpace bus with phones.
//
// To keep both clients informed, every forApp event is now mirrored
// onto each active device connection's MessageSpace channel. This
// keeps the desktop event stream narrow (only what targets it) and
// removes the phone↔desktop subject overlap that caused duplicate
// dispatch and per-device noise.
func (p *VsockPublisher) PublishToApp(ctx context.Context, eventType string, payload []byte) error {
	primary := fmt.Sprintf("OwnerSpace.%s.forApp.%s", p.ownerSpace, eventType)

	log.Debug().
		Str("subject", primary).
		Msg("Publishing to app")

	if err := p.sendFn(&OutgoingMessage{
		ID:      generateMessageID(),
		Type:    MessageTypeNATSPublish,
		Subject: primary,
		Payload: payload,
	}); err != nil {
		return err
	}

	// Fan out to each active device connection. Failures here are
	// non-fatal — the phone publish above already succeeded, and a
	// device with a transient publish error will catch up on its
	// next subscription event (most events have a follow-up trigger).
	for _, connID := range p.cachedDeviceConnections() {
		deviceSubject := fmt.Sprintf("MessageSpace.%s.forApp.device.%s.%s", p.ownerSpace, connID, eventType)
		if err := p.sendFn(&OutgoingMessage{
			ID:      generateMessageID(),
			Type:    MessageTypeNATSPublish,
			Subject: deviceSubject,
			Payload: payload,
		}); err != nil {
			log.Warn().Err(err).Str("subject", deviceSubject).Msg("Device fan-out publish failed (non-fatal)")
		}
	}

	return nil
}

// cachedDeviceConnections returns the active device-connection list,
// refreshing from the underlying lister only if the cached snapshot
// is past its TTL. Read-locked fast path; only takes the write lock
// when the cache actually needs to be refilled. Returns an empty
// slice if no lister has been wired (early-boot / unit-test path).
func (p *VsockPublisher) cachedDeviceConnections() []string {
	p.deviceCacheMu.RLock()
	if p.listDeviceConnections == nil {
		p.deviceCacheMu.RUnlock()
		return nil
	}
	if time.Now().Before(p.deviceCacheUntil) {
		out := p.deviceCacheList
		p.deviceCacheMu.RUnlock()
		return out
	}
	p.deviceCacheMu.RUnlock()

	p.deviceCacheMu.Lock()
	defer p.deviceCacheMu.Unlock()
	// Re-check under the write lock in case another goroutine
	// already refreshed while we were upgrading.
	if time.Now().Before(p.deviceCacheUntil) {
		return p.deviceCacheList
	}
	fresh := p.listDeviceConnections()
	p.deviceCacheList = fresh
	p.deviceCacheUntil = time.Now().Add(deviceListCacheTTL)
	return fresh
}

// InvalidateDeviceCache forces the next PublishToApp to re-read the
// active-connection list rather than waiting out the TTL. Call when
// the active set is known to have changed (a device just authorized,
// revoked, or ended a session) so the event reaches/skips it
// immediately. Cheap when uncontested.
func (p *VsockPublisher) InvalidateDeviceCache() {
	p.deviceCacheMu.Lock()
	p.deviceCacheUntil = time.Time{}
	p.deviceCacheMu.Unlock()
}

// PublishToVault sends event to another vault via forVault channel
func (p *VsockPublisher) PublishToVault(ctx context.Context, targetOwnerSpace string, eventType string, payload []byte) error {
	subject := fmt.Sprintf("OwnerSpace.%s.forVault.%s", targetOwnerSpace, eventType)

	msg := &OutgoingMessage{
		ID:      generateMessageID(),
		Type:    MessageTypeNATSPublish,
		Subject: subject,
		Payload: payload,
	}

	log.Debug().
		Str("subject", subject).
		Str("target", targetOwnerSpace).
		Msg("Publishing to vault")

	return p.sendFn(msg)
}

// listActiveDeviceConnectionIDs returns the IDs of every device-type
// connection that has an active session — what PublishToApp uses to
// pick fan-out targets for the device MessageSpace mirror. Storage
// is hit on every PublishToApp call; the connection list is small
// (paired desktops + agents, typically 0–3 entries) so we just read
// it fresh each time rather than caching with invalidation.
func listActiveDeviceConnectionIDs(storage *EncryptedStorage) []string {
	indexData, err := storage.Get("connections/_index")
	if err != nil {
		return nil
	}
	var ids []string
	if err := json.Unmarshal(indexData, &ids); err != nil {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		data, err := storage.Get("connections/" + id)
		if err != nil {
			continue
		}
		var rec ConnectionRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		if !rec.IsDevice() {
			continue
		}
		// Active session only — no point shouting at a paired-but-
		// disconnected device that won't have a subscriber listening.
		if rec.DeviceSession == nil || rec.DeviceSession.Status != "active" {
			continue
		}
		out = append(out, rec.ConnectionID)
	}
	return out
}

// PublishRaw sends a raw message to an arbitrary subject
func (p *VsockPublisher) PublishRaw(subject string, payload []byte) error {
	msg := &OutgoingMessage{
		ID:      generateMessageID(),
		Type:    MessageTypeNATSPublish,
		Subject: subject,
		Payload: payload,
	}

	log.Debug().
		Str("subject", subject).
		Msg("Publishing raw message")

	return p.sendFn(msg)
}

// NewMessageHandler creates a new message handler
func NewMessageHandler(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher, sendFn func(msg *OutgoingMessage) error) *MessageHandler {
	// Create vault state - this holds all cryptographic material in memory
	vaultState := NewVaultState()

	// Create sealer proxy for KMS-dependent operations
	// The sendFn allows the proxy to request KMS operations from the supervisor
	sealerProxy := NewSealerProxy(ownerSpace, sendFn)

	// Create bootstrap handler - generates CEK/UTK pairs
	bootstrapHandler := NewBootstrapHandler(ownerSpace, vaultState)

	// Create NATS proxy for credential generation (needed by PIN handler and connections handler)
	natsEndpoint := os.Getenv("NATS_ENDPOINT")
	natsProxy := NewNATSProxy(ownerSpace, natsEndpoint)

	// Create PIN handler - handles PIN setup/unlock/change using the sealer proxy
	// Storage is passed so DEK can initialize the encrypted SQLite database
	// NATSProxy is passed so vault can issue full NATS credentials after PIN verification
	pinHandler := NewPINHandler(ownerSpace, vaultState, bootstrapHandler, sealerProxy, storage, natsProxy)

	// Create Protean Credential handler - handles credential creation (Phase 3)
	proteanCredentialHandler := NewProteanCredentialHandler(ownerSpace, vaultState, bootstrapHandler)
	proteanCredentialHandler.SetStorage(storage)

	// Create vote handler for vault-signed voting
	voteHandler := NewVoteHandler(ownerSpace, vaultState, storage, bootstrapHandler)
	voteHandler.SetSealerProxy(sealerProxy)

	// Create event handler for unified audit logging and feed
	// NOTE: Must be created before handlers that depend on it for logging
	eventHandler := NewEventHandler(ownerSpace, storage, publisher)

	// Create credential secret handler for critical secrets
	credentialSecretHandler := NewCredentialSecretHandler(ownerSpace, storage, vaultState, bootstrapHandler, eventHandler)
	credentialSecretHandler.SetPublisher(publisher)
	// Minor-secrets handler shares the same publisher + vaultState so
	// every add/update/delete republishes the catalog automatically.
	minorSecretsHandler := NewSecretsHandler(ownerSpace, storage)
	minorSecretsHandler.SetPublisher(publisher)
	minorSecretsHandler.SetVaultState(vaultState)

	// Create migration handler for migration status and recovery
	migrationHandler := NewMigrationHandler(ownerSpace, storage, vaultState, sealerProxy)

	// Wire migration handler into pin handler so HandlePINUnlock can
	// drive the M1 PIN-coupled re-seal when migrate_consent=true.
	pinHandler.SetMigrationHandler(migrationHandler)

	// Create profile handler (needed by service contracts)
	profileHandler := NewProfileHandler(ownerSpace, storage)
	profileHandler.SetPublisher(publisher)
	profileHandler.SetVaultState(vaultState)

	// Create personal data handler (separate from profile for clarity)
	personalDataHandler := NewPersonalDataHandler(ownerSpace, storage)

	// Create service connection handlers (B2C)
	serviceConnectionHandler := NewServiceConnectionHandler(ownerSpace, storage, eventHandler, profileHandler)
	serviceContractsHandler := NewServiceContractsHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler, profileHandler)
	serviceDataHandler := NewServiceDataHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler, serviceContractsHandler, profileHandler)
	serviceRequestsHandler := NewServiceRequestsHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler, serviceContractsHandler)
	serviceResourcesHandler := NewServiceResourcesHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler)
	serviceActivityHandler := NewServiceActivityHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler)
	serviceNotificationsHandler := NewServiceNotificationsHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler)
	serviceOfflineHandler := NewServiceOfflineHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler)

	// Create combined datastore handler (Phase 4)
	combinedDatastoreHandler := NewCombinedDatastoreHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler, publisher)
	datastoreAccessController := NewDatastoreAccessController(ownerSpace, storage, eventHandler, combinedDatastoreHandler, publisher)
	datastoreAuditHandler := NewDatastoreAuditHandler(ownerSpace, storage, combinedDatastoreHandler)

	// Create agent secrets handler
	agentSecretsHandler := NewAgentSecretsHandler(ownerSpace, storage, eventHandler)

	// Create HTTP proxy for external HTTP requests through parent
	httpProxy := NewHTTPProxy(ownerSpace, sendFn)

	// Create connections handler (needed for agent handler)
	connectionsHandler := NewConnectionsHandler(ownerSpace, storage, eventHandler, natsProxy, publisher, vaultState)
	connectionsHandler.SetSealerProxy(sealerProxy)

	// Create agent handler
	agentHandler := NewAgentHandler(ownerSpace, storage, publisher, eventHandler, connectionsHandler, agentSecretsHandler)

	// Create device handler
	deviceHandler := NewDeviceHandler(ownerSpace, storage, publisher, eventHandler, connectionsHandler)

	// Create LEASH handler (agent delegation JWT issuer)
	leashHandler := NewLeashHandler(ownerSpace, storage, vaultState, sealerProxy)

	mh := &MessageHandler{
		ownerSpace:           ownerSpace,
		storage:              storage,
		callHandler:          NewCallHandler(ownerSpace, storage, publisher, eventHandler, vaultState, sealerProxy),
		secretsHandler:       minorSecretsHandler,
		profileHandler:       profileHandler,
		personalDataHandler:  personalDataHandler,
		credentialHandler:    NewCredentialHandler(ownerSpace, storage),
		messagingHandler:     NewMessagingHandler(ownerSpace, storage, publisher, eventHandler),
		connectionsHandler:      connectionsHandler,
		notificationsHandler:    NewNotificationsHandler(ownerSpace, storage, publisher),
		credentialSecretHandler: credentialSecretHandler,
		eventHandler:            eventHandler,
		publisher:               publisher,

		// Audit trail (audit_log.go / audit_handler.go / audit_backfill.go).
		// The handler reads, the log writes; backfiller synthesizes
		// history from messages + feed + lifecycle on first read per
		// connection.
		auditLog: NewAuditLog(storage),

		// NATS proxy
		natsProxy: natsProxy,

		// HTTP proxy
		httpProxy: httpProxy,

		// Cryptographic components
		vaultState:               vaultState,
		bootstrapHandler:         bootstrapHandler,
		pinHandler:               pinHandler,
		proteanCredentialHandler: proteanCredentialHandler,
		sealerProxy:              sealerProxy,

		// Voting
		voteHandler: voteHandler,

		// Migration
		migrationHandler: migrationHandler,

		// Usability feature handlers
		invitationsHandler: NewInvitationsHandler(ownerSpace, storage),
		capabilityHandler:  NewCapabilityHandler(ownerSpace, storage, publisher, eventHandler),
		settingsHandler:    NewSettingsHandler(ownerSpace, storage),

		// Service connection handlers (B2C)
		serviceConnectionHandler:  serviceConnectionHandler,
		serviceContractsHandler:   serviceContractsHandler,
		serviceDataHandler:        serviceDataHandler,
		serviceRequestsHandler:    serviceRequestsHandler,
		serviceResourcesHandler:   serviceResourcesHandler,
		serviceActivityHandler:      serviceActivityHandler,
		serviceNotificationsHandler: serviceNotificationsHandler,
		serviceOfflineHandler:       serviceOfflineHandler,

		// Combined datastore (Phase 4)
		combinedDatastoreHandler:  combinedDatastoreHandler,
		datastoreAccessController: datastoreAccessController,
		datastoreAuditHandler:     datastoreAuditHandler,

		// Guide handler
		guideHandler: NewGuideHandler(ownerSpace, storage, eventHandler),

		// Location handler
		locationHandler: NewLocationHandler(ownerSpace, storage, publisher),

		// Grant handler (data request/grant flow)
		grantHandler: NewGrantHandler(ownerSpace, storage, publisher),

		// Critical-secret use-on-my-behalf handler
		criticalSecretUseHandler: NewCriticalSecretHandler(ownerSpace, storage, publisher),

		// Agent handlers
		agentHandler:        agentHandler,
		agentSecretsHandler: agentSecretsHandler,

		// Device handler
		deviceHandler: deviceHandler,
		leashHandler:  leashHandler,

		// Bitcoin wallet handler
		walletHandler: NewWalletHandler(ownerSpace, storage, vaultState, eventHandler, publisher, httpProxy),
	}

	// Presence handler — needs ConnectionsHandler to read the
	// connection list during the heartbeat loop, so it's wired up
	// after the struct literal above has ConnectionsHandler populated.
	mh.presenceHandler = NewPresenceHandler(ownerSpace, storage, publisher, mh.connectionsHandler)

	// Wire the routing-handoff callback so the parent can update the
	// vault-routing KV after a successful migration re-seal.
	// NOTE: migration intentionally has no persist callback. Re-sealing
	// only touches sealed_material.bin / sealed_ecies.bin, never
	// vault_state.enc. See SECURITY comment in HandleStart.
	migrationHandler.SetSendToParent(sendFn)

	// Wire device-handler's independent-cap dispatch to re-enter
	// HandleMessage. Closing over mh so the device path picks up any
	// fields populated later (presenceHandler, auditHandler) without
	// needing to be re-wired. Without this, device ops in the
	// independent tier publish a placeholder ack instead of the
	// real op result — desktop sees success=true/data=nil and the
	// frontend surfaces "failed to load".
	deviceHandler.SetInternalDispatch(func(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
		return mh.HandleMessage(ctx, msg)
	})

	// Audit read-path wiring: handler reads, log writes. No backfill —
	// connections created before this feature shipped will have empty
	// history by design.
	mh.auditHandler = NewAuditHandler(ownerSpace, mh.auditLog)
	// Per-handler audit wiring. Each handler that produces
	// user-visible events gets a reference to the same AuditLog so
	// write points stay local rather than centralized.
	mh.messagingHandler.SetAuditLog(mh.auditLog)
	// ConnectionsHandler audits lifecycle events (activated, revoked,
	// rotated) so the per-connection history view shows them
	// alongside messages and calls.
	mh.connectionsHandler.SetAuditLog(mh.auditLog)
	// EventHandler mirrors call + connection lifecycle into the audit
	// trail too — the existing LogCallEvent / LogConnectionEvent call
	// sites get audit coverage for free.
	eventHandler.SetAuditLog(mh.auditLog)

	// Register the audit-chain signer. The closure reads the current
	// audit_priv from vault state on every call — pre-unlock writes
	// get a nil signature (storage leaves entry_sig blank, clients
	// render "unsigned"); post-unlock writes are signed with the
	// user's derived audit key.
	//
	// Registered on EncryptedStorage, NOT storage.SQLite(): on a
	// fresh-spawned subprocess the SQLite doesn't exist yet at
	// MessageHandler-init time (it's created lazily by
	// InitializeWithDEK / ResetWithDEK at pin-setup / cold-unlock).
	// The old `if sqlite := storage.SQLite(); sqlite != nil` guard
	// silently skipped the registration in that (universal, for cold
	// vaults) case, so the real SQLite came up signer-less and every
	// audit row was written unsigned — the "chain unsigned" pill on
	// 2026-05-14. EncryptedStorage.SetEntrySigner stores the closure
	// and re-applies it to every SQLiteStorage it creates.
	storage.SetEntrySigner(func(hashBytes []byte) []byte {
		if mh.vaultState == nil {
			return nil
		}
		mh.vaultState.mu.RLock()
		priv := append([]byte(nil), mh.vaultState.auditPrivateKey...)
		mh.vaultState.mu.RUnlock()
		if len(priv) == 0 {
			return nil
		}
		defer zeroBytes(priv)
		return ed25519.Sign(ed25519.PrivateKey(priv), hashBytes)
	})
	// Lazy audit-binding emit. Fires at the top of every LogEvent;
	// internal flag guards recursion (the binding event itself is a
	// LogEvent and would otherwise re-enter the hook). Net effect:
	// first audit write per PIN-unlock session is the binding event,
	// every subsequent write chains after it.
	eventHandler.SetPreLogEventHook(func(ctx context.Context) {
		mh.ensureBindingEmitted(ctx)
	})
	// Anchor getter so audit.query responses ship audit_pub +
	// binding_sig alongside the events. Client uses these to verify
	// (a) the chain is bound to this user's identity and (b) each
	// row's entry_sig was produced by the bound audit_priv.
	anchorFn := func() (string, string, string) {
		if mh.vaultState == nil {
			return "", "", ""
		}
		mh.vaultState.mu.RLock()
		pub := append([]byte(nil), mh.vaultState.auditPublicKey...)
		sig := append([]byte(nil), mh.vaultState.auditBindingSignature...)
		idPub := append([]byte(nil), mh.vaultState.identityPublicKey...)
		mh.vaultState.mu.RUnlock()
		idPubB64 := base64.StdEncoding.EncodeToString(idPub)
		if len(pub) != 0 && len(sig) != 0 {
			return base64.StdEncoding.EncodeToString(pub),
				base64.StdEncoding.EncodeToString(sig),
				idPubB64
		}
		// In-memory audit key isn't loaded (vault state cycled, or a
		// query landed before carve-outs were re-derived). Fall back
		// to the persisted anchor — audit_pub + binding_sig are public
		// data, written by persistAuditAnchor at every derivation. This
		// is what keeps audit.query from returning an empty anchor and
		// the client showing a spurious "chain unsigned" pill.
		pubB64, sigB64 := loadAuditAnchorFromStorage(mh.storage)
		if pubB64 == "" || sigB64 == "" {
			return "", "", ""
		}
		return pubB64, sigB64, idPubB64
	}
	eventHandler.SetAuditAnchorFn(anchorFn)
	// Same anchor for the per-connection audit response so Connection
	// History can verify against the same key the global Audit Log uses.
	if mh.auditHandler != nil {
		mh.auditHandler.SetAuditAnchorFn(anchorFn)
	}
	// WalletHandler emits transfer.btc.sent inline; transfer.btc.received
	// is appended in the inbound `btc-payment-receipt` case below using
	// the same shared log.
	mh.walletHandler.SetAuditLog(mh.auditLog)
	mh.walletHandler.SetCredentialSecretHandler(mh.credentialSecretHandler)
	// Service-originated event handlers mirror to the VettID system
	// connection via AuditLog.AppendSystem alongside their legacy feed
	// entries. Plans/luminous-unifying-manatee.md has the design.
	mh.guideHandler.SetAuditLog(mh.auditLog)
	mh.migrationHandler.SetAuditLog(mh.auditLog)
	mh.voteHandler.SetAuditLog(mh.auditLog)
	mh.locationHandler.SetAuditLog(mh.auditLog)
	mh.grantHandler.SetAuditLog(mh.auditLog)
	mh.criticalSecretUseHandler.SetAuditLog(mh.auditLog)
	mh.criticalSecretUseHandler.SetEventHandler(mh.eventHandler)
	mh.criticalSecretUseHandler.SetCredentialSecretHandler(mh.credentialSecretHandler)

	return mh
}

// Initialize loads persistent state
func (mh *MessageHandler) Initialize(ctx context.Context) error {
	// Load block list
	if err := mh.callHandler.LoadBlockList(ctx); err != nil {
		return fmt.Errorf("failed to load block list: %w", err)
	}
	// Provision the VettID system connection if it doesn't exist.
	// Idempotent — only writes on first run for a given vault.
	if err := mh.connectionsHandler.EnsureSystemConnection(ctx); err != nil {
		log.Warn().Err(err).Msg("failed to ensure VettID system connection — service events will not have a home")
	}
	// Kick off the presence heartbeat loop. Internally gated on
	// per-connection effective share, so if nothing is opted-in it's
	// just a ticker that reads the connection index and moves on.
	if mh.presenceHandler != nil {
		mh.presenceHandler.StartHeartbeat(ctx)
	}
	// Kick off the connection-expiry sweep — flips abandoned invites
	// past their TTL to "expired" and emits forApp.connection.expired.
	// See plans/parallel-review-handshake.md §10 risk #3.
	if mh.connectionsHandler != nil {
		mh.connectionsHandler.StartExpirySweep(ctx)
	}
	return nil
}

// SetSealerResponseChannel sets the channel for receiving sealer responses from supervisor
// This must be called before any PIN operations that require KMS access
func (mh *MessageHandler) SetSealerResponseChannel(ch chan *IncomingMessage) {
	mh.sealerProxy.SetResponseChannel(ch)
}

// GetSealerProxy returns the sealer proxy for routing sealer responses
func (mh *MessageHandler) GetSealerProxy() *SealerProxy {
	return mh.sealerProxy
}

// SetHTTPResponseChannel sets the channel for receiving HTTP proxy responses from parent
// This must be called before any operations that require external HTTP access
func (mh *MessageHandler) SetHTTPResponseChannel(ch chan *IncomingMessage) {
	mh.httpProxy.SetResponseChannel(ch)
}

// GetHTTPProxy returns the HTTP proxy for routing HTTP responses
func (mh *MessageHandler) GetHTTPProxy() *HTTPProxy {
	return mh.httpProxy
}

// IsHTTPResponse checks if a message is an HTTP proxy response from the parent.
func (mh *MessageHandler) IsHTTPResponse(msg *IncomingMessage) bool {
	return msg.Type == MessageTypeHTTPResponse
}

// IsSealerResponse checks if a message is a sealer response from supervisor.
// This includes both sealer_response (normal) and storage_response (shouldn't happen
// but included for defensive handling in case of race conditions).
func (mh *MessageHandler) IsSealerResponse(msg *IncomingMessage) bool {
	return msg.Type == MessageTypeSealerResponse || msg.Type == MessageTypeStorageResponse
}

// IsRevokeOwnership checks if a message is a routing-ownership revocation
// from the supervisor. receiveMessages intercepts these and applies them
// via MarkOwnershipRevoked directly — they must NOT be routed through
// HandleMessage, because the whole point is to land while the main loop
// is blocked mid-request. See the split-brain fix (D2, 2026-05-14).
func (mh *MessageHandler) IsRevokeOwnership(msg *IncomingMessage) bool {
	return msg.Type == MessageTypeRevokeOwnership
}

// MarkOwnershipRevoked fences off this subprocess: flushVaultStateToS3
// will refuse to persist and HandleMessage will refuse new ops. Called
// when a revoke_ownership message arrives because the parent's
// RoutingManager lost this user's routing claim. Idempotent.
func (mh *MessageHandler) MarkOwnershipRevoked() {
	if mh.vaultState == nil {
		return
	}
	mh.vaultState.mu.Lock()
	already := mh.vaultState.ownershipRevoked
	mh.vaultState.ownershipRevoked = true
	mh.vaultState.mu.Unlock()
	if !already {
		log.Warn().Str("owner_space", mh.ownerSpace).
			Msg("SECURITY: routing ownership REVOKED — vault_state persistence fenced off, new ops will be refused (split-brain guard)")
	}
}

// isOwnershipRevoked reports whether this subprocess has been fenced
// off by a revoke_ownership message.
func (mh *MessageHandler) isOwnershipRevoked() bool {
	if mh.vaultState == nil {
		return false
	}
	mh.vaultState.mu.RLock()
	defer mh.vaultState.mu.RUnlock()
	return mh.vaultState.ownershipRevoked
}

// IsSelfEvictRequested reports whether this subprocess tripped the D3
// split-brain guard and has asked to exit. The main loop polls this
// after every message: once set, it refuses further ops and exits so
// the supervisor can spawn a fresh subprocess. Exported because
// main.go's loop is in the same package but a different file.
func (mh *MessageHandler) IsSelfEvictRequested() bool {
	if mh.vaultState == nil {
		return false
	}
	mh.vaultState.mu.RLock()
	defer mh.vaultState.mu.RUnlock()
	return mh.vaultState.selfEvictRequested
}

// HandleMessage processes an incoming message
func (mh *MessageHandler) HandleMessage(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Debug().
		Str("id", msg.GetID()).
		Str("type", string(msg.Type)).
		Str("subject", msg.Subject).
		Msg("Handling message")

	// SECURITY: once routing ownership is revoked, refuse to serve new
	// ops — don't just decline to persist, decline to act. The parent
	// has already handed this user to another enclave; the app retries
	// and lands on the new owner. Serving here would mutate in-memory
	// state that can never be safely persisted (split-brain fix, D2).
	if mh.isOwnershipRevoked() {
		log.Warn().Str("owner_space", mh.ownerSpace).Str("id", msg.GetID()).
			Msg("refusing vault op — routing ownership revoked; app should retry on the new owner")
		return mh.errorResponse(msg.GetID(), "vault ownership transferred — retry")
	}

	// D3 self-eviction: a prior persist hit a conditional-PUT
	// conflict. Refuse this op too — the main loop will exit the
	// subprocess right after, and the next op spawns a fresh one
	// that cold-loads the winning vault_state.enc. Same retry error
	// as the revoke path so the app's existing retry handling kicks
	// in transparently.
	if mh.IsSelfEvictRequested() {
		log.Warn().Str("owner_space", mh.ownerSpace).Str("id", msg.GetID()).
			Msg("refusing vault op — D3 self-eviction pending; subprocess exiting, app should retry")
		return mh.errorResponse(msg.GetID(), "vault ownership transferred — retry")
	}

	switch msg.Type {
	case MessageTypeVaultOp:
		return mh.handleVaultOp(ctx, msg)
	case MessageTypeStorageResponse:
		// Storage responses should be handled by the sealer proxy's synchronous operations.
		// If we receive one here in the main message handler, it means there was a
		// race condition or message ordering issue between the main loop and sealer proxy.
		// Log a warning and return nil - the caller should handle this gracefully.
		log.Warn().
			Str("id", msg.GetID()).
			Str("type", string(msg.Type)).
			Msg("Received storage_response in main handler - possible race condition with sealer proxy")
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

// unwrapPayload extracts the inner payload from the parent's envelope format.
// Parent sends: {"type":"guide.sync","payload":{"guides":[...]}}
// Returns: payloadType="guide.sync", innerPayload={"guides":[...]}
// If not wrapped, returns empty type and original data unchanged.
func unwrapPayload(data json.RawMessage) (string, json.RawMessage) {
	if len(data) == 0 {
		return "", data
	}
	var envelope struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return "", data
	}
	// Only unwrap if BOTH type and payload are present.
	// Vault-to-vault messages (e.g., CallEvent) may have a "payload" field
	// for data like WebRTC SDP, but no "type" field — don't strip those.
	if envelope.Type == "" || len(envelope.Payload) == 0 {
		return "", data
	}
	return envelope.Type, envelope.Payload
}

// handleVaultOp routes vault operations based on subject
func (mh *MessageHandler) handleVaultOp(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// Parse subject to determine operation type
	// Formats supported:
	// - OwnerSpace.{guid}.forVault.{operation...}  (from mobile app)
	// - MessageSpace.{guid}.fromService.{serviceId}.{operation...}  (from services)
	parts := strings.Split(msg.Subject, ".")
	if len(parts) < 4 {
		return mh.errorResponse(msg.GetID(), "invalid subject format")
	}

	// Check for service messages first (fromService routing)
	// Format: MessageSpace.{ownerSpace}.fromService.{serviceId}.{operation}.*
	serviceIndex := -1
	for i, part := range parts {
		if part == "fromService" {
			serviceIndex = i
			break
		}
	}
	if serviceIndex != -1 && serviceIndex+2 < len(parts) {
		// This is a message from a service
		serviceID := parts[serviceIndex+1]
		return mh.handleFromServiceOperation(ctx, msg, serviceID, parts[serviceIndex+2:])
	}

	// Check for agent/device messages (forOwner routing)
	// Format: MessageSpace.{ownerSpace}.forOwner.agent  OR  ...forOwner.device
	for i, part := range parts {
		if part == "forOwner" {
			// Determine if this is an agent, device, or connection message
			var resp *OutgoingMessage
			var err error

			if i+1 < len(parts) && parts[i+1] == "device" {
				// Device messages on the forOwner channel split into two
				// flavors:
				//
				//   - PAIRING (Stage 2): the desktop publishes
				//     `forOwner.device.{conn}.request-session` while still
				//     pre-activation. The payload is a plain JSON envelope
				//     (no per-connection encryption — the key exchange
				//     hasn't happened yet), so it has to bypass
				//     HandleDeviceMessage (which decrypts) and go straight
				//     to the pairing handler. Same applies to
				//     `revoke` published by a desktop logging itself out.
				//
				//   - OPERATIONS: once the device session is active,
				//     `forOwner.device.{conn}.op-request` carries an
				//     encrypted AgentEnvelope that HandleDeviceMessage
				//     decrypts and dispatches per the device-op routing.
				//
				// Detect the pairing flavor by looking at the trailing
				// path segment (parts[i+3] when the conn-id is at i+2).
				// Unknown tails fall through to HandleDeviceMessage to
				// keep the existing op routing intact.
				pairingOp := ""
				if i+3 < len(parts) {
					pairingOp = parts[i+3]
				}
				switch pairingOp {
				case "request-session":
					// Pairing payloads on the forOwner channel ship with the
					// parent's envelope wrapper still attached (the forVault
					// path normally calls unwrapPayload further down, but
					// forOwner messages skipped that step before this fix).
					// Strip it now so HandleDeviceRequestSession sees the
					// inner request fields directly.
					msg.PayloadType, msg.Payload = unwrapPayload(msg.Payload)
					resp, err = mh.connectionsHandler.HandleDeviceRequestSession(ctx, msg)
				case "revoke":
					// Desktop-initiated logout. Same envelope shape as
					// request-session — JSON wrapper, no encryption (the
					// connection's session key gets wiped as part of the
					// revoke so encrypting against it would be circular).
					msg.PayloadType, msg.Payload = unwrapPayload(msg.Payload)
					resp, err = mh.connectionsHandler.HandleRevokeDevice(ctx, msg)
				case "end-session":
					// Desktop-initiated soft end. Wipes the active session
					// key vault-side and flips DeviceSession to expired so
					// the user can start a new session without re-pairing.
					msg.PayloadType, msg.Payload = unwrapPayload(msg.Payload)
					resp, err = mh.connectionsHandler.HandleDeviceEndSession(ctx, msg)
				default:
					resp, err = mh.deviceHandler.HandleDeviceMessage(ctx, msg)
				}
			} else if i+1 < len(parts) && parts[i+1] == "agent" {
				// Agent messages on the forOwner channel split into two
				// flavors, mirroring the device path above:
				//
				//   - PAIRING (Stage 2): the agent publishes
				//     `forOwner.agent.{conn}.request-session` while still
				//     pre-activation. The payload is a plain JSON envelope
				//     (no per-connection encryption — the key exchange
				//     hasn't happened yet), so it bypasses HandleAgentMessage
				//     (which decrypts AgentEnvelope) and routes to the
				//     pairing handler directly. Same applies to
				//     `revoke` and `end-session` published by an agent
				//     logging itself out.
				//
				//   - OPERATIONS: once the agent session is active, the
				//     agent publishes an encrypted AgentEnvelope (subject
				//     suffixes documented in agent_handler.go) which
				//     HandleAgentMessage decrypts and dispatches.
				//
				// Detect the pairing flavor by looking at the trailing
				// path segment (parts[i+3] when the conn-id is at i+2).
				// Unknown tails fall through to HandleAgentMessage to keep
				// existing agent op routing intact.
				pairingOp := ""
				if i+3 < len(parts) {
					pairingOp = parts[i+3]
				}
				switch pairingOp {
				case "request-session":
					msg.PayloadType, msg.Payload = unwrapPayload(msg.Payload)
					resp, err = mh.connectionsHandler.HandleAgentRequestSession(ctx, msg)
				case "end-session":
					msg.PayloadType, msg.Payload = unwrapPayload(msg.Payload)
					resp, err = mh.connectionsHandler.HandleAgentEndSession(ctx, msg)
				case "revoke":
					msg.PayloadType, msg.Payload = unwrapPayload(msg.Payload)
					resp, err = mh.connectionsHandler.HandleRevokeAgent(ctx, msg)
				default:
					resp, err = mh.agentHandler.HandleAgentMessage(ctx, msg)
				}
			} else if i+1 < len(parts) && parts[i+1] == "presence" {
				// Cross-vault presence heartbeat from a peer published
				// via MessageSpace.{us}.forOwner.presence.heartbeat
				// (backend NATS account). Republish to our app's
				// forApp.presence.heartbeat so the OwnerSpaceClient
				// can light up the avatar ring.
				if mh.presenceHandler != nil {
					if hbErr := mh.presenceHandler.HandleIncomingPeerHeartbeat(ctx, msg.Payload); hbErr != nil {
						log.Debug().Err(hbErr).Msg("Failed to forward peer presence heartbeat")
					}
				}
				resp = &OutgoingMessage{RequestID: msg.GetID(), Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}
			} else if i+1 < len(parts) && parts[i+1] == "connection" {
				// Connection messages from peers, agents, and devices.
				// Parallel-review handshake (plans/parallel-review-handshake.md):
				// every peer-direction subject collapses into either
				// `connection.signal` (response-ready / peer-accepted /
				// peer-rejected) or `connection.store-credentials` for
				// agent/device pairing. Pre-parallel-review subject
				// aliases were removed once existing users re-enrolled.
				if i+2 < len(parts) {
					switch parts[i+2] {
					case "signal":
						resp, err = mh.connectionsHandler.HandleConnectionSignal(ctx, msg)
					case "store-credentials":
						// Agents and devices still use store-credentials.
						resp, err = mh.connectionsHandler.HandleStoreCredentials(msg)
					default:
						log.Debug().Str("subject", parts[i+2]).Msg("Unknown peer connection subject — dropping")
						resp = &OutgoingMessage{RequestID: msg.GetID(), Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}
					}
				} else {
					resp = &OutgoingMessage{RequestID: msg.GetID(), Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}
				}
			} else {
				// Anything else on forOwner falls back to HandleAgentMessage
				// — historical behavior from before the explicit `agent`
				// branch above. Live agent op envelopes are caught by that
				// branch's default arm; this is for unknown owner-side
				// subjects we haven't classified yet.
				resp, err = mh.agentHandler.HandleAgentMessage(ctx, msg)
			}

			if resp == nil && err == nil {
				// Return a minimal ack response so the supervisor's ProcessMessage loop
				// terminates. Without this, the supervisor would timeout after 30s waiting
				// for a final response that never comes.
				return &OutgoingMessage{
					RequestID: msg.GetID(),
					Type:      MessageTypeResponse,
					Payload:   json.RawMessage(`{"ack":true}`),
				}, nil
			}
			return resp, err
		}
	}

	// Extract operation path (everything after forVault)
	opIndex := -1
	for i, part := range parts {
		if part == "forVault" {
			opIndex = i
			break
		}
	}
	if opIndex == -1 || opIndex+1 >= len(parts) {
		return mh.errorResponse(msg.GetID(), "missing operation in subject")
	}

	operation := parts[opIndex+1]

	// Multi-token peer subjects need the joined-tokens form because
	// strings.Split breaks them apart. `data.request` becomes parts
	// [..., forVault, data, request] so operation alone is "data" and
	// `case "data.request"` would never match. Reconstruct the full
	// path and route those subjects explicitly here before falling
	// through to the single-token switch below.
	fullOp := strings.Join(parts[opIndex+1:], ".")
	if resp, handled := mh.dispatchMultiTokenPeerSubject(ctx, msg, fullOp); handled {
		return resp, nil
	}

	// Check if vault is locked (DEK not available) for operations that need it.
	// After an enclave instance refresh, the vault-manager restarts with no DEK.
	// The DEK is derived from PIN + sealed material during PIN unlock.
	// Without it, data operations silently fail, causing data loss.
	mh.vaultState.mu.RLock()
	dek := mh.vaultState.dek
	mh.vaultState.mu.RUnlock()

	if dek == nil {
		// These operations are allowed without DEK (they set it up or don't need it)
		allowedWithoutDEK := map[string]bool{
			"pin-unlock": true, "pin-setup": true, "pin-change": true, "pin": true,
			"bootstrap": true, "app": true,
			"credential": true,
			"vault": true, "handlers": true,
			"guide": true,
		}
		if !allowedWithoutDEK[operation] {
			log.Warn().
				Str("owner_space", mh.ownerSpace).
				Str("operation", operation).
				Msg("Vault locked — DEK not available, rejecting operation")
			return mh.errorResponse(msg.GetID(), "vault_locked: PIN unlock required")
		}
	}

	// Unwrap payload envelope from parent process.
	// Parent preserves: {"type":"X","payload":{actual data}}
	// Handlers expect just the inner payload content.
	msg.PayloadType, msg.Payload = unwrapPayload(msg.Payload)

	// Handler authorization gate. Owner-originated dispatch (forVault.*
	// from the user's app) — system handlers bypass; everything else
	// must be enabled in handlers/_state. Peer-originated subjects are
	// gated separately inside the cases below so we have the resolved
	// connection_id in scope.
	if peerHandlerForIncomingSubject(operation) == "" {
		if gateResp := mh.gateOperation(operation, "owner", "", msg.GetID()); gateResp != nil {
			return gateResp, nil
		}
	}

	switch operation {
	case "call":
		return mh.handleCallOperation(ctx, msg, parts[opIndex+1:])
	case "app":
		return mh.handleAppOperation(ctx, msg, parts[opIndex+1:])
	case "bootstrap":
		return mh.handleBootstrap(ctx, msg)
	case "pin":
		// Route based on payload type for mobile apps using forVault.pin subject.
		// Refresh handler-auth cache afterwards so the gate can read the
		// user's toggles on the very next dispatch.
		resp, err := mh.handlePinOperation(ctx, msg)
		if err == nil && resp != nil && resp.Type != MessageTypeError {
			if rerr := mh.refreshHandlerAuth(); rerr != nil {
				log.Debug().Err(rerr).Msg("Failed to refresh handler-auth cache after pin op")
			}
		}
		return resp, err
	case "pin-setup":
		resp, err := mh.pinHandler.HandlePINSetup(ctx, msg)
		if err == nil && resp != nil && resp.Type != MessageTypeError {
			if rerr := mh.refreshHandlerAuth(); rerr != nil {
				log.Debug().Err(rerr).Msg("Failed to refresh handler-auth cache after pin-setup")
			}
		}
		return resp, err
	case "pin-unlock":
		resp, err := mh.pinHandler.HandlePINUnlock(ctx, msg)
		if err == nil && resp != nil && resp.Type != MessageTypeError {
			if rerr := mh.refreshHandlerAuth(); rerr != nil {
				log.Debug().Err(rerr).Msg("Failed to refresh handler-auth cache after pin-unlock")
			}
		}
		return resp, err
	case "pin-change":
		response, err := mh.pinHandler.HandlePINChange(ctx, msg)
		if err != nil {
			return response, err
		}
		// Persist vault state to S3 so cold vault recovery uses updated credential/auth
		mh.persistVaultStateToS3()
		return response, nil
	case "unseal":
		return mh.handleUnseal(ctx, msg)
	case "sign":
		return mh.handleSign(ctx, msg)
	case "block":
		return mh.handleBlockOperation(ctx, msg, parts[opIndex+1:])
	case "secrets", "secret":
		// Android client publishes the singular `secret.*` form; legacy callers
		// use the plural `secrets.*` form. Both route to the same handler.
		return mh.handleSecretsOperation(ctx, msg, parts[opIndex+1:])
	case "profile":
		return mh.handleProfileOperation(ctx, msg, parts[opIndex+1:])
	case "personal-data":
		return mh.handlePersonalDataOperation(ctx, msg, parts[opIndex+1:])
	case "credential":
		return mh.handleCredentialOperation(ctx, msg, parts[opIndex+1:])
	case "message":
		return mh.handleMessageOperation(ctx, msg, parts[opIndex+1:])
	case "connection":
		return mh.handleConnectionOperation(ctx, msg, parts[opIndex+1:])
	case "notification":
		return mh.handleNotificationOperation(ctx, msg, parts[opIndex+1:])
	case "profile-update":
		// Incoming notification from peer vault
		if gateResp := mh.gatePeerSubject(operation, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, nil
		}
		return mh.handleIncomingProfileUpdate(ctx, msg)
	case "revoked":
		// Incoming revocation notice from peer vault
		if gateResp := mh.gatePeerSubject(operation, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, nil
		}
		return mh.handleIncomingRevocation(ctx, msg)
	case "new-message":
		// Incoming message from peer vault
		if gateResp := mh.gatePeerSubject(operation, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, nil
		}
		return mh.handleIncomingPeerMessage(ctx, msg)
	case "read-receipt":
		// Incoming read receipt from peer vault
		if gateResp := mh.gatePeerSubject(operation, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, nil
		}
		return mh.handleIncomingReadReceipt(ctx, msg)
	case "location-update":
		// Incoming location update from peer vault
		if gateResp := mh.gatePeerSubject(operation, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, nil
		}
		return mh.handleIncomingLocationUpdate(ctx, msg)
	case "location-stop":
		// Incoming stop-sharing notice from peer vault (V5).
		if gateResp := mh.gatePeerSubject(operation, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, nil
		}
		return mh.handleIncomingLocationStop(ctx, msg)
	case "location-request-ping":
		// Incoming one-shot location-request ping from peer vault (V6).
		if gateResp := mh.gatePeerSubject(operation, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, nil
		}
		return mh.handleIncomingLocationRequest(ctx, msg)
	case "btc-address-request":
		// Incoming BTC address request from peer vault — auto-respond
		if gateResp := mh.gatePeerSubject(operation, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, nil
		}
		return mh.walletHandler.HandleIncomingAddressRequest(ctx, msg)
	case "btc-payment-request":
		// Incoming BTC payment request from peer vault — decrypt and
		// forward the plaintext inner payload to the app.
		if gateResp := mh.gatePeerSubject(operation, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, nil
		}
		btcDec, btcErr := decryptIncomingPeerEnvelope(mh.storage, msg.Payload)
		if btcErr != nil {
			log.Warn().Err(btcErr).Msg("Failed to decrypt btc-payment-request envelope")
		} else if mh.publisher != nil {
			_ = mh.publisher.PublishToApp(ctx, "message.btc-payment-request", btcDec.InnerPayload)
		}
		if mh.eventHandler != nil {
			mh.eventHandler.LogEvent(ctx, &Event{EventType: EventTypePaymentReceived})
		}
		ack, _ := json.Marshal(map[string]string{"status": "received"})
		return mh.successResponse(msg.GetID(), ack)
	case "btc-payment-receipt":
		// Incoming BTC payment receipt from peer vault — decrypt + forward.
		if gateResp := mh.gatePeerSubject(operation, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, nil
		}
		receiptDec, receiptErr := decryptIncomingPeerEnvelope(mh.storage, msg.Payload)
		if receiptErr != nil {
			log.Warn().Err(receiptErr).Msg("Failed to decrypt btc-payment-receipt envelope")
		} else if mh.publisher != nil {
			_ = mh.publisher.PublishToApp(ctx, "message.btc-payment-receipt", receiptDec.InnerPayload)
		}
		if mh.eventHandler != nil {
			mh.eventHandler.LogEvent(ctx, &Event{EventType: EventTypeWalletTxReceived})
		}
		// Per-connection audit: record the inbound transfer. sender_guid
		// travels in the receipt so we can resolve a local connection_id
		// without asking NATS (accounts may differ across peers).
		if mh.auditLog != nil && receiptErr == nil {
			var receipt BtcPaymentReceiptContent
			if err := json.Unmarshal(receiptDec.InnerPayload, &receipt); err == nil && receipt.SenderGUID != "" {
				connID := ""
				if mh.notificationsHandler != nil {
					connID = mh.notificationsHandler.FindConnectionByPeerGUID(receipt.SenderGUID)
				}
				if connID != "" {
					mh.auditLog.Append(AuditEntry{
						ConnectionID: connID,
						PeerGUID:     receipt.SenderGUID,
						EventType:    AuditTypeTransferBtcReceived,
						Direction:    AuditDirectionInbound,
						Title:        "Received BTC",
						CreatedAt:    time.Now().Unix(),
						Refs: map[string]string{
							"tx_id": receipt.TxID,
						},
						Metadata: map[string]string{
							"amount_sats": fmt.Sprintf("%d", receipt.AmountSats),
						},
					})
				}
			}
		}
		ack, _ := json.Marshal(map[string]string{"status": "received"})
		return mh.successResponse(msg.GetID(), ack)
	case "btc-address-response":
		// Incoming BTC address response from peer vault — decrypt + forward.
		if gateResp := mh.gatePeerSubject(operation, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, nil
		}
		addrDec, addrErr := decryptIncomingPeerEnvelope(mh.storage, msg.Payload)
		if addrErr != nil {
			log.Warn().Err(addrErr).Msg("Failed to decrypt btc-address-response envelope")
		} else if mh.publisher != nil {
			_ = mh.publisher.PublishToApp(ctx, "message.btc-address-response", addrDec.InnerPayload)
		}
		ack, _ := json.Marshal(map[string]string{"status": "received"})
		return mh.successResponse(msg.GetID(), ack)
	case "vote":
		// Vault-signed voting operation
		return mh.handleVoteOperation(ctx, msg, parts[opIndex+1:])
	case "action":
		// Shared-action layer: list catalog, configure auth, invoke on
		// peer, decide pending approvals. See action_*.go.
		return mh.handleActionOperation(ctx, msg, parts[opIndex+1:])
	case "invoke-action":
		// Peer-originated invocation arriving on our connection's E2E
		// channel. The auth engine handles 9-step validation + audit.
		return mh.handleIncomingInvokeAction(ctx, msg)
	case "action-result":
		// Peer-originated result for an invocation we sent. Forward to
		// our app via forApp.action.result so the invoker's UI updates.
		return mh.handleIncomingActionResult(ctx, msg)
	case "feed":
		// Feed operations (unified event feed)
		return mh.handleFeedOperation(ctx, msg, parts[opIndex+1:])
	case "grant":
		// Reference-based data sharing (plans/data-request-grants.md).
		return mh.handleGrantOperation(ctx, msg, parts[opIndex+1:])
	case "critical-secret-use":
		// Use-on-my-behalf for critical secrets (Phase 6).
		return mh.handleCriticalSecretUseOperation(ctx, msg, parts[opIndex+1:])
	case "connection-authenticate":
		// Challenge/response proof-of-credential between connections.
		// App-side ops:
		//   - request: requester sends a nonce challenge
		//   - approve: receiver authorizes signing under password
		//   - deny:    receiver explicitly refuses
		//   - get:     read cached verify-state for one connection
		//   - list:    read cached verify-state across all connections
		if len(parts) > opIndex+2 {
			switch parts[opIndex+2] {
			case "request":
				return mh.HandleAuthRequest(msg)
			case "approve":
				return mh.HandleApproveVerify(msg)
			case "deny":
				return mh.HandleDenyVerify(msg)
			case "get":
				return mh.HandleVerifyStateGet(ctx, msg)
			case "list":
				return mh.HandleVerifyStateList(ctx, msg)
			}
		}
		return mh.errorResponse(msg.GetID(), "unknown connection-authenticate op")
	case "audit":
		// Audit log operations
		return mh.handleAuditOperation(ctx, msg, parts[opIndex+1:])
	case "invitation":
		// Invitation lifecycle operations
		return mh.handleInvitationOperation(ctx, msg, parts[opIndex+1:])
	case "capability":
		// Capability request operations
		return mh.handleCapabilityOperation(ctx, msg, parts[opIndex+1:])
	case "settings":
		// Settings operations
		return mh.handleSettingsOperation(ctx, msg, parts[opIndex+1:])
	case "notifications":
		// Notifications operations (digest)
		return mh.handleNotificationsDigestOperation(ctx, msg, parts[opIndex+1:])
	case "service":
		// Service connection operations (B2C)
		return mh.handleServiceOperation(ctx, msg, parts[opIndex+1:])
	case "datastore":
		// Combined datastore operations (Phase 4)
		return mh.handleDatastoreOperation(ctx, msg, parts[opIndex+1:])
	case "guide":
		// Guide sync operations (welcome/tutorial events)
		return mh.handleGuideOperation(ctx, msg, parts[opIndex+1:])
	case "location":
		// Location tracking operations
		return mh.handleLocationOperation(ctx, msg, parts[opIndex+1:])
	case "presence":
		// Presence (online/offline) opt-in settings + overrides
		return mh.handlePresenceOperation(ctx, msg, parts[opIndex+1:])
	case "enrollment":
		// Enrollment operations (identity mismatch reports)
		return mh.handleEnrollmentOperation(ctx, msg, parts[opIndex+1:])
	case "handlers":
		// Handler listing (read-only introspection of vault capabilities)
		return mh.handleHandlersOperation(ctx, msg, parts[opIndex+1:])
	case "agent":
		// Agent management operations (from mobile app)
		return mh.handleAgentOperation(ctx, msg, parts[opIndex+1:])
	case "leash":
		// LEASH token issuance + revocation for agent delegation (see
		// docs/LEASH-TOKEN-FORMAT.md).
		return mh.handleLeashOperation(ctx, msg, parts[opIndex+1:])
	case "device":
		// Device management operations (from mobile app)
		return mh.handleDeviceOperation(ctx, msg, parts[opIndex+1:])
	case "wallet":
		// Bitcoin wallet operations
		response, err := mh.handleWalletOperation(ctx, msg, parts[opIndex+1:])
		if err != nil {
			return response, err
		}
		// Persist state after wallet creation/modification
		mh.persistVaultStateToS3()
		return response, nil
	case "vault":
		// Vault lifecycle operations (save state, etc.)
		return mh.handleVaultLifecycleOperation(ctx, msg, parts[opIndex+1:])
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown operation: %s", operation))
	}
}

// handlePinOperation routes PIN operations based on payload type
// Supports mobile apps that use forVault.pin subject with type in payload
func (mh *MessageHandler) handlePinOperation(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// PayloadType was extracted by central unwrapPayload in handleVaultOp
	pinOp := msg.PayloadType
	if pinOp == "" {
		return mh.errorResponse(msg.GetID(), "missing PIN operation type")
	}

	log.Debug().
		Str("owner_space", mh.ownerSpace).
		Str("pin_operation", pinOp).
		Msg("Routing PIN operation")

	switch pinOp {
	case "pin.setup":
		return mh.pinHandler.HandlePINSetup(ctx, msg)
	case "pin.unlock":
		return mh.pinHandler.HandlePINUnlock(ctx, msg)
	case "pin.change":
		return mh.pinHandler.HandlePINChange(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown PIN operation type: %s", pinOp))
	}
}

// handleAgentOperation routes agent management operations from the mobile app.
// Format: forVault.agent.{sub-operation}
func (mh *MessageHandler) handleAgentOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing agent operation type")
	}

	opType := opParts[1]

	log.Debug().
		Str("owner_space", mh.ownerSpace).
		Str("agent_operation", opType).
		Msg("Routing agent operation")

	switch opType {
	case "approval":
		// App approves or denies a pending per-operation agent request
		// (NOT the stage-2 session authorization — that's authorize-session).
		return mh.agentHandler.HandleAppApprovalResponse(ctx, msg)
	case "list":
		// List active agent connections
		return mh.connectionsHandler.HandleListAgentConnections(ctx, msg)
	case "revoke":
		// Revoke an agent connection (from app admin or agent shutdown)
		return mh.connectionsHandler.HandleRevokeAgent(ctx, msg)
	case "update-contract":
		// Update an agent's contract (scope, approval mode, rate limit)
		// without re-running the full session authorization round-trip.
		return mh.connectionsHandler.HandleUpdateAgentContract(ctx, msg)
	case "create-invite":
		// Stage 1: app creates a pairing invite for a new agent
		// (see vettid-agent/docs/AGENT-PAIRING-FLOW.md §Stage 1).
		return mh.connectionsHandler.HandleCreateAgentInvite(msg)
	case "cancel-invite":
		// User cancelled the pairing invite from the phone before it
		// was claimed by an agent.
		return mh.connectionsHandler.HandleCancelAgentInvite(msg)
	case "request-session":
		// Stage 2 (agent → vault): request session authorization
		return mh.connectionsHandler.HandleAgentRequestSession(ctx, msg)
	case "authorize-session":
		// Stage 2 (app → vault): owner approves the session with
		// final scope / approval_mode / rate_limit / duration.
		return mh.connectionsHandler.HandleAgentAuthorizeSession(ctx, msg)
	case "extend-session":
		// Owner re-approves an extension request from the agent — rotates
		// keys and extends the session.
		return mh.connectionsHandler.HandleAgentExtendSession(ctx, msg)
	case "end-session":
		// Soft end-session: wipe session key + flip AgentSession to
		// expired, but keep the connection so the agent can restart
		// a session without re-pairing.
		return mh.connectionsHandler.HandleAgentEndSession(ctx, msg)
	case "message-reply":
		// User replies to an agent message
		return mh.agentHandler.HandleAgentMessageReply(ctx, msg)
	case "leash-approve":
		// Owner approved (or denied) an agent-initiated LEASH mint request.
		// Vault calls into the leash handler's MintLeash internally and
		// delivers the resulting JWT back to the agent over its NATS
		// subscription, encrypted with the active AgentSession key.
		return mh.HandleAgentLeashApprove(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown agent operation: %s", opType))
	}
}

// AgentLeashApproveRequest is the phone-side payload for owner approval
// of an agent-initiated LEASH mint request. The phone supplies the final
// scope / duration (which may differ from what the agent requested if
// the owner narrowed things on LeashApprovalScreen) and a boolean
// approval flag.
type AgentLeashApproveRequest struct {
	RequestID     string   `json:"request_id"`
	Approved      bool     `json:"approved"`
	GrantedScope  []string `json:"granted_scope,omitempty"`
	DurationSecs  int64    `json:"duration_secs,omitempty"`
	DenyReason    string   `json:"deny_reason,omitempty"`
}

// HandleAgentLeashApprove handles forVault.agent.leash-approve. Looks
// up the PendingLeashRequest stored by handleLeashMintRequest, branches
// on approved/denied, and delivers an AgentMsgLeashGranted (with the
// freshly minted JWT) or AgentMsgLeashDenied envelope back to the agent
// via its forOwner.agent.<conn> subscription, encrypted with the active
// AgentSession key.
func (mh *MessageHandler) HandleAgentLeashApprove(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AgentLeashApproveRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleAgentLeashApprove"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}
	if req.RequestID == "" {
		return mh.errorResponse(msg.GetID(), "request_id is required")
	}

	storageKey := "agent_leash_pending/" + req.RequestID
	pendingBytes, err := mh.storage.Get(storageKey)
	if err != nil {
		return mh.errorResponse(msg.GetID(), "leash request not found or already resolved")
	}
	var pending PendingLeashRequest
	if err := json.Unmarshal(pendingBytes, &pending); err != nil {
		return mh.errorResponse(msg.GetID(), "pending leash request unreadable")
	}
	if time.Now().Unix() > pending.ExpiresAt {
		_ = mh.storage.Delete(storageKey)
		return mh.errorResponse(msg.GetID(), "leash request expired")
	}

	// Always consume the pending row regardless of outcome — one approval
	// op per request, even on denial. Delete BEFORE the publish so a
	// retry from the phone (e.g. timeout + re-approve) hits the
	// "not found" branch instead of silently double-issuing.
	_ = mh.storage.Delete(storageKey)

	// Look up the connection's AgentSession key for the agent-side
	// envelope encryption. If the session has rotated or expired since
	// the request was filed, we can't deliver the JWT to the agent —
	// fail the approve so the owner sees the error rather than minting
	// a leash that the agent never receives.
	connData, err := mh.storage.Get("connections/" + pending.ConnectionID)
	if err != nil {
		return mh.errorResponse(msg.GetID(), "connection not found")
	}
	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return mh.errorResponse(msg.GetID(), "connection record unreadable")
	}
	if conn.AgentSession == nil || conn.AgentSession.SessionKeyID == "" {
		return mh.errorResponse(msg.GetID(), "agent has no active session — request a fresh extend before approving")
	}
	keyPath := fmt.Sprintf("agent_session_keys/%s/%s", pending.ConnectionID, conn.AgentSession.SessionKeyID)
	sessionKey, err := mh.storage.Get(keyPath)
	if err != nil || len(sessionKey) == 0 {
		return mh.errorResponse(msg.GetID(), "agent session key not found")
	}

	topic := fmt.Sprintf("MessageSpace.%s.forOwner.agent.%s", mh.ownerSpace, pending.ConnectionID)

	if !req.Approved {
		reason := req.DenyReason
		if reason == "" {
			reason = "denied by owner"
		}
		deniedBytes, _ := json.Marshal(AgentLeashDeniedPayload{
			RequestID: pending.RequestID,
			Reason:    reason,
		})
		mh.agentHandler.publishAgentResponse(sessionKey, pending.ConnectionID, AgentMsgLeashDenied, deniedBytes, topic)
		return createSuccessResponse(msg.GetID(), true, "denied")
	}

	// Approved — fall back to the agent-requested values when the owner
	// didn't narrow them on the approval screen.
	scope := req.GrantedScope
	if len(scope) == 0 {
		scope = pending.RequestedScope
	}
	duration := req.DurationSecs
	if duration <= 0 {
		duration = pending.DurationSecs
	}

	out, mintErr := mh.leashHandler.MintLeash(GrantAttestRequest{
		ConnectionID: pending.ConnectionID,
		AgentPubkey:  pending.AgentPubkey,
		Scope:        scope,
		DurationSecs: duration,
	})
	if mintErr != nil {
		log.Warn().Err(mintErr).Str("request_id", pending.RequestID).Msg("LEASH mint failed during approve")
		deniedBytes, _ := json.Marshal(AgentLeashDeniedPayload{
			RequestID: pending.RequestID,
			Reason:    "mint failed: " + mintErr.Error(),
		})
		mh.agentHandler.publishAgentResponse(sessionKey, pending.ConnectionID, AgentMsgLeashDenied, deniedBytes, topic)
		return mh.errorResponse(msg.GetID(), mintErr.Error())
	}

	grantedBytes, _ := json.Marshal(AgentLeashGrantedPayload{
		RequestID: pending.RequestID,
		Leash:     out.Leash,
		JTI:       out.JTI,
		Kid:       out.Kid,
		IssuedAt:  out.IssuedAt,
		ExpiresAt: out.ExpiresAt,
	})
	mh.agentHandler.publishAgentResponse(sessionKey, pending.ConnectionID, AgentMsgLeashGranted, grantedBytes, topic)

	resp := map[string]interface{}{
		"success":    true,
		"request_id": pending.RequestID,
		"jti":        out.JTI,
		"expires_at": out.ExpiresAt,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// handleLeashOperation routes LEASH token issuance + revocation.
// Format: forVault.leash.{sub-operation}
//
// Wired: `attest` (mint), `revoke` (owner pulls back a previously-
// issued leash by jti — re-publishes the DDB row so public verifiers
// see `revoked=true` on their next status check).
//
// All leash ops are owner-only (phone-required at the device tier) —
// nobody but the user should be able to mint leashes on the user's
// behalf or look up what was minted.
func (mh *MessageHandler) handleLeashOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing leash operation type")
	}

	opType := opParts[1]

	log.Debug().
		Str("owner_space", mh.ownerSpace).
		Str("leash_operation", opType).
		Msg("Routing leash operation")

	switch opType {
	case "attest":
		return mh.leashHandler.HandleGrantAttest(ctx, msg)
	case "revoke":
		return mh.leashHandler.HandleRevoke(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown leash operation: %s", opType))
	}
}

// handleDeviceOperation routes device management operations from the mobile app.
// Format: forVault.device.{sub-operation}
func (mh *MessageHandler) handleDeviceOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing device operation type")
	}

	opType := opParts[1]

	log.Debug().
		Str("owner_space", mh.ownerSpace).
		Str("device_operation", opType).
		Msg("Routing device operation")

	switch opType {
	case "create-invite":
		// Stage 1: app creates a pairing invite for a new desktop
		return mh.connectionsHandler.HandleCreateDeviceInvite(msg)
	case "cancel-invite":
		// User cancelled the pairing invite from the phone before it
		// was claimed by a desktop. Tears down the pending connection
		// record + supersedes the feed event so the in-flight invite
		// stops appearing as its own card.
		return mh.connectionsHandler.HandleCancelDeviceInvite(msg)
	case "request-session":
		// Stage 2 (desktop → vault): request session authorization
		return mh.connectionsHandler.HandleDeviceRequestSession(ctx, msg)
	case "authorize-session":
		// Stage 2 (app → vault): user approves the session with duration
		return mh.connectionsHandler.HandleDeviceAuthorizeSession(ctx, msg)
	case "extend-session":
		// Stage 4: user scans extension QR to rotate keys and extend the session
		return mh.connectionsHandler.HandleDeviceExtendSession(ctx, msg)
	case "list":
		// List active device connections
		return mh.connectionsHandler.HandleListDeviceConnections(ctx, msg)
	case "revoke":
		// Revoke a device connection (from app admin or device logout)
		return mh.connectionsHandler.HandleRevokeDevice(ctx, msg)
	case "end-session":
		// Soft end-session: wipe session key + flip DeviceSession to
		// expired, but keep the connection so the desktop can restart
		// a session without re-pairing.
		return mh.connectionsHandler.HandleDeviceEndSession(ctx, msg)
	case "approval":
		// Phone responds to a pending per-operation approval request (not stage-2 auth)
		return mh.deviceHandler.HandlePhoneApprovalResponse(ctx, msg)
	case "approval-pending":
		// Phone pulls the set of approvals still awaiting its decision —
		// recovers requests missed while the app was killed/offline
		// (forApp.* delivery is core NATS, no replay).
		return mh.deviceHandler.HandleListPendingApprovals(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown device operation: %s", opType))
	}
}

// handleWalletOperation routes Bitcoin wallet operations from the mobile app.
// Format: forVault.wallet.{sub-operation}
func (mh *MessageHandler) handleWalletOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing wallet operation type")
	}
	opType := opParts[1]
	switch opType {
	case "detail":
		return mh.walletHandler.HandleDetail(ctx, msg)
	case "create":
		return mh.walletHandler.HandleCreate(ctx, msg)
	case "list":
		return mh.walletHandler.HandleList(ctx, msg)
	case "get-address":
		return mh.walletHandler.HandleGetAddress(ctx, msg)
	case "get-balance":
		return mh.walletHandler.HandleGetBalance(ctx, msg)
	case "get-fees":
		return mh.walletHandler.HandleGetFees(ctx, msg)
	case "send":
		return mh.walletHandler.HandleSend(ctx, msg)
	case "send-to-connection":
		return mh.walletHandler.HandleSendToConnection(ctx, msg)
	case "request-payment":
		return mh.walletHandler.HandleRequestPayment(ctx, msg)
	case "get-history":
		return mh.walletHandler.HandleGetHistory(ctx, msg)
	case "delete":
		return mh.walletHandler.HandleDelete(ctx, msg)
	case "set-visibility":
		return mh.walletHandler.HandleSetVisibility(ctx, msg)
	case "move-seed-to-credential":
		return mh.walletHandler.HandleMoveSeedToCredential(ctx, msg)
	case "move-seed-to-wallet":
		return mh.walletHandler.HandleMoveSeedToWallet(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown wallet operation: %s", opType))
	}
}

// handleVaultLifecycleOperation routes vault lifecycle operations from the mobile app.
// Format: forVault.vault.{sub-operation}
func (mh *MessageHandler) handleVaultLifecycleOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing vault lifecycle operation type")
	}

	opType := opParts[1]

	switch opType {
	case "snapshot":
		// One-round-trip screen-load bundle: profile + photo +
		// personal-data. See handleVaultSnapshot for the rationale —
		// dominant cost on read ops is per-op overhead (vsock queue,
		// ChaCha20, JSON encode/decode), so bundling 3-5 reads cuts
		// the wall-clock to a fraction.
		return mh.handleVaultSnapshot(ctx, msg)
	case "save":
		// Persist vault state (SQLite + vault state) to S3
		mh.persistVaultStateToS3()
		resp := map[string]interface{}{"success": true, "message": "Vault state saved to S3"}
		respBytes, _ := json.Marshal(resp)
		return mh.successResponse(msg.GetID(), respBytes)
	case "info":
		// Return vault info including handler operations
		info := map[string]interface{}{
			"owner_space":        mh.ownerSpace,
			"has_wallet_handler": mh.walletHandler != nil,
		}
		// List available handler operations
		handlerOps := []string{}
		if mh.walletHandler != nil {
			handlerOps = append(handlerOps, "wallet.create", "wallet.list", "wallet.detail",
				"wallet.get-balance", "wallet.get-address", "wallet.send", "wallet.get-history",
				"wallet.delete", "wallet.set-visibility")
		}
		info["handler_operations"] = handlerOps
		respBytes, _ := json.Marshal(info)
		return mh.successResponse(msg.GetID(), respBytes)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown vault lifecycle operation: %s", opType))
	}
}

// handleAppOperation routes app-related operations (like authenticate)
func (mh *MessageHandler) handleAppOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing app operation type")
	}

	opType := opParts[1] // e.g., "authenticate"

	switch opType {
	case "authenticate":
		return mh.handleAuthenticate(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown app operation: %s", opType))
	}
}

// handleCallOperation routes call-related operations
// Distinguishes between:
// - App requests: call.start, call.accept, call.reject, call.end, call.signal, call.history
// - Incoming vault events: call.initiate, call.offer, call.answer, call.candidate, etc.
func (mh *MessageHandler) handleCallOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing call operation type")
	}

	opType := opParts[1]

	// Peer-to-peer events and app-initiated requests both land on forVault.call.*
	// with the same op suffix (e.g., both "call.accept"). Distinguish by payload
	// shape: peer CallEvents carry an `event_type` field; app requests do not.
	// Without this check, peer accepts get routed to HandleAcceptCall (the
	// app-side handler), and handleCallAccept — which pushes call.accepted to
	// the caller's app — never runs, so the caller hangs in "Calling..." forever.
	var peek struct {
		EventType string `json:"event_type"`
	}
	isPeerEvent := len(msg.Payload) > 0 &&
		unmarshalRequest(msg.Payload, &peek, "handleCallOperation") == nil &&
		peek.EventType != ""

	if !isPeerEvent {
		// App-initiated operations (requests from the mobile app)
		switch opType {
		case "start":
			// App wants to initiate an outgoing call
			return mh.callHandler.HandleInitiateCall(ctx, msg)
		case "accept":
			// App wants to accept an incoming call
			return mh.callHandler.HandleAcceptCall(ctx, msg)
		case "reject":
			// App wants to reject an incoming call
			return mh.callHandler.HandleRejectCall(ctx, msg)
		case "end":
			// App wants to end a call
			return mh.callHandler.HandleEndCall(ctx, msg)
		case "signal":
			// App wants to send WebRTC signaling (offer/answer/candidate)
			return mh.callHandler.HandleSendSignaling(ctx, msg)
		case "history":
			// App wants call history
			return mh.callHandler.HandleGetCallHistory(ctx, msg)
		case "mark-seen":
			// App wants to acknowledge missed calls (clears the bold
			// "Missed call" badge on connection cards)
			return mh.callHandler.HandleMarkCallsSeen(ctx, msg)
		case "turn-credentials":
			// App wants short-lived TURN credentials for WebRTC NAT traversal
			return mh.callHandler.HandleGetTurnCredentials(ctx, msg)
		}
	}

	// Incoming events from other vaults (call.initiate, call.offer, etc.)
	// Wire format is the encrypted envelope. Unwrap with the peer
	// connection's shared secret first; the inner payload is the
	// CallEvent JSON.
	dec, derr := decryptIncomingPeerEnvelope(mh.storage, msg.Payload)
	if derr != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("failed to decrypt call event envelope: %v", derr))
	}
	var event CallEvent
	if err := json.Unmarshal(dec.InnerPayload, &event); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("invalid call event payload: %v", err))
	}

	// Map string to CallEventType (fallback for older peer events that
	// didn't set event_type in the payload itself).
	if event.EventType == "" {
		event.EventType = CallEventType(opType)
	}

	// Handle the incoming call event
	if err := mh.callHandler.HandleCallEvent(ctx, &event); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("call handling error: %v", err))
	}

	return mh.successResponse(msg.GetID(), nil)
}

// handleBlockOperation handles block/unblock requests from the app
func (mh *MessageHandler) handleBlockOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing block operation type")
	}

	opType := opParts[1] // "add" or "remove"

	var req struct {
		TargetID     string `json:"target_id"`
		Reason       string `json:"reason,omitempty"`
		DurationSecs int64  `json:"duration_secs,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "handleBlockOperation"); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("invalid block request: %v", err))
	}

	switch opType {
	case "add":
		if err := mh.callHandler.BlockCaller(ctx, req.TargetID, req.Reason, req.DurationSecs); err != nil {
			return mh.errorResponse(msg.GetID(), err.Error())
		}
	case "remove":
		if err := mh.callHandler.UnblockCaller(ctx, req.TargetID); err != nil {
			return mh.errorResponse(msg.GetID(), err.Error())
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown block operation: %s", opType))
	}

	return mh.successResponse(msg.GetID(), nil)
}

// handleBootstrap handles vault bootstrap request
func (mh *MessageHandler) handleBootstrap(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	response, err := mh.bootstrapHandler.HandleBootstrap(ctx, msg)
	if err != nil {
		return response, err
	}

	// Persist ECIES keys to S3 for cold vault recovery
	// This allows the vault to receive encrypted PINs even after restart
	mh.vaultState.mu.RLock()
	eciesPrivate := mh.vaultState.eciesPrivateKey
	eciesPublic := mh.vaultState.eciesPublicKey
	mh.vaultState.mu.RUnlock()

	log.Debug().
		Str("owner_space", mh.ownerSpace).
		Bool("has_ecies_private", eciesPrivate != nil).
		Bool("has_ecies_public", eciesPublic != nil).
		Bool("has_sealer_proxy", mh.sealerProxy != nil).
		Msg("Checking ECIES storage conditions after bootstrap")

	if eciesPrivate != nil && eciesPublic != nil && mh.sealerProxy != nil {
		// Marshal ECIES keys
		eciesKeys := struct {
			PrivateKey []byte `json:"private_key"`
			PublicKey  []byte `json:"public_key"`
		}{
			PrivateKey: eciesPrivate,
			PublicKey:  eciesPublic,
		}
		eciesData, err := json.Marshal(eciesKeys)
		if err != nil {
			log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to marshal ECIES keys")
		} else {
			defer zeroBytes(eciesData)

			// Seal with KMS
			sealedData, err := mh.sealerProxy.SealCredential(eciesData)
			if err != nil {
				log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to seal ECIES keys")
			} else {
				// Store sealed ECIES keys to S3
				if err := mh.sealerProxy.StoreSealedECIES(sealedData); err != nil {
					log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to store ECIES keys to S3 - cold vault unlock may not work")
				} else {
					log.Info().Str("owner_space", mh.ownerSpace).Msg("ECIES keys sealed and stored to S3 for cold vault recovery")
				}
			}
		}
	}

	return response, nil
}

// handleUnseal handles credential unseal request
func (mh *MessageHandler) handleUnseal(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// TODO: Implement unseal logic
	log.Info().Msg("Unseal requested")
	return mh.successResponse(msg.GetID(), nil)
}

// handleSign handles signing request
func (mh *MessageHandler) handleSign(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// TODO: Implement signing logic
	log.Info().Msg("Sign requested")
	return mh.successResponse(msg.GetID(), nil)
}

// handleSecretsOperation routes secrets-related operations
func (mh *MessageHandler) handleSecretsOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing secrets operation type")
	}

	opType := opParts[1]

	switch opType {
	case "add":
		response, err := mh.secretsHandler.HandleAdd(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "update":
		response, err := mh.secretsHandler.HandleUpdate(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "retrieve":
		return mh.secretsHandler.HandleRetrieve(msg)
	case "delete":
		response, err := mh.secretsHandler.HandleDelete(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "list":
		return mh.secretsHandler.HandleList(msg)
	case "get":
		return mh.secretsHandler.HandleGet(msg)
	case "set-discoverability":
		response, err := mh.secretsHandler.HandleSetDiscoverability(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "identity":
		// Return the user's Ed25519 identity public key from the credential
		return mh.handleGetIdentityPublicKey(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown secrets operation: %s", opType))
	}
}

// handleGetIdentityPublicKey returns the user's Ed25519 identity public key
// This is the user's permanent identity key generated during credential creation
// API: secrets.datastore.identity
func (mh *MessageHandler) handleGetIdentityPublicKey(msg *IncomingMessage) (*OutgoingMessage, error) {
	// Phase D: read from the identity-public-key carve-out so we
	// don't need the full credential plaintext in memory.
	mh.vaultState.mu.RLock()
	idPub := append([]byte(nil), mh.vaultState.identityPublicKey...)
	mh.vaultState.mu.RUnlock()

	if len(idPub) == 0 {
		log.Warn().Str("owner_space", mh.ownerSpace).Msg("Identity public key requested but vault is locked")
		return mh.errorResponse(msg.GetID(), "vault is locked - unlock with PIN first")
	}

	response := map[string]interface{}{
		"success":    true,
		"public_key": base64.StdEncoding.EncodeToString(idPub),
		"key_type":   "Ed25519",
		"is_system":  true,
	}
	responseBytes, _ := json.Marshal(response)

	log.Debug().
		Str("owner_space", mh.ownerSpace).
		Int("key_len", len(idPub)).
		Msg("Identity public key retrieved")

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   responseBytes,
	}, nil
}

// handleVaultSnapshot returns profile + profile photo + personal-data
// in a single response so the desktop Vault home screen renders from
// one round-trip. Per-component fields are optional — a partial
// response (e.g. photo missing) still flips success=true.
func (mh *MessageHandler) handleVaultSnapshot(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// Build sub-messages so each underlying handler sees the input
	// shape it normally would when called directly from forVault.<op>.
	emptyPayload := json.RawMessage("{}")
	profileMsg := &IncomingMessage{
		Type:       MessageTypeVaultOp,
		OwnerSpace: mh.ownerSpace,
		RequestID:  msg.GetID(),
		Subject:    fmt.Sprintf("OwnerSpace.%s.forVault.profile.get", mh.ownerSpace),
		Payload:    emptyPayload,
	}
	photoMsg := &IncomingMessage{
		Type:       MessageTypeVaultOp,
		OwnerSpace: mh.ownerSpace,
		RequestID:  msg.GetID(),
		Subject:    fmt.Sprintf("OwnerSpace.%s.forVault.profile.photo.get", mh.ownerSpace),
		Payload:    emptyPayload,
	}
	pdMsg := &IncomingMessage{
		Type:       MessageTypeVaultOp,
		OwnerSpace: mh.ownerSpace,
		RequestID:  msg.GetID(),
		Subject:    fmt.Sprintf("OwnerSpace.%s.forVault.personal-data.get", mh.ownerSpace),
		Payload:    emptyPayload,
	}

	// Inline rather than goroutines: each constituent handler may
	// poke at the same vault state (data_catalog, profile/_index)
	// and racing them under the throttle gets thorny. Sequential is
	// fine — the cost we're saving is round-trip + persist, not
	// in-handler CPU.
	profileResp, profileErr := mh.handleProfileOperation(ctx, profileMsg, []string{"profile", "get"})
	photoResp, photoErr := mh.handleProfileOperation(ctx, photoMsg, []string{"profile", "photo", "get"})
	pdResp, pdErr := mh.handlePersonalDataOperation(ctx, pdMsg, []string{"personal-data", "get"})

	bundle := map[string]interface{}{
		"success": true,
	}
	// Each component lands as a JSON-decoded object so the desktop
	// can pull fields without a second parse step.
	if profileErr == nil && profileResp != nil && profileResp.Type != MessageTypeError && len(profileResp.Payload) > 0 {
		var v interface{}
		if json.Unmarshal(profileResp.Payload, &v) == nil {
			bundle["profile"] = v
		}
	}
	if photoErr == nil && photoResp != nil && photoResp.Type != MessageTypeError && len(photoResp.Payload) > 0 {
		var v interface{}
		if json.Unmarshal(photoResp.Payload, &v) == nil {
			bundle["photo"] = v
		}
	}
	if pdErr == nil && pdResp != nil && pdResp.Type != MessageTypeError && len(pdResp.Payload) > 0 {
		var v interface{}
		if json.Unmarshal(pdResp.Payload, &v) == nil {
			bundle["personal_data"] = v
		}
	}

	respBytes, _ := json.Marshal(bundle)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// handleProfileOperation routes profile-related operations
func (mh *MessageHandler) handleProfileOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing profile operation type")
	}

	opType := opParts[1]

	switch opType {
	case "get":
		return mh.profileHandler.HandleGet(msg)
	case "update":
		response, err := mh.profileHandler.HandleUpdate(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		// data_catalog reflects every non-private field — broadcast
		// so peers' cached _peer_profile mirrors what the owner sees.
		go RepublishProfile(mh.ownerSpace, mh.storage, mh.publisher, mh.vaultState)
		return response, nil
	case "delete":
		response, err := mh.profileHandler.HandleDelete(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		go RepublishProfile(mh.ownerSpace, mh.storage, mh.publisher, mh.vaultState)
		return response, nil
	case "get-shared":
		return mh.profileHandler.HandleGetShared(msg)
	case "sharing-settings":
		// Handle sub-operations for sharing settings
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing sharing-settings operation")
		}
		switch opParts[2] {
		case "get":
			return mh.profileHandler.HandleGetSharingSettings(msg)
		case "update":
			response, err := mh.profileHandler.HandleUpdateSharingSettings(msg)
			if err != nil {
				return response, err
			}
			mh.persistVaultStateToS3()
			return response, nil
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown sharing-settings operation: %s", opParts[2]))
		}
	case "categories":
		// Handle category operations (predefined + custom)
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing categories operation")
		}
		switch opParts[2] {
		case "get":
			return mh.profileHandler.HandleCategoriesGet(msg)
		case "update":
			response, err := mh.profileHandler.HandleCategoriesUpdate(msg)
			if err != nil {
				return response, err
			}
			mh.persistVaultStateToS3()
			return response, nil
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown categories operation: %s", opParts[2]))
		}
	case "public":
		// Handle public profile operations
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing public operation")
		}
		switch opParts[2] {
		case "get":
			return mh.profileHandler.HandlePublicSettingsGet(msg)
		case "update":
			response, err := mh.profileHandler.HandlePublicSettingsUpdate(msg)
			if err != nil {
				return response, err
			}
			mh.persistVaultStateToS3()
			return response, nil
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown public operation: %s", opParts[2]))
		}
	case "publish":
		// Publish public profile to NATS
		response, err := mh.profileHandler.HandlePublish(ctx, msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "broadcast":
		// Push the current published profile snapshot to every active
		// peer. Alias for notification.profile-broadcast — the app uses
		// the profile.* namespace for everything profile-shaped, so we
		// route it here too. The heavy lifting lives in the
		// NotificationsHandler.
		return mh.notificationsHandler.HandleProfileBroadcast(msg)
	case "get-published":
		// Get the last published profile (what connections see)
		return mh.profileHandler.HandleGetPublished(msg)
	case "photo":
		// Handle photo operations
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing photo operation")
		}
		switch opParts[2] {
		case "get":
			return mh.profileHandler.HandlePhotoGet(msg)
		case "update":
			response, err := mh.profileHandler.HandlePhotoUpdate(msg)
			if err != nil {
				return response, err
			}
			mh.persistVaultStateToS3()
			return response, nil
		case "delete":
			response, err := mh.profileHandler.HandlePhotoDelete(msg)
			if err != nil {
				return response, err
			}
			mh.persistVaultStateToS3()
			return response, nil
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown photo operation: %s", opParts[2]))
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown profile operation: %s", opType))
	}
}

// handlePersonalDataOperation routes personal data operations
func (mh *MessageHandler) handlePersonalDataOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing personal-data operation type")
	}

	opType := opParts[1]

	switch opType {
	case "get":
		return mh.personalDataHandler.HandleGet(msg)
	case "update":
		response, err := mh.personalDataHandler.HandleUpdate(msg)
		if err != nil {
			return response, err
		}
		// Persist vault state to S3 after successful update
		mh.persistVaultStateToS3()
		// Catalog (data_catalog) just changed — fan the new snapshot
		// out to peers so their cached _peer_profile mirrors what the
		// owner sees in their own profile preview.
		go RepublishProfile(mh.ownerSpace, mh.storage, mh.publisher, mh.vaultState)
		return response, nil
	case "delete":
		response, err := mh.personalDataHandler.HandleDelete(msg)
		if err != nil {
			return response, err
		}
		// Persist vault state to S3 after successful delete
		mh.persistVaultStateToS3()
		go RepublishProfile(mh.ownerSpace, mh.storage, mh.publisher, mh.vaultState)
		return response, nil
	case "update-sort-order":
		response, err := mh.personalDataHandler.HandleUpdateSortOrder(msg)
		if err != nil {
			return response, err
		}
		// Persist vault state to S3 after successful sort order update
		mh.persistVaultStateToS3()
		// Sort-order doesn't change WHAT is exposed in data_catalog
		// (content), only ordering on the owner's screen. No broadcast
		// needed — peers don't see ordering.
		return response, nil
	case "get-sort-order":
		return mh.personalDataHandler.HandleGetSortOrder(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown personal-data operation: %s", opType))
	}
}

// PersistVaultStateToS3 is the exported, force-flush variant. Bypasses
// the throttle in persistVaultStateToS3 so callers that need a
// guaranteed flush — graceful shutdown, decommission, post-PIN
// commit points — actually land on S3 before they return.
//
// Use this sparingly. The throttled variant is correct for the
// "after every request" hot path.
func (mh *MessageHandler) PersistVaultStateToS3() {
	mh.flushVaultStateToS3()
}

// shouldRefuseShrink returns true when the new vault-state payload is
// drastically smaller than what this instance previously saw — the
// shape of the 2026-05-06 / 2026-05-09 data-loss incidents (220 KB
// vault_state.enc clobbered by a 12 KB stub from an instance that
// hadn't fully loaded the user's data). prevSize == 0 means we have
// no reference point (fresh enrollment, first write) and the guard
// is a no-op.
//
// Threshold: existing must be at least 50 KB AND new must be less
// than half. Below 50 KB everything is small enough that legitimate
// edits could halve the size; above that floor a 50% drop strongly
// implies state loss.
func shouldRefuseShrink(prevSize, newSize int64) bool {
	const shrinkGuardFloor = int64(50 * 1024)
	if prevSize < shrinkGuardFloor {
		return false
	}
	return newSize*2 < prevSize
}

// shouldThrottlePersist returns true when a non-forced persist call
// arriving at `now` should be skipped because the previous flush was
// less than `window` ago. Extracted as a pure function so the
// regression test in persist_throttle_test.go exercises THIS check
// directly rather than a parallel copy that could drift under future
// edits.
func shouldThrottlePersist(now, lastPersist time.Time, window time.Duration) bool {
	return now.Sub(lastPersist) < window
}

// persistVaultStateToS3 is the throttled wrapper used by the main
// request loop and every handler-level persist site. Persists are
// rate-limited to one per persistDebounceInterval — a burst of
// mutations within the window collapses into a single S3 write,
// cutting the noncurrent-version count and storage cost dramatically
// without changing the "auto-persist after every successful request"
// semantics callers expect.
//
// If the throttle skips, the data sits in vault-manager memory
// (encrypted SQLite + crypto carve-outs) until the next non-throttled
// persist or a graceful shutdown via PersistVaultStateToS3. A crash
// inside the throttle window loses at most that window's worth of
// edits — acceptable given the alternative (~one S3 write per
// handler call, ~hundreds per session).
func (mh *MessageHandler) persistVaultStateToS3() {
	mh.persistMu.Lock()
	if shouldThrottlePersist(time.Now(), mh.lastPersistTime, persistDebounceInterval) {
		mh.persistMu.Unlock()
		return
	}
	// Update lastPersistTime BEFORE the flush so concurrent callers
	// land on the throttled branch even while this flush is in flight.
	// On flush failure we leave the timestamp set: the next call within
	// the window is still skipped; retries continue at the cadence.
	mh.lastPersistTime = time.Now()
	mh.persistMu.Unlock()
	mh.flushVaultStateToS3()
}

// flushVaultStateToS3 is the unconditional flush: dek/loaded gates,
// shrink guard, S3 PUT, size update. Called by both the throttled
// path (persistVaultStateToS3) after the throttle window opens, and
// by PersistVaultStateToS3 (shutdown/decommission) directly.
func (mh *MessageHandler) flushVaultStateToS3() {
	mh.vaultState.mu.RLock()
	dek := mh.vaultState.dek
	dataLoaded := mh.vaultState.vaultDataLoaded
	prevSize := mh.vaultState.loadedVaultStateSize
	revoked := mh.vaultState.ownershipRevoked
	selfEvict := mh.vaultState.selfEvictRequested
	mh.vaultState.mu.RUnlock()

	// D3: once a split-brain conflict has been detected and
	// self-eviction is pending, don't even attempt another write —
	// our ETag is known-stale, so it would just conflict again.
	// The subprocess is exiting; the fresh one will cold-reload.
	if selfEvict {
		log.Warn().Str("owner_space", mh.ownerSpace).
			Msg("skipping vault state persist — D3 self-eviction pending")
		return
	}

	// SECURITY: refuse to persist once routing ownership is revoked.
	// This is the in-window half of the split-brain fix (D2): when
	// this user is handed off / reclaimed, the parent sends
	// revoke_ownership and this flag goes up. Without this guard, the
	// OLD subprocess's in-flight request would still run its tail-end
	// force-flush and clobber the NEW owner's vault_state.enc — exactly
	// the 2026-05-13 corruption (stale UTK pool + credential blob).
	// Checked FIRST so it short-circuits before createEncryptedVaultState.
	if revoked {
		log.Error().Str("owner_space", mh.ownerSpace).
			Msg("SECURITY: REFUSING to persist vault state — routing ownership has been revoked (split-brain guard)")
		return
	}

	if dek == nil || mh.sealerProxy == nil {
		log.Warn().Str("owner_space", mh.ownerSpace).Msg("Cannot persist vault state — DEK not available (vault locked)")
		return
	}

	// SECURITY: refuse to persist if this instance has not loaded the
	// user's vault state. The 2026-05-09 incident: a credential.migration.start
	// request landed on an enclave instance whose in-memory storage was
	// stale/empty for this user; persistFn ran and overwrote a 220KB S3
	// vault_state with a 12KB stub, wiping the user's data. The flag is
	// set on cold-unlock-from-S3, on warm-unlock (already loaded), and
	// on fresh enrollment. Any other code path that tries to persist
	// without going through one of those is by definition writing
	// incomplete state and would silently corrupt S3.
	if !dataLoaded {
		log.Warn().
			Str("owner_space", mh.ownerSpace).
			Msg("REFUSING to persist vault state — this instance has not loaded the user's data from S3 (would overwrite with stale/empty state)")
		return
	}

	encryptedState, contentHash, err := mh.createEncryptedVaultState(dek)
	if err != nil {
		log.Error().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to create encrypted vault state for persistence")
		return
	}

	// WS3: skip the S3 PUT when the vault state is byte-identical to
	// what we last successfully flushed. The main loop calls persist
	// after every successful op (reads included) and a periodic timer
	// flushes on top — without this guard a polling-only vault
	// re-uploads the full multi-hundred-KB DB every debounce window
	// forever. Skipping an identical write is a guaranteed no-op: the
	// S3 object already holds exactly this content. lastFlushedStateHash
	// is set only after a *successful* store, so a failed store leaves
	// it stale and the next call retries.
	mh.vaultState.mu.RLock()
	unchanged := contentHash == mh.vaultState.lastFlushedStateHash
	mh.vaultState.mu.RUnlock()
	if unchanged {
		log.Debug().Str("owner_space", mh.ownerSpace).
			Msg("vault state unchanged since last flush — skipping S3 PUT")
		return
	}

	// SECURITY: shrink guard (architect §3). If we previously loaded
	// (or wrote) >= 50 KB of state and the new payload is < 50% of that,
	// the write looks like the 2026-05-06 / 2026-05-09 incident shape:
	// in-memory state was incomplete and we're about to clobber a
	// healthy S3 object with a stub. Refuse and log loudly so the
	// operator notices in CloudWatch. Legitimate edits (delete one
	// field, shrink a single record) stay well above 50% — only
	// catastrophic state loss trips this threshold.
	newSize := int64(len(encryptedState))
	if shouldRefuseShrink(prevSize, newSize) {
		log.Error().
			Str("owner_space", mh.ownerSpace).
			Int64("previous_size", prevSize).
			Int64("new_size", newSize).
			Msg("SECURITY: REFUSING to persist vault state — payload shrunk drastically (possible data-loss bug). Investigate before retrying.")
		return
	}

	// D3: stamp generation+1 and wrap before storing. Conditional put
	// uses IfMatch=loadedETag on every store after the first, and
	// IfNoneMatch=* on the very first store of this vault's lifetime
	// (no ETag and generation still 0). On conflict we fence further
	// writes via ownershipRevoked — same mechanism D2 uses for the
	// routing-handoff case — because a 412 here means another writer
	// touched our object and our in-memory state is no longer the
	// truth.
	mh.vaultState.mu.RLock()
	prevETag := mh.vaultState.loadedVaultStateETag
	prevGen := mh.vaultState.vaultStateGeneration
	mh.vaultState.mu.RUnlock()

	nextGen := prevGen + 1
	wrapped, err := wrapVaultState(encryptedState, nextGen)
	if err != nil {
		log.Error().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to wrap vault state for persistence")
		return
	}

	firstWrite := prevETag == "" && prevGen == 0
	newETag, storeErr := mh.sealerProxy.StoreVaultState(wrapped, prevETag, firstWrite)
	if storeErr != nil {
		if errors.Is(storeErr, ErrVaultStateConflict) {
			// Distinguish first-write conflict from update-write conflict:
			//
			//   - first-write conflict (IfNoneMatch:* rejected): the S3
			//     object already exists. Means the prior vault's
			//     vault_state.enc wasn't cleaned up (likely a stale
			//     object that survived decommission). NOT a split-brain
			//     between two live writers — there is no other live
			//     writer; just leftover state. Refuse the persist, log
			//     loudly, but do NOT trip ownershipRevoked, since
			//     fencing the (only) live owner would break enrollment
			//     and every subsequent op with "vault ownership
			//     transferred — retry". (Pixel 7 mesmer enrollment
			//     2026-05-16.)
			//
			//   - update-write conflict (IfMatch rejected): the object's
			//     ETag changed underneath us. Means another writer is
			//     racing this object — that IS split-brain. We refuse
			//     this write (no corruption) and request self-eviction:
			//     the main loop exits the subprocess and the next op
			//     spawns a fresh one that cold-loads whichever
			//     vault_state.enc won the race.
			//
			//     This used to latch ownershipRevoked permanently —
			//     but that flag assumes the supervisor kills us right
			//     after (true for an external revoke_ownership, false
			//     here: a self-detected D3 conflict has nothing
			//     external to kill us). The result was a subprocess
			//     wedged forever, refusing every op, until the whole
			//     EC2 instance was terminated. Self-eviction turns
			//     that permanent wedge into a one-op self-heal.
			if firstWrite {
				log.Error().
					Str("owner_space", mh.ownerSpace).
					Msg("D3: first-write rejected — vault_state.enc already exists at this key. Likely a stale object from a prior decommission that wasn't cleaned up. Refusing to overwrite; investigate manually.")
				return
			}
			log.Error().
				Str("owner_space", mh.ownerSpace).
				Str("expected_etag", prevETag).
				Int64("prev_gen", prevGen).
				Msg("SECURITY: D3 split-brain detected on update-write — refusing write, requesting self-eviction to cold-reload")
			mh.vaultState.mu.Lock()
			mh.vaultState.selfEvictRequested = true
			mh.vaultState.mu.Unlock()
			return
		}
		log.Error().Err(storeErr).Str("owner_space", mh.ownerSpace).Msg("Failed to persist vault state to S3")
		return
	}
	log.Info().
		Str("owner_space", mh.ownerSpace).
		Int64("size", newSize).
		Int64("generation", nextGen).
		Str("etag", newETag).
		Msg("Vault state persisted to S3")

	// Track the size we just wrote so subsequent writes have a
	// reference point. If we never load again before the next write,
	// the shrink guard still works against this size. Also stamp the
	// returned ETag + bumped generation for the next conditional put.
	mh.vaultState.mu.Lock()
	mh.vaultState.loadedVaultStateSize = newSize
	mh.vaultState.loadedVaultStateETag = newETag
	mh.vaultState.vaultStateGeneration = nextGen
	mh.vaultState.lastFlushedStateHash = contentHash
	mh.vaultState.mu.Unlock()
}

// handleCredentialOperation routes credential-related operations
func (mh *MessageHandler) handleCredentialOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing credential operation type")
	}

	opType := opParts[1]

	switch opType {
	case "create":
		// Protean Credential creation (Phase 3 of enrollment)
		response, err := mh.proteanCredentialHandler.HandleCredentialCreate(ctx, msg)
		if err != nil {
			return response, err
		}

		// Persist vault state to S3 for cold vault recovery
		mh.vaultState.mu.RLock()
		dek := mh.vaultState.dek
		revoked := mh.vaultState.ownershipRevoked
		mh.vaultState.mu.RUnlock()

		// SECURITY: same split-brain guard as flushVaultStateToS3 — this
		// inline enrollment-time persist bypasses flushVaultStateToS3, so
		// it needs its own ownershipRevoked check.
		if revoked {
			log.Error().Str("owner_space", mh.ownerSpace).
				Msg("SECURITY: REFUSING to persist vault state after credential.create — routing ownership revoked (split-brain guard)")
		} else if dek != nil && mh.sealerProxy != nil {
			// Create encrypted vault state for S3 storage. The content
			// hash is unused here — enrollment's first write always
			// stores unconditionally.
			encryptedState, _, err := mh.createEncryptedVaultState(dek)
			if err != nil {
				log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to create encrypted vault state")
			} else {
				// D3: enrollment is the canonical first-write. Use
				// IfNoneMatch:* so that if a vault_state.enc already
				// exists for this owner_space (a re-enrollment race or
				// stale S3 object that should have been decommissioned)
				// we refuse to overwrite. Generation stamped at 1.
				mh.vaultState.mu.RLock()
				prevETag := mh.vaultState.loadedVaultStateETag
				prevGen := mh.vaultState.vaultStateGeneration
				mh.vaultState.mu.RUnlock()
				nextGen := prevGen + 1
				wrapped, werr := wrapVaultState(encryptedState, nextGen)
				if werr != nil {
					log.Warn().Err(werr).Str("owner_space", mh.ownerSpace).Msg("Failed to wrap vault state for enrollment persist")
				} else {
					firstWrite := prevETag == "" && prevGen == 0
					newETag, serr := mh.sealerProxy.StoreVaultState(wrapped, prevETag, firstWrite)
					if serr != nil {
						if errors.Is(serr, ErrVaultStateConflict) {
							log.Error().Str("owner_space", mh.ownerSpace).Msg("SECURITY: enrollment-time vault_state.enc conflict — refusing to clobber existing object")
						} else {
							log.Warn().Err(serr).Str("owner_space", mh.ownerSpace).Msg("Failed to store vault state to S3 - cold vault unlock may not work")
						}
					} else {
						log.Info().
							Str("owner_space", mh.ownerSpace).
							Int64("generation", nextGen).
							Str("etag", newETag).
							Msg("Vault state encrypted and stored to S3 for cold vault recovery")
						mh.vaultState.mu.Lock()
						mh.vaultState.loadedVaultStateETag = newETag
						mh.vaultState.vaultStateGeneration = nextGen
						mh.vaultState.mu.Unlock()
					}
				}
			}
		}

		// NOTE: DEK is intentionally NOT cleared here after credential.create
		// The enrollment flow continues with personal-data.update and profile.publish
		// which also need DEK for persistence. DEK will be cleared on:
		// - Vault decommission (credential.delete)
		// - Vault manager restart
		// - Re-authentication (future)

		return response, nil
	case "store":
		return mh.credentialHandler.HandleStore(msg)
	case "sync":
		return mh.credentialHandler.HandleSync(msg)
	case "get":
		return mh.credentialHandler.HandleGet(msg)
	case "version":
		return mh.credentialHandler.HandleVersion(msg)
	case "delete":
		// Delete credential (for vault decommission)
		// First clear in-memory state, then delete from storage
		mh.proteanCredentialHandler.ClearCredential()
		return mh.credentialHandler.HandleDelete(msg)
	case "password-change":
		// Change the credential password (Argon2id PHC hash)
		response, err := mh.proteanCredentialHandler.HandlePasswordChange(ctx, msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "identity-unlock":
		// Phase E: re-populate the identity-key carve-out after the
		// sliding TTL has elapsed. Decrypts the request-supplied
		// credential blob, verifies the password, copies the identity
		// keypair into vaultState, and starts a fresh window.
		return mh.handleCredentialIdentityUnlock(ctx, msg)
	case "secret":
		// Critical secrets stored within Protean Credential
		return mh.handleCredentialSecretOperation(ctx, msg, opParts[1:])
	case "migration":
		// Migration status, config, and the deprecated start endpoint.
		// The acknowledge sub-op was removed in M2 (architect redesign,
		// 2026-05-09); old apps that still call it will receive an
		// "unknown credential.migration operation" error.
		return mh.handleCredentialMigrationOperation(ctx, msg, opParts[1:])
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown credential operation: %s", opType))
	}
}

// handleCredentialSecretOperation routes credential.secret.* operations
// These are critical secrets (seed phrases, private keys, etc.) that require password verification
func (mh *MessageHandler) handleCredentialSecretOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing credential.secret operation type")
	}

	opType := opParts[1]

	switch opType {
	case "add":
		return mh.credentialSecretHandler.HandleAdd(msg)
	case "get":
		return mh.credentialSecretHandler.HandleGet(msg)
	case "list":
		return mh.credentialSecretHandler.HandleList(msg)
	case "delete":
		return mh.credentialSecretHandler.HandleDelete(msg)
	case "set-discoverability":
		return mh.credentialSecretHandler.HandleSetDiscoverability(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown credential.secret operation: %s", opType))
	}
}

// handleCredentialMigrationOperation routes credential.migration.* operations
func (mh *MessageHandler) handleCredentialMigrationOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing credential.migration operation type")
	}

	opType := opParts[1]

	switch opType {
	case "status":
		// Deprecated; returns "none" stub. Pin-unlock response is the
		// canonical migration completion signal post-redesign.
		return mh.migrationHandler.HandleStatus(ctx, msg)
	case "config":
		return mh.migrationHandler.HandleGetConfig(ctx, msg)
	case "start":
		// Deprecated; PIN-unlock-coupled re-seal (M1) is the new path.
		return mh.migrationHandler.HandleStart(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown credential.migration operation: %s", opType))
	}
}

// handleMessageOperation routes messaging-related operations
func (mh *MessageHandler) handleMessageOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing message operation type")
	}

	opType := opParts[1]

	switch opType {
	case "send":
		return mh.messagingHandler.HandleSend(msg)
	case "list":
		return mh.messagingHandler.HandleList(msg)
	case "get-transport-key":
		return mh.messagingHandler.HandleGetTransportKey(msg)
	case "incoming":
		return mh.messagingHandler.HandleIncomingPeerMessage(ctx, msg)
	case "read-receipt":
		return mh.messagingHandler.HandleReadReceipt(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown message operation: %s", opType))
	}
}

// handleConnectionOperation routes connection-related operations
func (mh *MessageHandler) handleConnectionOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing connection operation type")
	}

	opType := opParts[1]

	switch opType {
	case "create-invite":
		response, err := mh.connectionsHandler.HandleCreateInvite(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "resolve-invite":
		return mh.connectionsHandler.HandleResolveInvite(msg)
	// connection.store-credentials over forVault (OwnerSpace) had no
	// live caller — the agent/device pairing flow shipped its
	// credentials in via MessageSpace.<us>.forOwner.connection
	// .store-credentials, and the local-app `ConnectionsClient
	// .storeCredentials(...)` API was never wired up to anything.
	// The MessageSpace route at line ~631 is the canonical (and
	// invite-code-gated) path; this OwnerSpace duplicate is removed
	// to eliminate the dual gate surface.
	case "initiate":
		response, err := mh.connectionsHandler.HandleInitiate(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "respond":
		response, err := mh.connectionsHandler.HandleRespond(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "revoke":
		// Capture the connection_id before invoking so we can drop the
		// per-connection grant blob even if HandleRevoke mutates state.
		var revokeReq struct {
			ConnectionID string `json:"connection_id"`
		}
		_ = json.Unmarshal(msg.Payload, &revokeReq)
		response, err := mh.connectionsHandler.HandleRevoke(msg)
		if err != nil {
			return response, err
		}
		if revokeReq.ConnectionID != "" {
			mh.clearConnectionGrants(revokeReq.ConnectionID)
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "list":
		return mh.connectionsHandler.HandleList(msg)
	case "get":
		return mh.connectionsHandler.HandleGet(msg)
	case "update":
		response, err := mh.connectionsHandler.HandleUpdate(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "get-capabilities":
		return mh.connectionsHandler.HandleGetCapabilities(msg)
	case "activity-summary":
		return mh.connectionsHandler.HandleActivitySummary(msg)
	case "rotate":
		response, err := mh.connectionsHandler.HandleRotate(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "get-credentials":
		return mh.connectionsHandler.HandleGetCredentials(msg)
	case "audit":
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing audit operation (list|search)")
		}
		if mh.auditHandler == nil {
			return mh.errorResponse(msg.GetID(), "audit handler unavailable")
		}
		switch opParts[2] {
		case "list":
			return mh.auditHandler.HandleList(msg)
		case "search":
			return mh.auditHandler.HandleSearch(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown audit operation: %s", opParts[2]))
		}
	case "agent":
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing agent connection operation")
		}
		switch opParts[2] {
		case "create-invite":
			response, err := mh.connectionsHandler.HandleCreateAgentInvite(msg)
			if err != nil {
				return response, err
			}
			mh.persistVaultStateToS3()
			return response, nil
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown agent operation: %s", opParts[2]))
		}
	case "share-handlers":
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing share-handlers operation (get|set)")
		}
		switch opParts[2] {
		case "get":
			return mh.handleShareHandlersGet(msg)
		case "set":
			resp, err := mh.handleShareHandlersSet(msg)
			if err != nil {
				return resp, err
			}
			mh.persistVaultStateToS3()
			return resp, nil
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown share-handlers operation: %s", opParts[2]))
		}
	case "share-policy":
		// Phase 2: per-connection sharing policy (the unified store).
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing share-policy operation (get|set)")
		}
		switch opParts[2] {
		case "get":
			return mh.handleSharePolicyGet(msg)
		case "set":
			return mh.handleSharePolicySet(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown share-policy operation: %s", opParts[2]))
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown connection operation: %s", opType))
	}
}

// handleShareHandlersGet returns the per-connection grant blob plus the
// surfaced catalog so the app can render the toggles.
//
//	body: {"connection_id": "<id>"}
func (mh *MessageHandler) handleShareHandlersGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil || req.ConnectionID == "" {
		return mh.errorResponse(msg.GetID(), "connection_id required")
	}
	grants, err := mh.getConnectionGrants(req.ConnectionID)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}
	respBytes, _ := json.Marshal(map[string]interface{}{
		"connection_id": req.ConnectionID,
		"granted":       grants.Granted,
		"updated_at":    grants.UpdatedAt,
	})
	return mh.successResponse(msg.GetID(), respBytes)
}

// handleShareHandlersSet replaces the per-connection grant blob.
//
//	body: {"connection_id": "<id>", "granted": {"wallet": true, "call": false}}
func (mh *MessageHandler) handleShareHandlersSet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string          `json:"connection_id"`
		Granted      map[string]bool `json:"granted"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil || req.ConnectionID == "" {
		return mh.errorResponse(msg.GetID(), "connection_id and granted map required")
	}
	if err := mh.setConnectionGrants(req.ConnectionID, req.Granted); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
	})
	return mh.successResponse(msg.GetID(), respBytes)
}

// handleSharePolicyGet returns the per-connection share policy or
// the empty default if none is set.
func (mh *MessageHandler) handleSharePolicyGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil || req.ConnectionID == "" {
		return mh.errorResponse(msg.GetID(), "connection_id required")
	}
	policy := loadSharePolicy(mh.storage, req.ConnectionID)
	if policy == nil {
		policy = defaultSharePolicy()
	}
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
		"policy":        policy,
	})
	return mh.successResponse(msg.GetID(), respBytes)
}

// handleSharePolicySet merges new items into the policy. The payload's
// `items` map is keyed by SharePolicyKey ("<kind>:<id>"). To clear an
// item entirely, send `{allowed:false}` rather than omitting it (we
// don't currently support a "remove key" operation — that's Phase 3
// fast-follow if it's needed).
func (mh *MessageHandler) handleSharePolicySet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string                     `json:"connection_id"`
		Items        map[string]SharePolicyItem `json:"items"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil || req.ConnectionID == "" {
		return mh.errorResponse(msg.GetID(), "connection_id and items required")
	}
	if err := MergePolicyItems(mh.storage, req.ConnectionID, req.Items); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}
	policy := loadSharePolicy(mh.storage, req.ConnectionID)
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
		"policy":        policy,
	})
	return mh.successResponse(msg.GetID(), respBytes)
}

// handleNotificationOperation routes notification-related operations
func (mh *MessageHandler) handleNotificationOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing notification operation type")
	}

	opType := opParts[1]

	switch opType {
	case "profile-broadcast":
		return mh.notificationsHandler.HandleProfileBroadcast(msg)
	case "revoke-notify":
		return mh.notificationsHandler.HandleRevokeNotify(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown notification operation: %s", opType))
	}
}

// handleVoteOperation routes voting-related operations
func (mh *MessageHandler) handleVoteOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing vote operation type")
	}

	opType := opParts[1]

	switch opType {
	case "list":
		return mh.voteHandler.HandleListProposals(ctx, msg)
	case "cast":
		return mh.voteHandler.HandleCastVote(ctx, msg)
	case "verify":
		return mh.voteHandler.HandleVerifyVote(ctx, msg)
	case "resubmit-pending":
		return mh.voteHandler.HandleResubmitPendingVotes(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown vote operation: %s", opType))
	}
}

// handleFeedOperation routes feed-related operations
func (mh *MessageHandler) handleFeedOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing feed operation type")
	}

	opType := opParts[1]

	switch opType {
	case "list":
		return mh.handleFeedList(ctx, msg)
	case "get":
		return mh.handleFeedGet(ctx, msg)
	case "read":
		return mh.handleFeedRead(ctx, msg)
	case "archive":
		return mh.handleFeedArchive(ctx, msg)
	case "delete":
		return mh.handleFeedDelete(ctx, msg)
	case "set-priority":
		return mh.handleFeedSetPriority(ctx, msg)
	case "action":
		return mh.handleFeedAction(ctx, msg)
	case "sync":
		return mh.handleFeedSync(ctx, msg)
	case "settings":
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing settings operation")
		}
		switch opParts[2] {
		case "get":
			return mh.handleFeedSettingsGet(ctx, msg)
		case "update":
			return mh.handleFeedSettingsUpdate(ctx, msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown settings operation: %s", opParts[2]))
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown feed operation: %s", opType))
	}
}

// handleGuideOperation routes guide-related operations
func (mh *MessageHandler) handleGuideOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing guide operation type")
	}

	opType := opParts[1]

	switch opType {
	case "sync":
		return mh.guideHandler.HandleSync(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown guide operation: %s", opType))
	}
}

// handleLocationOperation routes location-related operations
func (mh *MessageHandler) handleLocationOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing location operation type")
	}

	opType := opParts[1]

	switch opType {
	case "add":
		response, err := mh.locationHandler.HandleAdd(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "list":
		return mh.locationHandler.HandleList(msg)
	case "delete":
		response, err := mh.locationHandler.HandleDelete(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "delete-all":
		response, err := mh.locationHandler.HandleDeleteAll(msg)
		if err != nil {
			return response, err
		}
		mh.persistVaultStateToS3()
		return response, nil
	case "stats":
		return mh.locationHandler.HandleStats(msg)
	case "settings":
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing settings operation")
		}
		switch opParts[2] {
		case "get":
			return mh.locationHandler.HandleSettingsGet(msg)
		case "update":
			response, err := mh.locationHandler.HandleSettingsUpdate(msg)
			if err != nil {
				return response, err
			}
			mh.persistVaultStateToS3()
			return response, nil
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown location settings operation: %s", opParts[2]))
		}
	case "sharing":
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing sharing operation")
		}
		switch opParts[2] {
		case "toggle":
			response, err := mh.locationHandler.HandleSharingToggle(msg)
			if err != nil {
				return response, err
			}
			mh.persistVaultStateToS3()
			return response, nil
		case "list":
			return mh.locationHandler.HandleSharingList(msg)
		case "push":
			response, err := mh.locationHandler.HandleSharingPush(msg)
			if err != nil {
				return response, err
			}
			mh.persistVaultStateToS3()
			return response, nil
		case "set-auto-fulfill":
			response, err := mh.locationHandler.HandleSetAutoFulfill(msg)
			if err != nil {
				return response, err
			}
			mh.persistVaultStateToS3()
			return response, nil
		case "get-auto-fulfill":
			return mh.locationHandler.HandleGetAutoFulfill(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown location sharing operation: %s", opParts[2]))
		}
	case "peer":
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing peer operation")
		}
		switch opParts[2] {
		case "get":
			return mh.locationHandler.HandlePeerGet(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown location peer operation: %s", opParts[2]))
		}
	case "request":
		return mh.locationHandler.HandleRequest(msg)
	case "send-once":
		return mh.locationHandler.HandleSendOnce(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown location operation: %s", opType))
	}
}

// handleAuditOperation routes audit-related operations
func (mh *MessageHandler) handleAuditOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing audit operation type")
	}

	opType := opParts[1]

	switch opType {
	case "query":
		return mh.handleAuditQuery(ctx, msg)
	case "export":
		return mh.handleAuditExport(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown audit operation: %s", opType))
	}
}

// --- Feed Operation Handlers ---

func (mh *MessageHandler) handleFeedList(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req FeedListRequest
	if err := unmarshalRequest(msg.Payload, &req, "handleFeedList"); err != nil {
		req = FeedListRequest{} // Use defaults
	}

	resp, err := mh.eventHandler.ListFeed(ctx, &req)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedGet(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		EventID string `json:"event_id"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "handleFeedGet"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.EventID == "" {
		return mh.errorResponse(msg.GetID(), "event_id is required")
	}

	event, err := mh.eventHandler.GetEvent(ctx, req.EventID)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}
	if event == nil {
		return mh.errorResponse(msg.GetID(), "event not found")
	}

	respBytes, _ := json.Marshal(event)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedRead(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req FeedUpdateStatusRequest
	if err := unmarshalRequest(msg.Payload, &req, "handleFeedRead"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.EventID == "" {
		return mh.errorResponse(msg.GetID(), "event_id is required")
	}

	if err := mh.eventHandler.MarkRead(ctx, req.EventID); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	resp := map[string]interface{}{"success": true, "event_id": req.EventID}
	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedArchive(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req FeedUpdateStatusRequest
	if err := unmarshalRequest(msg.Payload, &req, "handleFeedArchive"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.EventID == "" {
		return mh.errorResponse(msg.GetID(), "event_id is required")
	}

	if err := mh.eventHandler.Archive(ctx, req.EventID); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	resp := map[string]interface{}{"success": true, "event_id": req.EventID}
	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedDelete(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req FeedUpdateStatusRequest
	if err := unmarshalRequest(msg.Payload, &req, "handleFeedDelete"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.EventID == "" {
		return mh.errorResponse(msg.GetID(), "event_id is required")
	}

	if err := mh.eventHandler.Delete(ctx, req.EventID); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	resp := map[string]interface{}{"success": true, "event_id": req.EventID}
	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedSetPriority(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		EventID  string `json:"event_id"`
		Priority int    `json:"priority"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "handleFeedSetPriority"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.EventID == "" {
		return mh.errorResponse(msg.GetID(), "event_id is required")
	}

	// Clamp priority to valid range: -1 (LOW) to 2 (URGENT)
	if req.Priority < -1 || req.Priority > 2 {
		return mh.errorResponse(msg.GetID(), "priority must be between -1 and 2")
	}

	if err := mh.eventHandler.SetEventPriority(ctx, req.EventID, Priority(req.Priority)); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	resp := map[string]interface{}{"success": true, "event_id": req.EventID, "priority": req.Priority}
	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedAction(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req FeedActionRequest
	if err := unmarshalRequest(msg.Payload, &req, "handleFeedAction"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.EventID == "" {
		return mh.errorResponse(msg.GetID(), "event_id is required")
	}

	// Look up the event to determine if action needs special routing
	event, err := mh.eventHandler.storage.SQLite().GetEvent(req.EventID)
	if err == nil && event != nil {
		// Route connection acceptance actions to the connection respond handler
		if event.EventType == string(EventTypeConnectionAccepted) && (req.Action == "accept" || req.Action == "decline") {
			connectionID := event.SourceID
			if connectionID != "" {
				response := req.Action
				if response == "decline" {
					response = "reject"
				}
				reviewPayload, _ := json.Marshal(map[string]string{
					"connection_id": connectionID,
					"response":      response,
				})
				reviewMsg := &IncomingMessage{
					ID:      msg.GetID(),
					Type:    msg.Type,
					Payload: reviewPayload,
				}
				return mh.connectionsHandler.HandleRespond(reviewMsg)
			}
		}
	}

	if err := mh.eventHandler.ExecuteAction(ctx, req.EventID, req.Action); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	resp := map[string]interface{}{"success": true, "event_id": req.EventID, "action": req.Action}
	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedSync(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req FeedSyncRequest
	if err := unmarshalRequest(msg.Payload, &req, "handleFeedSync"); err != nil {
		req = FeedSyncRequest{} // Use defaults
	}

	resp, err := mh.eventHandler.Sync(ctx, &req)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedSettingsGet(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	settings := mh.eventHandler.GetSettings()
	respBytes, _ := json.Marshal(settings)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedSettingsUpdate(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var settings FeedSettings
	if err := unmarshalRequest(msg.Payload, &settings, "handleFeedSettingsUpdate"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid settings format")
	}

	if err := mh.eventHandler.UpdateSettings(&settings); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	resp := map[string]interface{}{"success": true}
	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

// --- Audit Operation Handlers ---

func (mh *MessageHandler) handleAuditQuery(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AuditQueryRequest
	if err := unmarshalRequest(msg.Payload, &req, "handleAuditQuery"); err != nil {
		req = AuditQueryRequest{} // Use defaults
	}

	resp, err := mh.eventHandler.QueryAudit(ctx, &req)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleAuditExport(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AuditExportRequest
	if err := unmarshalRequest(msg.Payload, &req, "handleAuditExport"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.Format == "" {
		req.Format = "json"
	}

	resp, err := mh.eventHandler.ExportAudit(ctx, &req)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

// GetEventHandler returns the event handler for external access (e.g., cleanup)
func (mh *MessageHandler) GetEventHandler() *EventHandler {
	return mh.eventHandler
}

// Incoming peer message handlers

// handleIncomingProfileUpdate handles profile update notifications from peer vaults
func (mh *MessageHandler) handleIncomingProfileUpdate(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if err := mh.notificationsHandler.HandleIncomingProfileUpdate(ctx, msg.Payload); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("failed to handle profile update: %v", err))
	}
	return mh.successResponse(msg.GetID(), nil)
}

// handleIncomingRevocation handles revocation notices from peer vaults
func (mh *MessageHandler) handleIncomingRevocation(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if err := mh.notificationsHandler.HandleIncomingRevocation(ctx, msg.Payload); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("failed to handle revocation: %v", err))
	}
	return mh.successResponse(msg.GetID(), nil)
}

// handleIncomingPeerMessage handles messages from peer vaults
func (mh *MessageHandler) handleIncomingPeerMessage(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if err := mh.messagingHandler.HandleIncomingMessage(ctx, msg.Payload); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("failed to handle peer message: %v", err))
	}
	return mh.successResponse(msg.GetID(), nil)
}

// handleIncomingReadReceipt handles read receipts from peer vaults
func (mh *MessageHandler) handleIncomingReadReceipt(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if err := mh.messagingHandler.HandleIncomingReadReceipt(ctx, msg.Payload); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("failed to handle read receipt: %v", err))
	}
	return mh.successResponse(msg.GetID(), nil)
}

// handleIncomingLocationUpdate handles location updates from peer vaults
func (mh *MessageHandler) handleIncomingLocationUpdate(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if err := mh.locationHandler.HandleIncomingLocationUpdate(ctx, msg.Payload); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("failed to handle location update: %v", err))
	}
	return mh.successResponse(msg.GetID(), nil)
}

// handleIncomingLocationStop handles stop-sharing notices from peer vaults (V5).
func (mh *MessageHandler) handleIncomingLocationStop(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if err := mh.locationHandler.HandleIncomingLocationStop(ctx, msg.Payload); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("failed to handle location-stop: %v", err))
	}
	return mh.successResponse(msg.GetID(), nil)
}

// handleIncomingLocationRequest handles one-shot location-request pings (V6).
func (mh *MessageHandler) handleIncomingLocationRequest(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if err := mh.locationHandler.HandleIncomingLocationRequest(ctx, msg.Payload); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("failed to handle location-request-ping: %v", err))
	}
	return mh.successResponse(msg.GetID(), nil)
}

// --- Usability Feature Operation Handlers ---

// handleInvitationOperation routes invitation-related operations
func (mh *MessageHandler) handleInvitationOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing invitation operation type")
	}

	opType := opParts[1]

	switch opType {
	case "list":
		return mh.invitationsHandler.HandleList(msg)
	case "cancel":
		return mh.invitationsHandler.HandleCancel(msg)
	case "resend":
		return mh.invitationsHandler.HandleResend(msg)
	case "viewed":
		return mh.invitationsHandler.HandleViewed(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown invitation operation: %s", opType))
	}
}

// handleCapabilityOperation routes capability-related operations
func (mh *MessageHandler) handleCapabilityOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing capability operation type")
	}

	opType := opParts[1]

	switch opType {
	case "request":
		// Check for sub-operations
		if len(opParts) >= 3 && opParts[2] == "list" {
			return mh.capabilityHandler.HandleRequestList(msg)
		}
		return mh.capabilityHandler.HandleRequest(msg)
	case "respond":
		return mh.capabilityHandler.HandleRespond(msg)
	case "get":
		return mh.capabilityHandler.HandleGet(msg)
	case "list":
		return mh.capabilityHandler.HandleRequestList(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown capability operation: %s", opType))
	}
}

// handleSettingsOperation routes settings-related operations
func (mh *MessageHandler) handleSettingsOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing settings operation type")
	}

	opType := opParts[1]

	switch opType {
	case "notifications":
		// Handle sub-operations for notifications settings
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing notifications operation")
		}
		switch opParts[2] {
		case "get":
			return mh.settingsHandler.HandleNotificationsGet(msg)
		case "update":
			return mh.settingsHandler.HandleNotificationsUpdate(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown notifications operation: %s", opParts[2]))
		}
	case "credential":
		// Handle credential settings (session TTL, etc.)
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing credential settings operation")
		}
		switch opParts[2] {
		case "get":
			return mh.settingsHandler.HandleCredentialSettingsGet(msg)
		case "update":
			// Phase E: gate security-sensitive setting changes on
			// fresh password verification. We unmarshal once, verify
			// the password by decrypting the request-supplied
			// credential blob, then delegate to the settings handler
			// for the actual write.
			var verifyReq CredentialSettingsUpdateRequest
			if err := unmarshalRequest(msg.Payload, &verifyReq, "settings.credential.update"); err != nil {
				return mh.errorResponse(msg.GetID(), "invalid request format")
			}
			if verifyReq.EncryptedCredential == "" || verifyReq.EncryptedPasswordHash == "" ||
				verifyReq.EphemeralPublicKey == "" || verifyReq.Nonce == "" || verifyReq.KeyID == "" {
				return mh.errorResponse(msg.GetID(), "password authorization required")
			}
			idKey, err := mh.credentialSecretHandler.RevealIdentityPrivateKey(
				verifyReq.EncryptedCredential,
				verifyReq.EncryptedPasswordHash,
				verifyReq.EphemeralPublicKey,
				verifyReq.Nonce,
				verifyReq.KeyID,
			)
			if err != nil {
				log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("settings.credential.update password verification failed")
				return mh.errorResponse(msg.GetID(), err.Error())
			}
			zeroBytes(idKey)
			return mh.settingsHandler.HandleCredentialSettingsUpdate(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown credential settings operation: %s", opParts[2]))
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown settings operation: %s", opType))
	}
}

// handleNotificationsDigestOperation routes notifications digest operations
func (mh *MessageHandler) handleNotificationsDigestOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing notifications operation type")
	}

	opType := opParts[1]

	switch opType {
	case "digest":
		return mh.settingsHandler.HandleNotificationsDigest(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown notifications operation: %s", opType))
	}
}

// handleEnrollmentOperation routes enrollment-related operations
func (mh *MessageHandler) handleEnrollmentOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing enrollment operation type")
	}

	opType := opParts[1]

	switch opType {
	case "identity-mismatch":
		return mh.handleIdentityMismatch(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown enrollment operation: %s", opType))
	}
}

// handleIdentityMismatch processes identity mismatch reports from the app.
// When a user reports "This is not my account" during enrollment, this logs
// the event and publishes an admin alert.
func (mh *MessageHandler) handleIdentityMismatch(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		UserGUID   string `json:"user_guid"`
		ReportedAt string `json:"reported_at"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "handleIdentityMismatch"); err != nil {
		req.UserGUID = "unknown"
		req.ReportedAt = time.Now().UTC().Format(time.RFC3339)
	}

	// SECURITY: Log the identity mismatch for audit
	log.Warn().
		Str("owner_space", mh.ownerSpace).
		Str("user_guid", req.UserGUID).
		Str("reported_at", req.ReportedAt).
		Msg("SECURITY: Identity mismatch reported during enrollment")

	// Publish admin alert via NATS
	alertPayload, _ := json.Marshal(map[string]string{
		"event":       "identity_mismatch",
		"owner_space": mh.ownerSpace,
		"user_guid":   req.UserGUID,
		"reported_at": req.ReportedAt,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	})

	if err := mh.publisher.PublishRaw("Control.enclave.alerts.identity-mismatch", alertPayload); err != nil {
		log.Error().Err(err).Msg("Failed to publish identity mismatch alert")
		// Don't fail the response - the log entry is the primary record
	}

	// Return success to the app
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success": true,
		"message": "Identity mismatch reported",
	})
	return mh.successResponse(msg.GetID(), respBytes)
}

// handleHandlersOperation routes forVault.handlers.* operations. The
// handler list is now state-aware: each entry in the response includes
// the user's enabled / share_globally toggles alongside the immutable
// classification metadata from the catalog.
func (mh *MessageHandler) handleHandlersOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing handlers operation type")
	}
	switch opParts[1] {
	case "list", "get-state":
		respBytes, err := json.Marshal(map[string]interface{}{
			"handlers": mh.buildHandlersStateResponse(),
		})
		if err != nil {
			return mh.errorResponse(msg.GetID(), "failed to marshal handlers list")
		}
		return mh.successResponse(msg.GetID(), respBytes)
	case "set-enabled":
		id, val, key, err := parseHandlerToggleRequest(msg.Payload)
		if err != nil || key != "enabled" {
			return mh.errorResponse(msg.GetID(), "set-enabled requires {handler_id, enabled}")
		}
		if err := mh.setHandlerEnabled(id, val); err != nil {
			return mh.errorResponse(msg.GetID(), err.Error())
		}
		mh.persistVaultStateToS3()
		respBytes, _ := json.Marshal(map[string]interface{}{"success": true, "handler_id": id, "enabled": val})
		return mh.successResponse(msg.GetID(), respBytes)
	case "set-share-global":
		id, val, key, err := parseHandlerToggleRequest(msg.Payload)
		if err != nil || key != "share_globally" {
			return mh.errorResponse(msg.GetID(), "set-share-global requires {handler_id, share_globally}")
		}
		if err := mh.setHandlerShareGlobal(id, val); err != nil {
			return mh.errorResponse(msg.GetID(), err.Error())
		}
		mh.persistVaultStateToS3()
		respBytes, _ := json.Marshal(map[string]interface{}{"success": true, "handler_id": id, "share_globally": val})
		return mh.successResponse(msg.GetID(), respBytes)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown handlers operation: %s", opParts[1]))
	}
}

// Response helpers

func (mh *MessageHandler) successResponse(id string, payload []byte) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeResponse,
		Payload:   payload,
	}, nil
}

func (mh *MessageHandler) errorResponse(id string, errMsg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeError,
		Error:     sanitizeErrorForClient(errMsg),
	}, nil
}

// sanitizeErrorForClient removes potentially sensitive information from error messages
// before returning them to clients. Internal errors are logged but replaced with generic messages.
func sanitizeErrorForClient(errMsg string) string {
	// List of patterns that might expose internal details
	sensitivePatterns := []string{
		"file", "path", "/", "\\",
		"connection", "socket", "vsock",
		"internal", "memory", "malloc",
		"json", "unmarshal", "marshal",
		"EOF", "broken pipe",
		"timeout", "context",
		"storage", "database", "db",
		"key", "secret", "credential",
		"crypto", "cipher", "decrypt", "encrypt",
		"stack", "panic", "runtime",
	}

	lowerErr := strings.ToLower(errMsg)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerErr, pattern) {
			// Log the full error internally
			log.Error().Str("internal_error", errMsg).Msg("Sanitized error returned to client")
			return "operation failed"
		}
	}

	// For known safe error types, return as-is (truncated)
	if len(errMsg) > 100 {
		return errMsg[:100]
	}
	return errMsg
}

func generateMessageID() string {
	return fmt.Sprintf("msg-%d", currentTimestamp())
}

// createEncryptedVaultState creates DEK-encrypted vault state for S3 storage.
// Returns the encrypted bytes ready for S3 storage AND a deterministic
// content hash of the (plaintext) state — flushVaultStateToS3 uses the
// hash to skip an S3 PUT when nothing actually changed.
// Includes both cryptographic state AND the SQLite database backup so that
// all vault data (profile, secrets, personal data, etc.) survives cold restarts.
func (mh *MessageHandler) createEncryptedVaultState(dek []byte) ([]byte, [32]byte, error) {
	// Create DEK-encrypted vault state
	mh.vaultState.mu.RLock()
	persistedState := struct {
		CEKPrivateKey  []byte `json:"cek_private_key"`
		CEKPublicKey   []byte `json:"cek_public_key"`
		UTKPairs       []struct {
			ID        string `json:"id"`
			UTK       []byte `json:"utk"`
			LTK       []byte `json:"ltk"`
			UsedAt    int64  `json:"used_at"`
			CreatedAt int64  `json:"created_at"`
		} `json:"utk_pairs"`
		Credential     *ProteanCredentialV2 `json:"credential,omitempty"`
		SealedMaterial []byte               `json:"sealed_material"`
		DatabaseBackup json.RawMessage      `json:"database_backup,omitempty"`
	}{
		SealedMaterial: mh.vaultState.sealedMaterial,
	}

	if mh.vaultState.cekPair != nil {
		persistedState.CEKPrivateKey = mh.vaultState.cekPair.PrivateKey
		persistedState.CEKPublicKey = mh.vaultState.cekPair.PublicKey
	}

	// Only persist unused UTK pairs. MarkUTKUsed already removes consumed
	// pairs from the in-memory slice, but skip defensively in case legacy
	// tombstones linger after a cold restore from older state.
	for _, utk := range mh.vaultState.utkPairs {
		if utk.UsedAt != 0 {
			continue
		}
		persistedState.UTKPairs = append(persistedState.UTKPairs, struct {
			ID        string `json:"id"`
			UTK       []byte `json:"utk"`
			LTK       []byte `json:"ltk"`
			UsedAt    int64  `json:"used_at"`
			CreatedAt int64  `json:"created_at"`
		}{
			ID:        utk.ID,
			UTK:       utk.UTK,
			LTK:       utk.LTK,
			UsedAt:    utk.UsedAt,
			CreatedAt: utk.CreatedAt,
		})
	}

	// Phase D: vault state no longer caches the full credential
	// plaintext. The CEK-sealed credential blob is persisted under
	// `credential/sealed_blob` in storage instead, and PIN unlock
	// reads it back from there to repopulate the carve-outs.
	mh.vaultState.mu.RUnlock()

	// Include SQLite database backup if storage is initialized.
	// dbContentHash is the SQLite layer's hash of the PLAINTEXT export —
	// CreateBackup's encrypted Data field carries a random nonce, so the
	// encrypted blob itself can't be used to detect "did the DB change".
	var dbContentHash []byte
	if mh.storage != nil {
		backup, err := mh.storage.CreateBackup()
		if err != nil {
			log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to create database backup for vault state persistence")
		} else {
			dbContentHash = backup.PlaintextHash
			backupBytes, err := json.Marshal(backup)
			if err != nil {
				log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to marshal database backup")
			} else {
				persistedState.DatabaseBackup = backupBytes
				log.Debug().Str("owner_space", mh.ownerSpace).Int("backup_size", len(backupBytes)).Msg("Database backup included in vault state")
			}
		}
	}

	// WS3 content hash — a deterministic digest of the vault state used
	// by flushVaultStateToS3 to skip an S3 PUT when nothing changed. The
	// encrypted DatabaseBackup blob has a random nonce and can't be
	// hashed directly, so substitute the plaintext-export hash; every
	// other field of persistedState (CEK keys, UTK pairs, sealed
	// material) marshals deterministically.
	var contentHash [32]byte
	{
		dbBlob := persistedState.DatabaseBackup
		persistedState.DatabaseBackup = nil
		metaBytes, _ := json.Marshal(persistedState)
		persistedState.DatabaseBackup = dbBlob
		h := sha256.New()
		h.Write(metaBytes)
		h.Write(dbContentHash)
		copy(contentHash[:], h.Sum(nil))
	}

	// Marshal and encrypt with DEK
	stateData, err := json.Marshal(persistedState)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to marshal vault state: %w", err)
	}
	defer zeroBytes(stateData)

	encryptedState, err := encryptWithDEK(dek, stateData)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to encrypt vault state: %w", err)
	}

	return encryptedState, contentHash, nil
}

// SecureErase zeros all sensitive data in the message handler and its components
// SECURITY: This must be called before process exit to prevent credential leakage
func (mh *MessageHandler) SecureErase() {
	// Zero vault state (holds all cryptographic material)
	if mh.vaultState != nil {
		mh.vaultState.SecureErase()
		mh.vaultState = nil
	}

	// Clear handler references (they don't hold sensitive data directly)
	mh.bootstrapHandler = nil
	mh.pinHandler = nil
	mh.proteanCredentialHandler = nil
	mh.sealerProxy = nil
	mh.callHandler = nil
	mh.secretsHandler = nil
	mh.profileHandler = nil
	mh.personalDataHandler = nil
	mh.credentialHandler = nil
	mh.messagingHandler = nil
	mh.connectionsHandler = nil
	mh.notificationsHandler = nil
	mh.credentialSecretHandler = nil
	mh.migrationHandler = nil
	mh.invitationsHandler = nil
	mh.capabilityHandler = nil
	mh.settingsHandler = nil
	mh.serviceConnectionHandler = nil
	mh.serviceContractsHandler = nil
	mh.serviceDataHandler = nil
	mh.serviceRequestsHandler = nil
	mh.serviceResourcesHandler = nil
}

// handleServiceOperation routes service-related operations
// Handles B2C service connections including connection management,
// contract handling, and data access
func (mh *MessageHandler) handleServiceOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing service operation type")
	}

	subOp := opParts[1] // e.g., "connection", "contract", "data"

	switch subOp {
	case "connection":
		return mh.handleServiceConnectionOperation(ctx, msg, opParts[1:])
	case "contract":
		return mh.handleServiceContractOperation(ctx, msg, opParts[1:])
	case "data":
		return mh.handleServiceDataOperation(ctx, msg, opParts[1:])
	case "request":
		return mh.handleServiceRequestOperation(ctx, msg, opParts[1:])
	case "profile":
		return mh.handleServiceProfileOperation(ctx, msg, opParts[1:])
	case "activity":
		return mh.handleServiceActivityOperation(ctx, msg, opParts[1:])
	case "notifications":
		return mh.handleServiceNotificationsOperation(ctx, msg, opParts[1:])
	case "trust":
		return mh.handleServiceTrustOperation(ctx, msg, opParts[1:])
	case "violations":
		return mh.handleServiceViolationsOperation(ctx, msg, opParts[1:])
	case "offline":
		return mh.handleServiceOfflineOperation(ctx, msg, opParts[1:])
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown service operation: %s", subOp))
	}
}

// handleServiceConnectionOperation routes service.connection.* operations
func (mh *MessageHandler) handleServiceConnectionOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing connection operation type")
	}

	opType := opParts[1] // e.g., "discover", "initiate", "list"

	switch opType {
	case "discover":
		return mh.serviceConnectionHandler.HandleDiscover(msg)
	case "initiate":
		return mh.serviceConnectionHandler.HandleInitiate(msg)
	case "list":
		return mh.serviceConnectionHandler.HandleList(msg)
	case "get":
		return mh.serviceConnectionHandler.HandleGet(msg)
	case "update":
		return mh.serviceConnectionHandler.HandleUpdate(msg)
	case "revoke":
		return mh.serviceConnectionHandler.HandleRevoke(msg)
	case "health":
		return mh.serviceConnectionHandler.HandleHealth(msg)
	// Tag operations (Phase 6)
	case "tags":
		if len(opParts) < 3 {
			return mh.serviceConnectionHandler.HandleListTags(msg) // Default to list
		}
		tagOp := opParts[2]
		switch tagOp {
		case "list":
			return mh.serviceConnectionHandler.HandleListTags(msg)
		case "add":
			return mh.serviceConnectionHandler.HandleAddTag(msg)
		case "remove":
			return mh.serviceConnectionHandler.HandleRemoveTag(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown tag operation: %s", tagOp))
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown connection operation: %s", opType))
	}
}

// handleServiceContractOperation routes service.contract.* operations
func (mh *MessageHandler) handleServiceContractOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing contract operation type")
	}

	opType := opParts[1] // e.g., "get", "accept", "reject", "history"

	switch opType {
	case "get":
		return mh.serviceContractsHandler.HandleGetContract(msg)
	case "accept":
		return mh.serviceContractsHandler.HandleAcceptUpdate(msg)
	case "reject":
		return mh.serviceContractsHandler.HandleRejectUpdate(msg)
	case "history":
		return mh.serviceContractsHandler.HandleContractHistory(msg)
	case "update-notification":
		// Incoming notification from service about contract update
		return mh.serviceContractsHandler.HandleContractUpdateNotification(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown contract operation: %s", opType))
	}
}

// handleServiceDataOperation routes service.data.* operations
func (mh *MessageHandler) handleServiceDataOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing data operation type")
	}

	opType := opParts[1] // e.g., "get", "store", "list", "delete", "summary", "export"

	switch opType {
	case "get":
		// Incoming request from service for profile data
		return mh.serviceDataHandler.HandleGet(msg)
	case "store":
		// Incoming request from service to store data
		return mh.serviceDataHandler.HandleStore(msg)
	case "list":
		// User listing service-stored data
		return mh.serviceDataHandler.HandleList(msg)
	case "delete":
		// User deleting service data
		return mh.serviceDataHandler.HandleDelete(msg)
	case "summary":
		// User getting storage summary
		return mh.serviceDataHandler.HandleSummary(msg)
	case "export":
		// User exporting service data
		return mh.serviceDataHandler.HandleExport(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown data operation: %s", opType))
	}
}

// handleServiceRequestOperation routes service.request.* operations
func (mh *MessageHandler) handleServiceRequestOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing request operation type")
	}

	opType := opParts[1] // e.g., "auth", "consent", "payment", "respond", "list"

	switch opType {
	case "auth":
		// Incoming auth request from service
		return mh.serviceRequestsHandler.HandleAuthRequest(msg)
	case "consent":
		// Incoming consent request from service
		return mh.serviceRequestsHandler.HandleConsentRequest(msg)
	case "payment":
		// Incoming payment request from service
		return mh.serviceRequestsHandler.HandlePaymentRequest(msg)
	case "respond":
		// User responding to a request
		return mh.serviceRequestsHandler.HandleRespond(msg)
	case "list":
		// User listing requests
		return mh.serviceRequestsHandler.HandleList(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown request operation: %s", opType))
	}
}

// handleServiceProfileOperation routes service.profile.* operations
func (mh *MessageHandler) handleServiceProfileOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing profile operation type")
	}

	opType := opParts[1] // e.g., "get", "resources", "verify-download"

	switch opType {
	case "get":
		// Get cached service profile
		return mh.serviceResourcesHandler.HandleGetProfile(msg)
	case "resources":
		// Get trusted resources
		return mh.serviceResourcesHandler.HandleGetResources(msg)
	case "verify-download":
		// Verify a download
		return mh.serviceResourcesHandler.HandleVerifyDownload(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown profile operation: %s", opType))
	}
}

// handleServiceActivityOperation routes service.activity.* operations (Phase 7)
func (mh *MessageHandler) handleServiceActivityOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing activity operation type")
	}

	opType := opParts[1] // e.g., "list", "summary"

	switch opType {
	case "list":
		return mh.serviceActivityHandler.HandleActivityList(msg)
	case "summary":
		return mh.serviceActivityHandler.HandleActivitySummary(msg)
	case "data-summary":
		return mh.serviceActivityHandler.HandleDataSummary(msg)
	case "data-export":
		return mh.serviceActivityHandler.HandleDataExport(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown activity operation: %s", opType))
	}
}

// handleServiceNotificationsOperation routes service.notifications.* operations (Phase 8)
func (mh *MessageHandler) handleServiceNotificationsOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing notifications operation type")
	}

	opType := opParts[1] // e.g., "get", "update"

	switch opType {
	case "get":
		return mh.serviceNotificationsHandler.HandleGetNotificationSettings(msg)
	case "update":
		return mh.serviceNotificationsHandler.HandleUpdateNotificationSettings(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown notifications operation: %s", opType))
	}
}

// handleServiceTrustOperation routes service.trust.* operations (Phase 8)
func (mh *MessageHandler) handleServiceTrustOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing trust operation type")
	}

	opType := opParts[1] // e.g., "get"

	switch opType {
	case "get":
		return mh.serviceNotificationsHandler.HandleGetTrustIndicators(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown trust operation: %s", opType))
	}
}

// handleServiceViolationsOperation routes service.violations.* operations (Phase 8)
func (mh *MessageHandler) handleServiceViolationsOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing violations operation type")
	}

	opType := opParts[1] // e.g., "list", "acknowledge"

	switch opType {
	case "list":
		return mh.serviceNotificationsHandler.HandleListViolations(msg)
	case "acknowledge":
		return mh.serviceNotificationsHandler.HandleAcknowledgeViolation(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown violations operation: %s", opType))
	}
}

// handleServiceOfflineOperation routes service.offline.* operations (Phase 9)
func (mh *MessageHandler) handleServiceOfflineOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing offline operation type")
	}

	opType := opParts[1] // e.g., "list", "sync", "clear", "retry", "cancel", "status"

	switch opType {
	case "list":
		return mh.serviceOfflineHandler.HandleListOfflineActions(msg)
	case "sync":
		return mh.serviceOfflineHandler.HandleTriggerSync(msg)
	case "clear":
		return mh.serviceOfflineHandler.HandleClearOfflineActions(msg)
	case "retry":
		return mh.serviceOfflineHandler.HandleRetryAction(msg)
	case "cancel":
		return mh.serviceOfflineHandler.HandleCancelAction(msg)
	case "status":
		return mh.serviceOfflineHandler.HandleGetSyncStatus(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown offline operation: %s", opType))
	}
}

// handleDatastoreOperation routes datastore.* operations (Phase 4: Combined Datastore)
func (mh *MessageHandler) handleDatastoreOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 1 {
		return mh.errorResponse(msg.GetID(), "missing datastore operation type")
	}

	opType := opParts[0]

	switch opType {
	case "create":
		return mh.combinedDatastoreHandler.HandleCreate(msg)
	case "approve":
		return mh.combinedDatastoreHandler.HandleApprove(msg)
	case "reject":
		return mh.combinedDatastoreHandler.HandleReject(msg)
	case "invite":
		return mh.combinedDatastoreHandler.HandleInviteParticipant(msg)
	case "join":
		return mh.combinedDatastoreHandler.HandleAcceptInvitation(msg)
	case "approve-participant":
		return mh.combinedDatastoreHandler.HandleApproveParticipant(msg)
	case "list":
		return mh.combinedDatastoreHandler.HandleList(msg)
	case "get":
		return mh.combinedDatastoreHandler.HandleGet(msg)
	// Access control operations (DEV-051)
	case "read":
		return mh.datastoreAccessController.HandleRead(ctx, msg)
	case "write":
		return mh.datastoreAccessController.HandleWrite(ctx, msg)
	case "delete":
		return mh.datastoreAccessController.HandleDelete(ctx, msg)
	case "subscribe":
		return mh.datastoreAccessController.HandleSubscribe(ctx, msg)
	case "unsubscribe":
		return mh.datastoreAccessController.HandleUnsubscribe(ctx, msg)
	// Audit operations (DEV-052)
	case "audit":
		if len(opParts) < 2 {
			return mh.errorResponse(msg.GetID(), "missing audit operation type")
		}
		auditOp := opParts[1]
		switch auditOp {
		case "query":
			return mh.datastoreAuditHandler.HandleQuery(ctx, msg)
		case "export":
			return mh.datastoreAuditHandler.HandleExport(ctx, msg)
		case "verify":
			return mh.datastoreAuditHandler.HandleVerifyChain(ctx, msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown audit operation: %s", auditOp))
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown datastore operation: %s", opType))
	}
}

// handleFromServiceOperation handles incoming messages from services via NATS
// Subject format: MessageSpace.{ownerSpace}.fromService.{serviceId}.{operation}.*
//
// SECURITY: This is the entry point for all service-initiated communication.
// Key security principles:
// - Services can ONLY publish to vaults, never subscribe to user data
// - Connection must be active and verified before processing
// - Capabilities are enforced per-operation
// - All operations are logged for audit
func (mh *MessageHandler) handleFromServiceOperation(ctx context.Context, msg *IncomingMessage, serviceID string, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 1 {
		return mh.errorResponse(msg.GetID(), "missing service operation type")
	}

	log.Debug().
		Str("service_id", serviceID).
		Strs("operation", opParts).
		Msg("Handling incoming service message")

	// Find connection by service ID
	conn, err := mh.findConnectionByServiceID(serviceID)
	if err != nil {
		log.Warn().
			Str("service_id", serviceID).
			Err(err).
			Msg("Service connection lookup failed")
		return mh.errorResponse(msg.GetID(), "service connection not found")
	}

	// Verify connection is active
	if conn.Status != "active" {
		log.Warn().
			Str("service_id", serviceID).
			Str("status", conn.Status).
			Msg("Service connection not active")
		return mh.errorResponse(msg.GetID(), "service connection not active")
	}

	// Update last active timestamp
	go mh.serviceConnectionHandler.UpdateLastActive(conn.ConnectionID)

	operation := opParts[0]

	// Route based on operation type
	switch operation {
	case "auth":
		// Service requesting user authentication
		return mh.serviceRequestsHandler.HandleAuthRequest(msg)

	case "consent":
		// Service requesting data consent
		return mh.serviceRequestsHandler.HandleConsentRequest(msg)

	case "payment":
		// Service requesting payment
		if !conn.ServiceProfile.CurrentContract.CanRequestPayment {
			return mh.errorResponse(msg.GetID(), "service does not have payment capability")
		}
		return mh.serviceRequestsHandler.HandlePaymentRequest(msg)

	case "data":
		// Service requesting or sending data
		if len(opParts) < 2 {
			return mh.errorResponse(msg.GetID(), "missing data operation type")
		}
		return mh.handleFromServiceDataOperation(ctx, msg, conn, opParts[1:])

	case "contract-update":
		// Service publishing contract update
		return mh.serviceContractsHandler.HandleContractUpdateNotification(msg)

	case "notify":
		// Service sending notification
		if !conn.ServiceProfile.CurrentContract.CanSendMessages {
			return mh.errorResponse(msg.GetID(), "service does not have messaging capability")
		}
		return mh.handleFromServiceNotification(ctx, msg, conn)

	case "call":
		// Service initiating a call (DEV-034)
		// Check if service has voice or video call capability
		if !conn.ServiceProfile.CurrentContract.CanRequestVoiceCall && !conn.ServiceProfile.CurrentContract.CanRequestVideoCall {
			return mh.errorResponse(msg.GetID(), "service does not have call capability")
		}
		return mh.handleFromServiceCall(ctx, msg, conn, opParts[1:])

	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown service operation: %s", operation))
	}
}

// handleFromServiceDataOperation handles data requests from services
// Enforces contract capabilities before allowing access
func (mh *MessageHandler) handleFromServiceDataOperation(ctx context.Context, msg *IncomingMessage, conn *ServiceConnectionRecord, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 1 {
		return mh.errorResponse(msg.GetID(), "missing data operation type")
	}

	opType := opParts[0]

	switch opType {
	case "get":
		// Service requesting profile data
		// Parse requested fields from payload
		var req struct {
			Fields []string `json:"fields"`
		}
		if err := unmarshalRequest(msg.Payload, &req, "handleFromServiceDataOperation"); err != nil {
			return mh.errorResponse(msg.GetID(), "invalid request format")
		}

		// Enforce contract - check which fields are allowed
		allowed, denied, err := mh.serviceContractsHandler.EnforceContract(conn.ConnectionID, req.Fields, "read")
		if err != nil {
			return mh.errorResponse(msg.GetID(), "contract enforcement failed")
		}
		if !allowed {
			// Return partial error - some fields denied
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("access denied for fields: %v", denied))
		}

		return mh.serviceDataHandler.HandleGet(msg)

	case "store":
		// Service storing data in user's vault
		if !conn.ServiceProfile.CurrentContract.CanStoreData {
			return mh.errorResponse(msg.GetID(), "service does not have storage capability")
		}
		return mh.serviceDataHandler.HandleStore(msg)

	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown data operation: %s", opType))
	}
}

// ServiceNotification represents a notification from a service (DEV-033)
type ServiceNotification struct {
	Title    string                 `json:"title"`
	Body     string                 `json:"body"`
	Priority string                 `json:"priority,omitempty"` // "low", "normal", "high", "urgent"
	ImageURL string                 `json:"image_url,omitempty"`
	ActionURL string                `json:"action_url,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

// handleFromServiceNotification handles notification messages from services (DEV-033)
// Supports priority levels, rate limiting, and forwarding to the app
func (mh *MessageHandler) handleFromServiceNotification(ctx context.Context, msg *IncomingMessage, conn *ServiceConnectionRecord) (*OutgoingMessage, error) {
	var notification ServiceNotification
	if err := unmarshalRequest(msg.Payload, &notification, "handleFromServiceNotification"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid notification format")
	}

	// Validate required fields
	if notification.Title == "" && notification.Body == "" {
		return mh.errorResponse(msg.GetID(), "title or body is required")
	}

	// Default priority
	if notification.Priority == "" {
		notification.Priority = "normal"
	}

	// Validate priority
	var priority Priority
	switch notification.Priority {
	case "low":
		priority = PriorityLow
	case "normal":
		priority = PriorityNormal
	case "high":
		priority = PriorityHigh
	case "urgent":
		priority = PriorityUrgent
	default:
		priority = PriorityNormal
	}

	// Check rate limit for notifications (max 10 per hour per service by default)
	maxNotificationsPerHour := conn.ServiceProfile.CurrentContract.MaxNotificationsPerHour
	if maxNotificationsPerHour == 0 {
		maxNotificationsPerHour = 10 // Default limit
	}
	if err := mh.checkServiceNotificationRateLimit(conn.ConnectionID, maxNotificationsPerHour); err != nil {
		log.Warn().
			Str("connection_id", conn.ConnectionID).
			Str("service_id", conn.ServiceGUID).
			Msg("Service notification rate limit exceeded")
		return mh.errorResponse(msg.GetID(), "notification rate limit exceeded")
	}

	// Create feed event for the notification
	if mh.eventHandler != nil {
		event := &Event{
			EventType:  EventTypeServiceNotification,
			SourceType: "service",
			SourceID:   conn.ConnectionID,
			Title:      notification.Title,
			Message:    notification.Body,
			Priority:   priority,
			FeedStatus: FeedStatusActive,
			ActionType: ActionTypeView,
			Metadata: map[string]string{
				"service_id":   conn.ServiceGUID,
				"service_name": conn.ServiceProfile.ServiceName,
				"action_url":   notification.ActionURL,
				"image_url":    notification.ImageURL,
			},
		}
		if err := mh.eventHandler.LogEvent(ctx, event); err != nil {
			log.Error().Err(err).Msg("Failed to log service notification")
		}
	}

	// Forward to app via NATS (if connected)
	if mh.publisher != nil {
		appNotification := map[string]interface{}{
			"type":         "service.notification",
			"service_id":   conn.ServiceGUID,
			"service_name": conn.ServiceProfile.ServiceName,
			"title":        notification.Title,
			"body":         notification.Body,
			"priority":     notification.Priority,
			"image_url":    notification.ImageURL,
			"action_url":   notification.ActionURL,
			"data":         notification.Data,
			"received_at":  time.Now().Unix(),
		}
		notifBytes, _ := json.Marshal(appNotification)
		if err := mh.publisher.PublishToApp(ctx, "service.notification", notifBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to forward notification to app")
			// Continue - notification is still stored in feed
		}
	}

	log.Info().
		Str("connection_id", conn.ConnectionID).
		Str("service_id", conn.ServiceGUID).
		Str("priority", notification.Priority).
		Msg("Service notification processed")

	resp := map[string]interface{}{
		"success":    true,
		"message":    "notification received",
		"event_type": "service.notification",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// checkServiceNotificationRateLimit checks rate limit for service notifications
func (mh *MessageHandler) checkServiceNotificationRateLimit(connectionID string, maxPerHour int) error {
	// Use simple in-memory tracking via storage
	key := fmt.Sprintf("rate-limit/notification/%s", connectionID)
	data, _ := mh.storage.Get(key)

	var state struct {
		Count       int   `json:"count"`
		WindowStart int64 `json:"window_start"`
	}

	now := time.Now().Unix()
	hourAgo := now - 3600

	if data != nil {
		json.Unmarshal(data, &state)
	}

	// Reset window if expired
	if state.WindowStart < hourAgo {
		state.Count = 0
		state.WindowStart = now
	}

	// Check limit
	if state.Count >= maxPerHour {
		return fmt.Errorf("rate limit exceeded: %d/%d per hour", state.Count, maxPerHour)
	}

	// Increment counter
	state.Count++
	newData, _ := json.Marshal(state)
	mh.storage.Put(key, newData)

	return nil
}

// findConnectionByServiceID finds a service connection by the service's GUID
func (mh *MessageHandler) findConnectionByServiceID(serviceID string) (*ServiceConnectionRecord, error) {
	// Load connection index and find matching service
	indexData, err := mh.storage.Get("service-connections/_index")
	if err != nil {
		return nil, fmt.Errorf("connection index not found")
	}

	var connectionIDs []string
	if err := json.Unmarshal(indexData, &connectionIDs); err != nil {
		return nil, fmt.Errorf("invalid connection index")
	}

	// Search for connection with matching service ID
	for _, connID := range connectionIDs {
		conn, err := mh.serviceConnectionHandler.GetConnection(connID)
		if err != nil {
			continue
		}
		if conn.ServiceGUID == serviceID && conn.Status == "active" {
			return conn, nil
		}
	}

	return nil, fmt.Errorf("no active connection found for service %s", serviceID)
}

// handleFromServiceCall handles call operations from services (DEV-034)
// Supports: call.initiate, call.signal (offer/answer/candidate), call.end
func (mh *MessageHandler) handleFromServiceCall(ctx context.Context, msg *IncomingMessage, conn *ServiceConnectionRecord, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 1 {
		return mh.errorResponse(msg.GetID(), "missing call operation type")
	}

	opType := opParts[0]

	// Check call type capability
	var callType string
	if len(opParts) > 1 {
		callType = opParts[1] // e.g., "video" or "voice"
	}

	// For initiate, verify the specific call type is allowed
	if opType == "initiate" {
		if callType == "video" && !conn.ServiceProfile.CurrentContract.CanRequestVideoCall {
			return mh.errorResponse(msg.GetID(), "service does not have video call capability")
		}
		if callType == "voice" && !conn.ServiceProfile.CurrentContract.CanRequestVoiceCall {
			return mh.errorResponse(msg.GetID(), "service does not have voice call capability")
		}
	}

	switch opType {
	case "initiate":
		// Service initiating a call
		return mh.callHandler.HandleServiceCallInitiate(ctx, msg, conn)
	case "signal":
		// Service sending WebRTC signaling (offer/answer/candidate)
		return mh.callHandler.HandleServiceCallSignaling(ctx, msg, conn)
	case "end":
		// Service ending the call
		return mh.callHandler.HandleServiceCallEnd(ctx, msg, conn)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown service call operation: %s", opType))
	}
}

// handleGrantOperation routes grant lifecycle ops from the app to the
// GrantHandler. Owner-side: approve / deny / revoke / list-outbound /
// list-pending. Receiver-side: request / fetch-remote / list-inbound.
// See plans/data-request-grants.md Phase 1.
func (mh *MessageHandler) handleGrantOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing grant operation")
	}
	if mh.grantHandler == nil {
		return mh.errorResponse(msg.GetID(), "grant handler not initialized")
	}
	switch opParts[1] {
	case "request":
		return mh.grantHandler.HandleRequest(msg)
	case "approve":
		return mh.grantHandler.HandleApprove(msg)
	case "deny":
		return mh.grantHandler.HandleDeny(msg)
	case "revoke":
		return mh.grantHandler.HandleRevoke(msg)
	case "fetch-remote":
		return mh.grantHandler.HandleFetchRemote(msg)
	case "renew":
		return mh.grantHandler.HandleRenew(msg)
	case "list-outbound":
		return mh.grantHandler.HandleListOutbound(msg)
	case "list-inbound":
		return mh.grantHandler.HandleListInbound(msg)
	case "list-pending":
		return mh.grantHandler.HandleListPending(msg)
	case "list-my-requests":
		return mh.grantHandler.HandleListMyRequests(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown grant operation: %s", opParts[1]))
	}
}

// handleCriticalSecretUseOperation dispatches app-side critical-secret
// use ops. Owner-side: approve / deny. Receiver-side: request-use.
// Plans/data-request-grants.md Phase 6.
func (mh *MessageHandler) handleCriticalSecretUseOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing critical-secret-use operation")
	}
	if mh.criticalSecretUseHandler == nil {
		return mh.errorResponse(msg.GetID(), "critical-secret-use handler not initialized")
	}
	switch opParts[1] {
	case "request-use":
		return mh.criticalSecretUseHandler.HandleRequestUse(msg)
	case "approve":
		return mh.criticalSecretUseHandler.HandleApproveUse(msg)
	case "deny":
		return mh.criticalSecretUseHandler.HandleDenyUse(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown critical-secret-use operation: %s", opParts[1]))
	}
}

// dispatchMultiTokenPeerSubject handles peer-direction subjects whose
// eventType contains one or more dots (so strings.Split breaks them
// into multiple tokens and the main switch on parts[opIndex+1] can't
// match them). Returns (response, true) when it handled the subject
// and (nil, false) when nothing matched so the caller falls through.
//
// Bug context: every multi-dot peer subject below was previously a
// dead `case` in handleVaultOp's switch (2026-05-12). Symptom: data
// requests showed as pending on the requester but the owner never
// received a notification because HandleIncomingRequest never ran.
// All grant flow, connection.authenticate, critical_secret.use, and
// presence.heartbeat subjects route here now.
func (mh *MessageHandler) dispatchMultiTokenPeerSubject(ctx context.Context, msg *IncomingMessage, fullOp string) (*OutgoingMessage, bool) {
	// Common ack shape — every multi-token peer subject is fire-and-
	// forget from the publisher's perspective; we only return "received".
	ack := func() *OutgoingMessage {
		body, _ := json.Marshal(map[string]string{"status": "received"})
		out, _ := mh.successResponse(msg.GetID(), body)
		return out
	}
	decryptEnvelope := func(tag string) (*decryptedPeerEnvelope, *OutgoingMessage) {
		dec, err := decryptIncomingPeerEnvelope(mh.storage, msg.Payload)
		if err != nil {
			errOut, _ := mh.errorResponse(msg.GetID(), fmt.Sprintf("decrypt %s envelope: %v", tag, err))
			return nil, errOut
		}
		return dec, nil
	}
	switch fullOp {
	case "presence.heartbeat":
		if gateResp := mh.gatePeerSubject(fullOp, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, true
		}
		if mh.presenceHandler != nil {
			if err := mh.presenceHandler.HandleIncomingPeerHeartbeat(ctx, msg.Payload); err != nil {
				log.Debug().Err(err).Msg("Failed to forward presence heartbeat to app")
			}
		}
		return ack(), true
	case "data.request":
		if gateResp := mh.gatePeerSubject(fullOp, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, true
		}
		dec, errResp := decryptEnvelope("data.request")
		if errResp != nil {
			return errResp, true
		}
		if err := mh.grantHandler.HandleIncomingRequest(ctx, dec); err != nil {
			log.Warn().Err(err).Msg("data.request handler failed")
		}
		return ack(), true
	case "data.grant.created":
		if gateResp := mh.gatePeerSubject(fullOp, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, true
		}
		dec, errResp := decryptEnvelope("data.grant.created")
		if errResp != nil {
			return errResp, true
		}
		if err := mh.grantHandler.HandleIncomingGrantCreated(ctx, dec); err != nil {
			log.Warn().Err(err).Msg("data.grant.created handler failed")
		}
		return ack(), true
	case "data.grant.denied":
		if gateResp := mh.gatePeerSubject(fullOp, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, true
		}
		dec, errResp := decryptEnvelope("data.grant.denied")
		if errResp != nil {
			return errResp, true
		}
		if err := mh.grantHandler.HandleIncomingGrantDenied(ctx, dec); err != nil {
			log.Warn().Err(err).Msg("data.grant.denied handler failed")
		}
		return ack(), true
	case "data.grant.fetch":
		if gateResp := mh.gatePeerSubject(fullOp, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, true
		}
		dec, errResp := decryptEnvelope("data.grant.fetch")
		if errResp != nil {
			return errResp, true
		}
		if err := mh.grantHandler.HandleIncomingFetch(ctx, dec); err != nil {
			log.Warn().Err(err).Msg("data.grant.fetch handler failed")
		}
		return ack(), true
	case "data.grant.fetch-response":
		if gateResp := mh.gatePeerSubject(fullOp, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, true
		}
		dec, errResp := decryptEnvelope("data.grant.fetch-response")
		if errResp != nil {
			return errResp, true
		}
		if err := mh.grantHandler.HandleIncomingFetchResponse(ctx, dec); err != nil {
			log.Warn().Err(err).Msg("data.grant.fetch-response handler failed")
		}
		return ack(), true
	case "data.grant.revoked":
		if gateResp := mh.gatePeerSubject(fullOp, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, true
		}
		dec, errResp := decryptEnvelope("data.grant.revoked")
		if errResp != nil {
			return errResp, true
		}
		if err := mh.grantHandler.HandleIncomingGrantRevoked(ctx, dec); err != nil {
			log.Warn().Err(err).Msg("data.grant.revoked handler failed")
		}
		return ack(), true
	case "connection.authenticate.challenge":
		if gateResp := mh.gatePeerSubject(fullOp, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, true
		}
		dec, errResp := decryptEnvelope("auth challenge")
		if errResp != nil {
			return errResp, true
		}
		if err := mh.HandleIncomingAuthChallenge(ctx, dec); err != nil {
			log.Warn().Err(err).Msg("auth challenge handler failed")
		}
		return ack(), true
	case "connection.authenticate.response":
		if gateResp := mh.gatePeerSubject(fullOp, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, true
		}
		dec, errResp := decryptEnvelope("auth response")
		if errResp != nil {
			return errResp, true
		}
		if err := mh.HandleIncomingAuthResponse(ctx, dec); err != nil {
			log.Warn().Err(err).Msg("auth response handler failed")
		}
		return ack(), true
	case "critical_secret.use":
		if gateResp := mh.gatePeerSubject(fullOp, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, true
		}
		dec, errResp := decryptEnvelope("critical_secret.use")
		if errResp != nil {
			return errResp, true
		}
		if err := mh.criticalSecretUseHandler.HandleIncomingUseRequest(ctx, dec); err != nil {
			log.Warn().Err(err).Msg("critical_secret.use handler failed")
		}
		return ack(), true
	case "critical_secret.use-response":
		if gateResp := mh.gatePeerSubject(fullOp, msg.Payload, msg.GetID()); gateResp != nil {
			return gateResp, true
		}
		dec, errResp := decryptEnvelope("critical_secret.use-response")
		if errResp != nil {
			return errResp, true
		}
		if err := mh.criticalSecretUseHandler.HandleIncomingUseResponse(ctx, dec); err != nil {
			log.Warn().Err(err).Msg("critical_secret.use-response handler failed")
		}
		return ack(), true
	}
	return nil, false
}
