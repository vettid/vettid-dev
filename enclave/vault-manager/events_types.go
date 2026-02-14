package main

// events_types.go defines the unified event system types and constants.
// This system serves both audit logging and user feed purposes using
// a single event table, reducing write overhead and encryption costs.

import "time"

// EventType defines all event types in the system
type EventType string

const (
	// Call events
	EventTypeCallIncoming  EventType = "call.incoming"
	EventTypeCallOutgoing  EventType = "call.outgoing"
	EventTypeCallMissed    EventType = "call.missed"
	EventTypeCallEnded     EventType = "call.ended"
	EventTypeCallBlocked   EventType = "call.blocked"
	EventTypeCallRejected  EventType = "call.rejected"
	EventTypeCallAnswered  EventType = "call.answered"

	// Connection events
	EventTypeConnectionRequest   EventType = "connection.request"
	EventTypeConnectionInitiated EventType = "connection.initiated"
	EventTypeConnectionAccepted  EventType = "connection.accepted"
	EventTypeConnectionRejected  EventType = "connection.rejected"
	EventTypeConnectionRevoked   EventType = "connection.revoked"
	EventTypeConnectionCreated   EventType = "connection.created"
	EventTypeConnectionRotated   EventType = "connection.rotated"

	// Message events
	EventTypeMessageReceived EventType = "message.received"
	EventTypeMessageSent     EventType = "message.sent"
	EventTypeMessageRead     EventType = "message.read"

	// Secret events
	EventTypeSecretAccessed EventType = "secret.accessed"
	EventTypeSecretAdded    EventType = "secret.added"
	EventTypeSecretDeleted  EventType = "secret.deleted"

	// Security events
	EventTypeSecurityAlert     EventType = "security.alert"
	EventTypeAuthAttemptFailed EventType = "auth.attempt_failed"
	EventTypeAuthSuccess       EventType = "auth.success"

	// Transfer events
	EventTypeTransferRequest EventType = "transfer.request"

	// Profile events
	EventTypeProfileUpdated EventType = "profile.updated"

	// Service connection events (B2C)
	EventTypeServiceConnectionInitiated EventType = "service.connection.initiated"
	EventTypeServiceConnectionAccepted  EventType = "service.connection.accepted"
	EventTypeServiceConnectionRejected  EventType = "service.connection.rejected"
	EventTypeServiceConnectionRevoked   EventType = "service.connection.revoked"

	// Service data events
	EventTypeServiceDataRequested EventType = "service.data.requested"
	EventTypeServiceDataProvided  EventType = "service.data.provided"
	EventTypeServiceDataDenied    EventType = "service.data.denied"
	EventTypeServiceDataStored    EventType = "service.data.stored"
	EventTypeServiceDataDeleted   EventType = "service.data.deleted"

	// Service request events
	EventTypeServiceAuthRequested    EventType = "service.auth.requested"
	EventTypeServiceConsentRequested EventType = "service.consent.requested"
	EventTypeServicePaymentRequested EventType = "service.payment.requested"
	EventTypeServiceRequestApproved  EventType = "service.request.approved"
	EventTypeServiceRequestDenied    EventType = "service.request.denied"
	EventTypeServiceRequestExpired   EventType = "service.request.expired"

	// Contract events
	EventTypeServiceContractUpdatePublished EventType = "service.contract.update_published"
	EventTypeServiceContractAccepted        EventType = "service.contract.accepted"
	EventTypeServiceContractRejected        EventType = "service.contract.rejected"
	EventTypeServiceContractViolation       EventType = "service.contract.violation"

	// Rate limit events
	EventTypeServiceRateLimitWarning  EventType = "service.rate_limit.warning"
	EventTypeServiceRateLimitExceeded EventType = "service.rate_limit.exceeded"

	// Resource events
	EventTypeServiceResourceDownloaded EventType = "service.resource.downloaded"
	EventTypeServiceResourceVerified   EventType = "service.resource.verified"

	// Service notification events
	EventTypeServiceNotification EventType = "service.notification"

	// Agent connection events
	EventTypeAgentConnectionRequest  EventType = "agent.connection.request"
	EventTypeAgentConnectionApproved EventType = "agent.connection.approved"
	EventTypeAgentConnectionDenied   EventType = "agent.connection.denied"
	EventTypeAgentConnectionRevoked  EventType = "agent.connection.revoked"

	// Agent secret request events
	EventTypeAgentSecretRequested    EventType = "agent.secret.requested"
	EventTypeAgentSecretApproved     EventType = "agent.secret.approved"
	EventTypeAgentSecretAutoApproved EventType = "agent.secret.auto_approved"
	EventTypeAgentSecretDenied       EventType = "agent.secret.denied"

	// Agent action events (use-in-enclave operations)
	EventTypeAgentActionRequested EventType = "agent.action.requested"
	EventTypeAgentActionCompleted EventType = "agent.action.completed"
	EventTypeAgentActionDenied    EventType = "agent.action.denied"

	// Device connection events
	EventTypeDeviceConnectionRequest  EventType = "device.connection.request"
	EventTypeDeviceConnectionApproved EventType = "device.connection.approved"
	EventTypeDeviceConnectionDenied   EventType = "device.connection.denied"
	EventTypeDeviceConnectionRevoked  EventType = "device.connection.revoked"

	// Device session events
	EventTypeDeviceSessionCreated  EventType = "device.session.created"
	EventTypeDeviceSessionExtended EventType = "device.session.extended"
	EventTypeDeviceSessionExpired  EventType = "device.session.expired"
	EventTypeDeviceSessionRevoked  EventType = "device.session.revoked"
	EventTypeDeviceSessionSuspended EventType = "device.session.suspended"

	// Device approval events (operations delegated to phone)
	EventTypeDeviceApprovalRequested EventType = "device.approval.requested"
	EventTypeDeviceApprovalGranted   EventType = "device.approval.granted"
	EventTypeDeviceApprovalDenied    EventType = "device.approval.denied"

	// Feed interaction events (audit-only, tracks user actions on feed items)
	EventTypeFeedItemRead     EventType = "feed.item_read"
	EventTypeFeedItemArchived EventType = "feed.item_archived"
	EventTypeFeedItemDeleted  EventType = "feed.item_deleted"
	EventTypeFeedActionTaken  EventType = "feed.action_taken"

	// Guide events (tutorial/onboarding content)
	EventTypeGuide EventType = "guide"
)

// FeedStatus controls visibility in the feed
type FeedStatus string

const (
	FeedStatusHidden   FeedStatus = "hidden"   // Audit-only, not shown in feed
	FeedStatusActive   FeedStatus = "active"   // Shown in feed, may need action
	FeedStatusRead     FeedStatus = "read"     // Viewed but not archived
	FeedStatusArchived FeedStatus = "archived" // User archived
	FeedStatusDeleted  FeedStatus = "deleted"  // Soft delete, pending cleanup
)

// ActionType defines what action the user can take
type ActionType string

const (
	ActionTypeNone          ActionType = ""               // No action needed
	ActionTypeAcceptDecline ActionType = "accept_decline" // Accept/reject buttons
	ActionTypeReply         ActionType = "reply"          // Reply to message
	ActionTypeView          ActionType = "view"           // View details
	ActionTypeAcknowledge   ActionType = "acknowledge"    // Just dismiss
)

// Priority levels for feed ordering
type Priority int

const (
	PriorityLow    Priority = -1
	PriorityNormal Priority = 0
	PriorityHigh   Priority = 1
	PriorityUrgent Priority = 2
)

// RetentionClass controls how long events are kept
type RetentionClass string

const (
	RetentionEphemeral RetentionClass = "ephemeral" // 24 hours
	RetentionStandard  RetentionClass = "standard"  // Default, follows settings
	RetentionPermanent RetentionClass = "permanent" // Never auto-deleted
)

// Event is the unified structure for all vault events.
// It serves both audit logging and user feed purposes.
type Event struct {
	EventID   string    `json:"event_id"`
	EventType EventType `json:"event_type"`

	// Source tracking
	SourceType string `json:"source_type,omitempty"` // "system", "connection", "user"
	SourceID   string `json:"source_id,omitempty"`   // connection_id, etc.

	// Content (stored in encrypted payload)
	Title    string            `json:"title"`
	Message  string            `json:"message,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`

	// Feed control
	FeedStatus FeedStatus `json:"feed_status"`
	ActionType ActionType `json:"action_type,omitempty"`
	Priority   Priority   `json:"priority"`

	// Timestamps (Unix seconds)
	CreatedAt  int64 `json:"created_at"`
	ReadAt     int64 `json:"read_at,omitempty"`
	ActionedAt int64 `json:"actioned_at,omitempty"`
	ArchivedAt int64 `json:"archived_at,omitempty"`
	ExpiresAt  int64 `json:"expires_at,omitempty"`

	// Sync support
	SyncSequence int64 `json:"sync_sequence"`

	// Retention control
	RetentionClass RetentionClass `json:"retention_class"`
}

// EventPayload is the encrypted portion of an event
type EventPayload struct {
	Title    string            `json:"title"`
	Message  string            `json:"message,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// FeedSettings configures feed behavior and retention
type FeedSettings struct {
	FeedRetentionDays  int    `json:"feed_retention_days"`  // Default: 30
	AuditRetentionDays int    `json:"audit_retention_days"` // Default: 90
	ArchiveBehavior    string `json:"archive_behavior"`     // "archive" or "delete"
	AutoArchiveEnabled bool   `json:"auto_archive_enabled"`
	UpdatedAt          int64  `json:"updated_at"`
}

// DefaultFeedSettings returns default feed settings
func DefaultFeedSettings() *FeedSettings {
	return &FeedSettings{
		FeedRetentionDays:  30,
		AuditRetentionDays: 90,
		ArchiveBehavior:    "archive",
		AutoArchiveEnabled: true,
		UpdatedAt:          time.Now().Unix(),
	}
}

// EventClassification defines how an event type maps to feed behavior
type EventClassification struct {
	FeedStatus     FeedStatus
	ActionType     ActionType
	Priority       Priority
	RetentionClass RetentionClass
}

// eventClassifications maps event types to their default feed classification
var eventClassifications = map[EventType]EventClassification{
	// Call events
	EventTypeCallIncoming: {FeedStatusActive, ActionTypeAcceptDecline, PriorityHigh, RetentionStandard},
	EventTypeCallMissed:   {FeedStatusActive, ActionTypeView, PriorityNormal, RetentionStandard},
	EventTypeCallOutgoing: {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeCallEnded:    {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeCallBlocked:  {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeCallRejected: {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeCallAnswered: {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},

	// Connection events
	EventTypeConnectionRequest:   {FeedStatusActive, ActionTypeAcceptDecline, PriorityNormal, RetentionStandard},
	EventTypeConnectionInitiated: {FeedStatusActive, ActionTypeAcceptDecline, PriorityNormal, RetentionStandard},
	EventTypeConnectionAccepted:  {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeConnectionRejected:  {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeConnectionRevoked:   {FeedStatusActive, ActionTypeAcknowledge, PriorityLow, RetentionStandard},
	EventTypeConnectionCreated:   {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeConnectionRotated:   {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},

	// Message events
	EventTypeMessageReceived: {FeedStatusActive, ActionTypeReply, PriorityLow, RetentionStandard},
	EventTypeMessageSent:     {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeMessageRead:     {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionEphemeral},

	// Secret events
	EventTypeSecretAccessed: {FeedStatusActive, ActionTypeAcknowledge, PriorityNormal, RetentionPermanent},
	EventTypeSecretAdded:    {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionPermanent},
	EventTypeSecretDeleted:  {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionPermanent},

	// Security events
	EventTypeSecurityAlert:     {FeedStatusActive, ActionTypeAcknowledge, PriorityUrgent, RetentionPermanent},
	EventTypeAuthAttemptFailed: {FeedStatusActive, ActionTypeAcknowledge, PriorityHigh, RetentionPermanent},
	EventTypeAuthSuccess:       {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},

	// Transfer events
	EventTypeTransferRequest: {FeedStatusActive, ActionTypeAcceptDecline, PriorityHigh, RetentionStandard},

	// Profile events
	EventTypeProfileUpdated: {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},

	// Feed interaction events (audit-only, ephemeral)
	EventTypeFeedItemRead:     {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionEphemeral},
	EventTypeFeedItemArchived: {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionEphemeral},
	EventTypeFeedItemDeleted:  {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionEphemeral},
	EventTypeFeedActionTaken:  {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},

	// Service connection events
	EventTypeServiceConnectionInitiated: {FeedStatusActive, ActionTypeAcceptDecline, PriorityNormal, RetentionStandard},
	EventTypeServiceConnectionAccepted:  {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeServiceConnectionRejected:  {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeServiceConnectionRevoked:   {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},

	// Service data events
	EventTypeServiceDataRequested: {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeServiceDataProvided:  {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeServiceDataDenied:    {FeedStatusActive, ActionTypeAcknowledge, PriorityLow, RetentionStandard},
	EventTypeServiceDataStored:    {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeServiceDataDeleted:   {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},

	// Service request events
	EventTypeServiceAuthRequested:    {FeedStatusActive, ActionTypeAcceptDecline, PriorityHigh, RetentionStandard},
	EventTypeServiceConsentRequested: {FeedStatusActive, ActionTypeAcceptDecline, PriorityNormal, RetentionStandard},
	EventTypeServicePaymentRequested: {FeedStatusActive, ActionTypeAcceptDecline, PriorityHigh, RetentionStandard},
	EventTypeServiceRequestApproved:  {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeServiceRequestDenied:    {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeServiceRequestExpired:   {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionEphemeral},

	// Contract events
	EventTypeServiceContractUpdatePublished: {FeedStatusActive, ActionTypeAcceptDecline, PriorityNormal, RetentionStandard},
	EventTypeServiceContractAccepted:        {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeServiceContractRejected:        {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeServiceContractViolation:       {FeedStatusActive, ActionTypeAcknowledge, PriorityHigh, RetentionPermanent},

	// Rate limit events
	EventTypeServiceRateLimitWarning:  {FeedStatusActive, ActionTypeAcknowledge, PriorityNormal, RetentionStandard},
	EventTypeServiceRateLimitExceeded: {FeedStatusActive, ActionTypeAcknowledge, PriorityHigh, RetentionStandard},

	// Resource events
	EventTypeServiceResourceDownloaded: {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeServiceResourceVerified:   {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},

	// Service notification events
	EventTypeServiceNotification: {FeedStatusActive, ActionTypeView, PriorityNormal, RetentionStandard},

	// Agent connection events
	EventTypeAgentConnectionRequest:  {FeedStatusActive, ActionTypeAcceptDecline, PriorityHigh, RetentionStandard},
	EventTypeAgentConnectionApproved: {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeAgentConnectionDenied:   {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeAgentConnectionRevoked:  {FeedStatusActive, ActionTypeAcknowledge, PriorityNormal, RetentionStandard},

	// Agent secret request events
	EventTypeAgentSecretRequested:    {FeedStatusActive, ActionTypeAcceptDecline, PriorityHigh, RetentionPermanent},
	EventTypeAgentSecretApproved:     {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionPermanent},
	EventTypeAgentSecretAutoApproved: {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionPermanent},
	EventTypeAgentSecretDenied:       {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionPermanent},

	// Agent action events (use-in-enclave)
	EventTypeAgentActionRequested: {FeedStatusActive, ActionTypeAcceptDecline, PriorityHigh, RetentionPermanent},
	EventTypeAgentActionCompleted: {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionPermanent},
	EventTypeAgentActionDenied:    {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionPermanent},

	// Device connection events
	EventTypeDeviceConnectionRequest:  {FeedStatusActive, ActionTypeAcceptDecline, PriorityHigh, RetentionStandard},
	EventTypeDeviceConnectionApproved: {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeDeviceConnectionDenied:   {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeDeviceConnectionRevoked:  {FeedStatusActive, ActionTypeAcknowledge, PriorityNormal, RetentionStandard},

	// Device session events
	EventTypeDeviceSessionCreated:   {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeDeviceSessionExtended:  {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeDeviceSessionExpired:   {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeDeviceSessionRevoked:   {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionStandard},
	EventTypeDeviceSessionSuspended: {FeedStatusActive, ActionTypeAcknowledge, PriorityNormal, RetentionStandard},

	// Device approval events
	EventTypeDeviceApprovalRequested: {FeedStatusActive, ActionTypeAcceptDecline, PriorityHigh, RetentionPermanent},
	EventTypeDeviceApprovalGranted:   {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionPermanent},
	EventTypeDeviceApprovalDenied:    {FeedStatusHidden, ActionTypeNone, PriorityNormal, RetentionPermanent},

	// Guide events
	EventTypeGuide: {FeedStatusActive, ActionTypeView, PriorityNormal, RetentionPermanent},
}

// GetEventClassification returns the default classification for an event type
func GetEventClassification(eventType EventType) EventClassification {
	if class, ok := eventClassifications[eventType]; ok {
		return class
	}
	// Default classification for unknown event types
	return EventClassification{
		FeedStatus:     FeedStatusHidden,
		ActionType:     ActionTypeNone,
		Priority:       PriorityNormal,
		RetentionClass: RetentionStandard,
	}
}

// --- Feed API Request/Response Types ---

// FeedListRequest is the payload for feed.list
type FeedListRequest struct {
	Status []FeedStatus `json:"status,omitempty"` // Filter by status (default: active, read)
	Limit  int          `json:"limit,omitempty"`  // Max results (default: 50, max: 100)
	Offset int          `json:"offset,omitempty"` // Pagination offset
}

// FeedListResponse is the response for feed.list
type FeedListResponse struct {
	Events  []Event `json:"events"`
	Total   int     `json:"total"`
	HasMore bool    `json:"has_more"`
}

// FeedSyncRequest is the payload for feed.sync
type FeedSyncRequest struct {
	LastSequence  int64 `json:"last_sequence"`            // Last known sync sequence
	Limit         int   `json:"limit"`                    // Max events to return (default: 100)
	IncludeHidden bool  `json:"include_hidden,omitempty"` // Include audit-only (hidden) events
}

// FeedSyncResponse is the response for feed.sync
type FeedSyncResponse struct {
	Events         []Event `json:"events"`
	LatestSequence int64   `json:"latest_sequence"`
	HasMore        bool    `json:"has_more"`
}

// FeedActionRequest is the payload for feed.action
type FeedActionRequest struct {
	EventID string `json:"event_id"`
	Action  string `json:"action"` // "accept", "decline", "acknowledge", etc.
}

// FeedUpdateStatusRequest is the payload for feed.read, feed.archive, feed.delete
type FeedUpdateStatusRequest struct {
	EventID string `json:"event_id"`
}

// --- Audit API Request/Response Types ---

// AuditQueryRequest is the payload for audit.query
type AuditQueryRequest struct {
	EventTypes []EventType `json:"event_types,omitempty"` // Filter by event types
	StartTime  int64       `json:"start_time,omitempty"`  // Unix timestamp
	EndTime    int64       `json:"end_time,omitempty"`    // Unix timestamp
	SourceID   string      `json:"source_id,omitempty"`   // Filter by source
	Limit      int         `json:"limit,omitempty"`       // Max results (default: 100, max: 1000)
	Offset     int         `json:"offset,omitempty"`      // Pagination offset
}

// AuditQueryResponse is the response for audit.query
type AuditQueryResponse struct {
	Events  []Event `json:"events"`
	Total   int     `json:"total"`
	HasMore bool    `json:"has_more"`
}

// AuditExportRequest is the payload for audit.export
type AuditExportRequest struct {
	EventTypes []EventType `json:"event_types,omitempty"`
	StartTime  int64       `json:"start_time,omitempty"`
	EndTime    int64       `json:"end_time,omitempty"`
	Format     string      `json:"format"` // "json" or "csv"
}

// AuditExportResponse is the response for audit.export
type AuditExportResponse struct {
	Data       []byte `json:"data"`        // Exported data
	Format     string `json:"format"`      // "json" or "csv"
	EventCount int    `json:"event_count"` // Number of events exported
}
