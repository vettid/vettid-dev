package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/curve25519"
)

// ServiceConnectionHandler handles B2C service connections.
// Services are businesses/apps that run their own VettID Service Vaults.
// Key principles:
// - Services do NOT cache user profiles (on-demand access only)
// - Clean break on cancellation (service loses all access)
// - User controls contracts (can reject updates)
type ServiceConnectionHandler struct {
	ownerSpace     string
	storage        *EncryptedStorage
	eventHandler   *EventHandler
	profileHandler *ProfileHandler // DEV-026: For auto-sharing profile on connection
}

// NewServiceConnectionHandler creates a new service connection handler
func NewServiceConnectionHandler(ownerSpace string, storage *EncryptedStorage, eventHandler *EventHandler, profileHandler *ProfileHandler) *ServiceConnectionHandler {
	return &ServiceConnectionHandler{
		ownerSpace:     ownerSpace,
		storage:        storage,
		eventHandler:   eventHandler,
		profileHandler: profileHandler,
	}
}

// --- Data Models ---

// ServiceProfile represents a service's profile with trusted resources
type ServiceProfile struct {
	ServiceGUID        string             `json:"service_guid"`
	ServiceName        string             `json:"service_name"`
	ServiceDescription string             `json:"service_description"`
	ServiceLogoURL     string             `json:"service_logo_url,omitempty"`
	ServiceCategory    string             `json:"service_category"` // "retail", "healthcare", "finance", etc.
	Organization       OrganizationInfo   `json:"organization"`
	ContactInfo        ServiceContactInfo `json:"contact_info"`
	TrustedResources   []TrustedResource  `json:"trusted_resources"`
	CurrentContract    ServiceDataContract `json:"current_contract"`
	ProfileVersion     int                `json:"profile_version"`
	UpdatedAt          time.Time          `json:"updated_at"`
}

// OrganizationInfo contains verified organization details
type OrganizationInfo struct {
	Name             string `json:"name"`
	Verified         bool   `json:"verified"`
	VerificationType string `json:"verification_type"` // "business", "nonprofit", "government"
	VerifiedAt       string `json:"verified_at,omitempty"`
	RegistrationID   string `json:"registration_id,omitempty"`
	Country          string `json:"country,omitempty"`
}

// ServiceContactInfo contains verified contact methods
type ServiceContactInfo struct {
	Emails       []VerifiedContact `json:"emails,omitempty"`
	PhoneNumbers []VerifiedContact `json:"phone_numbers,omitempty"`
	Address      *PhysicalAddress  `json:"address,omitempty"`
	SupportURL   string            `json:"support_url,omitempty"`
	SupportEmail string            `json:"support_email,omitempty"`
	SupportPhone string            `json:"support_phone,omitempty"`
}

// VerifiedContact represents a verified email or phone
type VerifiedContact struct {
	Value      string `json:"value"`
	Label      string `json:"label"`
	Verified   bool   `json:"verified"`
	VerifiedAt string `json:"verified_at,omitempty"`
	Primary    bool   `json:"primary"`
}

// PhysicalAddress represents a physical address
type PhysicalAddress struct {
	Street     string `json:"street"`
	City       string `json:"city"`
	State      string `json:"state,omitempty"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

// TrustedResource represents a trusted URL or download
type TrustedResource struct {
	ResourceID  string        `json:"resource_id"`
	Type        string        `json:"type"` // "website", "app_download", "document", "api"
	Label       string        `json:"label"`
	Description string        `json:"description,omitempty"`
	URL         string        `json:"url"`
	Download    *DownloadInfo `json:"download,omitempty"`
	AddedAt     time.Time     `json:"added_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// DownloadInfo contains information for downloadable resources
type DownloadInfo struct {
	Platform     string              `json:"platform"` // "android", "ios", "windows", "macos", "linux"
	Version      string              `json:"version"`
	VersionCode  int                 `json:"version_code,omitempty"`
	MinOSVersion string              `json:"min_os_version,omitempty"`
	FileSize     int64               `json:"file_size"`
	FileName     string              `json:"file_name"`
	Signatures   []DownloadSignature `json:"signatures"`
}

// DownloadSignature contains cryptographic verification for downloads
type DownloadSignature struct {
	Algorithm string `json:"algorithm"` // "sha256", "sha512"
	Hash      string `json:"hash"`
	SignedBy  string `json:"signed_by"`
	Signature string `json:"signature"` // Ed25519 signature
}

// ServiceDataContract defines what a service can access
type ServiceDataContract struct {
	ContractID   string      `json:"contract_id"`
	ServiceGUID  string      `json:"service_guid"`
	Version      int         `json:"version"`
	Title        string      `json:"title"`
	Description  string      `json:"description"`
	TermsURL     string      `json:"terms_url,omitempty"`
	PrivacyURL   string      `json:"privacy_url,omitempty"`
	RequiredFields []FieldSpec `json:"required_fields"`
	OptionalFields []FieldSpec `json:"optional_fields"`
	OnDemandFields []string    `json:"on_demand_fields"`
	ConsentFields  []string    `json:"consent_fields"`
	CanStoreData      bool     `json:"can_store_data"`
	StorageCategories []string `json:"storage_categories,omitempty"`
	CanSendMessages    bool     `json:"can_send_messages"`
	CanRequestAuth     bool     `json:"can_request_auth"`
	CanRequestPayment  bool     `json:"can_request_payment"`
	CanRequestVoiceCall bool    `json:"can_request_voice_call"` // DEV-034: Voice call capability
	CanRequestVideoCall bool    `json:"can_request_video_call"` // DEV-034: Video call capability
	MaxRequestsPerHour int      `json:"max_requests_per_hour,omitempty"`
	MaxNotificationsPerHour int `json:"max_notifications_per_hour,omitempty"` // DEV-033
	MaxStorageMB       int     `json:"max_storage_mb,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// FieldSpec describes a field the service wants to access
type FieldSpec struct {
	Field     string `json:"field"`
	Purpose   string `json:"purpose"`
	Retention string `json:"retention"` // "session", "until_revoked", "30_days", etc.
}

// ServiceConnectionRecord stores a service connection in user's vault
type ServiceConnectionRecord struct {
	// Base connection fields
	ConnectionID    string    `json:"connection_id"`
	Status          string    `json:"status"` // "active", "pending", "revoked", "suspended"
	CreatedAt       time.Time `json:"created_at"`
	LastActiveAt    *time.Time `json:"last_active_at,omitempty"`

	// E2E encryption
	LocalPublicKey  []byte    `json:"local_public_key,omitempty"`
	LocalPrivateKey []byte    `json:"local_private_key,omitempty"`
	PeerPublicKey   []byte    `json:"peer_public_key,omitempty"`
	SharedSecret    []byte    `json:"shared_secret,omitempty"`
	KeyExchangeAt   time.Time `json:"key_exchange_at,omitempty"`

	// Service identification
	IsServiceConnection bool   `json:"is_service_connection"`
	ServiceGUID         string `json:"service_guid"`

	// Cached service profile (user can view offline)
	ServiceProfile ServiceProfile `json:"service_profile"`

	// Contract tracking
	ContractID             string    `json:"contract_id"`
	ContractVersion        int       `json:"contract_version"`
	ContractAcceptedAt     time.Time `json:"contract_accepted_at"`
	PendingContractVersion *int      `json:"pending_contract_version,omitempty"`

	// Usability fields
	Tags       []string `json:"tags,omitempty"`
	IsFavorite bool     `json:"is_favorite"`
	IsArchived bool     `json:"is_archived"`
	IsMuted    bool     `json:"is_muted"`

	// Activity tracking
	ActivityCount int `json:"activity_count"`
}

// ContractUpdate represents a contract update notification
type ContractUpdate struct {
	PreviousVersion int             `json:"previous_version"`
	NewVersion      int             `json:"new_version"`
	Changes         ContractChanges `json:"changes"`
	Reason          string          `json:"reason"`
	PublishedAt     time.Time       `json:"published_at"`
	RequiredBy      *time.Time      `json:"required_by,omitempty"`
}

// ContractChanges describes what changed between contract versions
type ContractChanges struct {
	AddedFields       []FieldSpec `json:"added_fields,omitempty"`
	RemovedFields     []string    `json:"removed_fields,omitempty"`
	ChangedFields     []FieldSpec `json:"changed_fields,omitempty"`
	PermissionChanges []string    `json:"permission_changes,omitempty"`
	RateLimitChanges  *string     `json:"rate_limit_changes,omitempty"`
}

// --- Request/Response Types ---

// DiscoverServiceRequest is the payload for service.connection.discover
type DiscoverServiceRequest struct {
	ServiceGUID     string `json:"service_guid"`
	InvitationToken string `json:"invitation_token,omitempty"`
}

// DiscoverServiceResponse is the response for service.connection.discover
type DiscoverServiceResponse struct {
	ServiceProfile ServiceProfile      `json:"service_profile"`
	Contract       ServiceDataContract `json:"contract"`
	MissingFields  []string            `json:"missing_fields,omitempty"`
}

// InitiateServiceConnectionRequest is the payload for service.connection.initiate
type InitiateServiceConnectionRequest struct {
	ServiceGUID       string          `json:"service_guid"`
	ServiceProfile    ServiceProfile  `json:"service_profile"`
	ContractVersion   int             `json:"contract_version"`
	NATSCredentials   string          `json:"nats_credentials,omitempty"`
	ServiceE2EPublicKey string        `json:"service_e2e_public_key"`
}

// InitiateServiceConnectionResponse is the response for service.connection.initiate
type InitiateServiceConnectionResponse struct {
	ConnectionID  string                          `json:"connection_id"`
	E2EPublicKey  string                          `json:"e2e_public_key"`
	Status        string                          `json:"status"`
	SharedProfile map[string]ProfileFieldResponse `json:"shared_profile,omitempty"` // DEV-026: Auto-shared profile fields
}

// ListServiceConnectionsRequest is the payload for service.connection.list
type ListServiceConnectionsRequest struct {
	Status     string   `json:"status,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	IsFavorite *bool    `json:"is_favorite,omitempty"`
	IsArchived *bool    `json:"is_archived,omitempty"`
	Search     string   `json:"search,omitempty"`
	SortBy     string   `json:"sort_by,omitempty"`
	SortOrder  string   `json:"sort_order,omitempty"`
	Limit      int      `json:"limit,omitempty"`
	Offset     int      `json:"offset,omitempty"`
}

// ServiceConnectionInfo is a summary for list responses
type ServiceConnectionInfo struct {
	ConnectionID           string    `json:"connection_id"`
	ServiceGUID            string    `json:"service_guid"`
	ServiceName            string    `json:"service_name"`
	ServiceLogoURL         string    `json:"service_logo_url,omitempty"`
	ServiceCategory        string    `json:"service_category"`
	OrganizationVerified   bool      `json:"organization_verified"`
	Status                 string    `json:"status"`
	ContractVersion        int       `json:"contract_version"`
	PendingContractVersion *int      `json:"pending_contract_version,omitempty"`
	LastActiveAt           *time.Time `json:"last_active_at,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
	Tags                   []string  `json:"tags,omitempty"`
	IsFavorite             bool      `json:"is_favorite"`
	IsArchived             bool      `json:"is_archived"`
	IsMuted                bool      `json:"is_muted"`
}

// ListServiceConnectionsResponse is the response for service.connection.list
type ListServiceConnectionsResponse struct {
	Connections []ServiceConnectionInfo `json:"connections"`
	Total       int                     `json:"total"`
	HasMore     bool                    `json:"has_more"`
}

// GetServiceConnectionRequest is the payload for service.connection.get
type GetServiceConnectionRequest struct {
	ConnectionID string `json:"connection_id"`
}

// GetServiceConnectionResponse is the response for service.connection.get
type GetServiceConnectionResponse struct {
	Connection ServiceConnectionRecord `json:"connection"`
}

// UpdateServiceConnectionRequest is the payload for service.connection.update
type UpdateServiceConnectionRequest struct {
	ConnectionID string    `json:"connection_id"`
	Tags         *[]string `json:"tags,omitempty"`
	IsFavorite   *bool     `json:"is_favorite,omitempty"`
	IsArchived   *bool     `json:"is_archived,omitempty"`
	IsMuted      *bool     `json:"is_muted,omitempty"`
}

// UpdateServiceConnectionResponse is the response for service.connection.update
type UpdateServiceConnectionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// RevokeServiceConnectionRequest is the payload for service.connection.revoke
type RevokeServiceConnectionRequest struct {
	ConnectionID   string `json:"connection_id"`
	DeleteData     bool   `json:"delete_data"`     // Also delete service-stored data
	ExportDataFirst bool  `json:"export_data_first"` // Export before deleting
}

// RevokeServiceConnectionResponse is the response for service.connection.revoke
type RevokeServiceConnectionResponse struct {
	Success      bool   `json:"success"`
	ExportedData []byte `json:"exported_data,omitempty"`
	Message      string `json:"message,omitempty"`
}

// ServiceConnectionHealthRequest is the payload for service.connection.health
type ServiceConnectionHealthRequest struct {
	ConnectionID string `json:"connection_id"`
}

// ServiceConnectionHealth represents health status
type ServiceConnectionHealth struct {
	ConnectionID      string    `json:"connection_id"`
	Status            string    `json:"status"` // "healthy", "warning", "critical"
	LastActiveAt      *time.Time `json:"last_active_at,omitempty"`
	ContractStatus    string    `json:"contract_status"` // "current", "update_available", "expired"
	DataStorageUsed   int64     `json:"data_storage_used"`
	DataStorageLimit  int64     `json:"data_storage_limit"`
	RequestsThisHour  int       `json:"requests_this_hour"`
	RequestLimit      int       `json:"request_limit"`
	Issues            []string  `json:"issues,omitempty"`
}

// --- Handler Methods ---

func (h *ServiceConnectionHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	resp := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDiscover handles service.connection.discover
// Returns service profile and contract, checks for missing required fields
func (h *ServiceConnectionHandler) HandleDiscover(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DiscoverServiceRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ServiceGUID == "" {
		return h.errorResponse(msg.GetID(), "service_guid is required")
	}

	// In a real implementation, this would query the service vault via NATS
	// For now, we return an error indicating the service needs to provide its profile
	log.Info().
		Str("service_guid", req.ServiceGUID).
		Msg("Service discovery requested")

	// This handler is called when user initiates discovery
	// The actual service profile comes from the service vault
	return h.errorResponse(msg.GetID(), "Service discovery requires service vault response - use NATS to query service")
}

// HandleInitiate handles service.connection.initiate
// Accepts contract and establishes connection with service
func (h *ServiceConnectionHandler) HandleInitiate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req InitiateServiceConnectionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ServiceGUID == "" {
		return h.errorResponse(msg.GetID(), "service_guid is required")
	}
	if req.ServiceE2EPublicKey == "" {
		return h.errorResponse(msg.GetID(), "service_e2e_public_key is required")
	}

	// Generate connection ID
	connectionID := generateUUID()

	// Generate E2E key pair
	var privateKey [32]byte
	var publicKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to generate key pair")
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	// Decode service's public key
	peerPublicKey, err := decodeHexKey(req.ServiceE2EPublicKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Invalid service public key format")
	}

	// Compute shared secret
	var sharedSecret []byte
	if len(peerPublicKey) == 32 {
		sharedSecret, _ = curve25519.X25519(privateKey[:], peerPublicKey)
	}

	now := time.Now()

	// Create service connection record
	record := ServiceConnectionRecord{
		ConnectionID:        connectionID,
		Status:              "active",
		CreatedAt:           now,
		LocalPublicKey:      publicKey[:],
		LocalPrivateKey:     privateKey[:],
		PeerPublicKey:       peerPublicKey,
		SharedSecret:        sharedSecret,
		KeyExchangeAt:       now,
		IsServiceConnection: true,
		ServiceGUID:         req.ServiceGUID,
		ServiceProfile:      req.ServiceProfile,
		ContractID:          req.ServiceProfile.CurrentContract.ContractID,
		ContractVersion:     req.ContractVersion,
		ContractAcceptedAt:  now,
		Tags:                []string{},
		IsFavorite:          false,
		IsArchived:          false,
		IsMuted:             false,
		ActivityCount:       0,
	}

	// Store the connection
	storageKey := "service-connections/" + connectionID
	data, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to serialize connection")
	}
	if err := h.storage.Put(storageKey, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection")
	}

	// Update service connection index
	if err := h.addToConnectionIndex(connectionID); err != nil {
		log.Warn().Err(err).Msg("Failed to update connection index")
	}

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeServiceConnectionAccepted, connectionID, req.ServiceGUID, "Service connection established")
	}

	log.Info().
		Str("connection_id", connectionID).
		Str("service_guid", req.ServiceGUID).
		Int("contract_version", req.ContractVersion).
		Msg("Service connection established")

	// DEV-026: Get shared profile data to include in response
	var sharedProfile map[string]ProfileFieldResponse
	if h.profileHandler != nil {
		sharedProfile = h.getSharedProfileForConnection(connectionID)
	}

	resp := InitiateServiceConnectionResponse{
		ConnectionID:  connectionID,
		E2EPublicKey:  fmt.Sprintf("%x", publicKey[:]),
		Status:        "active",
		SharedProfile: sharedProfile,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleList handles service.connection.list
func (h *ServiceConnectionHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListServiceConnectionsRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		// Default values if no payload
		req = ListServiceConnectionsRequest{
			Limit:  50,
			Offset: 0,
		}
	}

	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	// Load connection index
	indexData, err := h.storage.Get("service-connections/_index")
	var connectionIDs []string
	if err == nil {
		json.Unmarshal(indexData, &connectionIDs)
	}

	var connections []ServiceConnectionInfo
	for _, connID := range connectionIDs {
		data, err := h.storage.Get("service-connections/" + connID)
		if err != nil {
			continue
		}

		var record ServiceConnectionRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}

		// Apply filters
		if req.Status != "" && record.Status != req.Status {
			continue
		}
		if req.IsFavorite != nil && record.IsFavorite != *req.IsFavorite {
			continue
		}
		if req.IsArchived != nil && record.IsArchived != *req.IsArchived {
			continue
		}
		if len(req.Tags) > 0 {
			hasTag := false
			for _, reqTag := range req.Tags {
				for _, recTag := range record.Tags {
					if reqTag == recTag {
						hasTag = true
						break
					}
				}
				if hasTag {
					break
				}
			}
			if !hasTag {
				continue
			}
		}
		if req.Search != "" {
			searchLower := strings.ToLower(req.Search)
			nameLower := strings.ToLower(record.ServiceProfile.ServiceName)
			if !strings.Contains(nameLower, searchLower) {
				continue
			}
		}

		info := ServiceConnectionInfo{
			ConnectionID:           record.ConnectionID,
			ServiceGUID:            record.ServiceGUID,
			ServiceName:            record.ServiceProfile.ServiceName,
			ServiceLogoURL:         record.ServiceProfile.ServiceLogoURL,
			ServiceCategory:        record.ServiceProfile.ServiceCategory,
			OrganizationVerified:   record.ServiceProfile.Organization.Verified,
			Status:                 record.Status,
			ContractVersion:        record.ContractVersion,
			PendingContractVersion: record.PendingContractVersion,
			LastActiveAt:           record.LastActiveAt,
			CreatedAt:              record.CreatedAt,
			Tags:                   record.Tags,
			IsFavorite:             record.IsFavorite,
			IsArchived:             record.IsArchived,
			IsMuted:                record.IsMuted,
		}
		connections = append(connections, info)
	}

	// Apply pagination
	total := len(connections)
	start := req.Offset
	if start > total {
		start = total
	}
	end := start + req.Limit
	if end > total {
		end = total
	}

	paginatedConnections := connections[start:end]
	if paginatedConnections == nil {
		paginatedConnections = []ServiceConnectionInfo{}
	}

	resp := ListServiceConnectionsResponse{
		Connections: paginatedConnections,
		Total:       total,
		HasMore:     end < total,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGet handles service.connection.get
func (h *ServiceConnectionHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetServiceConnectionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	data, err := h.storage.Get("service-connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ServiceConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	// Don't expose private keys in response
	record.LocalPrivateKey = nil
	record.SharedSecret = nil

	resp := GetServiceConnectionResponse{
		Connection: record,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleUpdate handles service.connection.update
func (h *ServiceConnectionHandler) HandleUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req UpdateServiceConnectionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	storageKey := "service-connections/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ServiceConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	// Apply updates
	if req.Tags != nil {
		record.Tags = *req.Tags
	}
	if req.IsFavorite != nil {
		record.IsFavorite = *req.IsFavorite
	}
	if req.IsArchived != nil {
		record.IsArchived = *req.IsArchived
	}
	if req.IsMuted != nil {
		record.IsMuted = *req.IsMuted
	}

	// Save updated record
	newData, _ := json.Marshal(record)
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update connection")
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Msg("Service connection updated")

	resp := UpdateServiceConnectionResponse{
		Success: true,
		Message: "Connection updated",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRevoke handles service.connection.revoke
// This is a clean break - service loses all access immediately
func (h *ServiceConnectionHandler) HandleRevoke(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RevokeServiceConnectionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	storageKey := "service-connections/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ServiceConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	var exportedData []byte
	if req.ExportDataFirst || req.DeleteData {
		// Export service data before deletion if requested
		exportedData, _ = h.exportServiceData(req.ConnectionID)
	}

	if req.DeleteData {
		// Delete all data stored by this service
		h.deleteServiceData(req.ConnectionID)
	}

	// Mark connection as revoked
	record.Status = "revoked"
	newData, _ := json.Marshal(record)
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to revoke connection")
	}

	// Remove from index
	h.removeFromConnectionIndex(req.ConnectionID)

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeServiceConnectionRevoked, req.ConnectionID, record.ServiceGUID, "Service connection revoked by user")
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Str("service_guid", record.ServiceGUID).
		Bool("data_deleted", req.DeleteData).
		Msg("Service connection revoked")

	resp := RevokeServiceConnectionResponse{
		Success:      true,
		ExportedData: exportedData,
		Message:      "Connection revoked",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleHealth handles service.connection.health
func (h *ServiceConnectionHandler) HandleHealth(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ServiceConnectionHealthRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	data, err := h.storage.Get("service-connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ServiceConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	// Calculate health status
	var issues []string
	status := "healthy"

	// Check contract status
	contractStatus := "current"
	if record.PendingContractVersion != nil {
		contractStatus = "update_available"
		issues = append(issues, "Contract update pending")
		status = "warning"
	}

	// Get storage usage
	storageUsed, _ := h.getServiceStorageUsage(req.ConnectionID)
	storageLimit := int64(record.ServiceProfile.CurrentContract.MaxStorageMB * 1024 * 1024)
	if storageLimit > 0 && storageUsed > storageLimit*90/100 {
		issues = append(issues, "Storage usage above 90%")
		status = "warning"
	}

	// Get request rate (would need rate limit tracking)
	requestsThisHour := 0 // TODO: implement rate tracking
	requestLimit := record.ServiceProfile.CurrentContract.MaxRequestsPerHour

	if record.Status == "suspended" {
		status = "critical"
		issues = append(issues, "Connection suspended")
	}

	health := ServiceConnectionHealth{
		ConnectionID:     req.ConnectionID,
		Status:           status,
		LastActiveAt:     record.LastActiveAt,
		ContractStatus:   contractStatus,
		DataStorageUsed:  storageUsed,
		DataStorageLimit: storageLimit,
		RequestsThisHour: requestsThisHour,
		RequestLimit:     requestLimit,
		Issues:           issues,
	}

	respBytes, _ := json.Marshal(health)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// --- Helper Methods ---

func (h *ServiceConnectionHandler) addToConnectionIndex(connectionID string) error {
	indexKey := "service-connections/_index"
	indexData, _ := h.storage.Get(indexKey)

	var connectionIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &connectionIDs)
	}

	// Add new ID
	connectionIDs = append(connectionIDs, connectionID)

	newIndexData, _ := json.Marshal(connectionIDs)
	return h.storage.Put(indexKey, newIndexData)
}

func (h *ServiceConnectionHandler) removeFromConnectionIndex(connectionID string) error {
	indexKey := "service-connections/_index"
	indexData, _ := h.storage.Get(indexKey)

	var connectionIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &connectionIDs)
	}

	// Remove ID
	var newIDs []string
	for _, id := range connectionIDs {
		if id != connectionID {
			newIDs = append(newIDs, id)
		}
	}

	newIndexData, _ := json.Marshal(newIDs)
	return h.storage.Put(indexKey, newIndexData)
}

func (h *ServiceConnectionHandler) exportServiceData(connectionID string) ([]byte, error) {
	// Export all data stored by a service
	// TODO: Implement when storage list support is available
	// Would iterate over all keys with prefix "service-data/{connectionID}/"
	return json.Marshal(map[string]interface{}{
		"connection_id": connectionID,
		"exported_at":   time.Now(),
		"data":          []interface{}{},
	})
}

func (h *ServiceConnectionHandler) deleteServiceData(connectionID string) error {
	// Delete all data stored by a service
	// This would delete all keys with prefix "service-data/{connectionID}/"
	// Actual implementation needs storage list/delete support
	log.Info().Str("connection_id", connectionID).Msg("Deleting service data")
	return nil
}

func (h *ServiceConnectionHandler) getServiceStorageUsage(connectionID string) (int64, error) {
	// Calculate total storage used by a service
	// This would sum sizes of all keys with prefix "service-data/{connectionID}/"
	// For now, return 0
	return 0, nil
}

// GetConnection retrieves a service connection by ID (for use by other handlers)
func (h *ServiceConnectionHandler) GetConnection(connectionID string) (*ServiceConnectionRecord, error) {
	data, err := h.storage.Get("service-connections/" + connectionID)
	if err != nil {
		return nil, err
	}

	var record ServiceConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}

	return &record, nil
}

// UpdateLastActive updates the last active timestamp for a connection
func (h *ServiceConnectionHandler) UpdateLastActive(connectionID string) error {
	storageKey := "service-connections/" + connectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return err
	}

	var record ServiceConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return err
	}

	now := time.Now()
	record.LastActiveAt = &now
	record.ActivityCount++

	newData, _ := json.Marshal(record)
	return h.storage.Put(storageKey, newData)
}

// generateUUID generates a simple UUID
func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// getSharedProfileForConnection returns the profile fields to share with a new connection
// DEV-026: Profile auto-sharing on connection initiation
func (h *ServiceConnectionHandler) getSharedProfileForConnection(connectionID string) map[string]ProfileFieldResponse {
	if h.profileHandler == nil {
		return nil
	}

	// Load sharing settings
	settingsData, err := h.storage.Get("profile/_sharing_settings")
	if err != nil {
		log.Debug().Msg("No sharing settings found, returning empty profile")
		return nil
	}

	var settings SharingSettings
	if err := json.Unmarshal(settingsData, &settings); err != nil {
		log.Warn().Err(err).Msg("Failed to parse sharing settings")
		return nil
	}

	// Determine which fields to share
	fieldsToShare := settings.DefaultShared

	// Apply connection-specific overrides if available
	if settings.ConnectionOverrides != nil {
		if override, exists := settings.ConnectionOverrides[connectionID]; exists {
			fieldsToShare = override
		}
	}

	if len(fieldsToShare) == 0 {
		return nil
	}

	// Fetch the profile fields
	sharedProfile := make(map[string]ProfileFieldResponse)
	for _, field := range fieldsToShare {
		storageKey := "profile/" + field
		data, err := h.storage.Get(storageKey)
		if err != nil {
			continue // Skip missing fields
		}

		var entry ProfileEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}

		sharedProfile[field] = ProfileFieldResponse{
			Value:     entry.Value,
			UpdatedAt: entry.UpdatedAt.Format(time.RFC3339),
		}
	}

	if len(sharedProfile) == 0 {
		return nil
	}

	log.Info().
		Str("connection_id", connectionID).
		Int("shared_fields", len(sharedProfile)).
		Msg("Auto-shared profile fields on connection")

	return sharedProfile
}
