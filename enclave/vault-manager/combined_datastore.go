package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// CombinedDatastoreHandler manages combined datastores for cross-service collaboration.
// Combined datastores allow multiple services to share data within the user's vault,
// all with user consent and full audit trails.
//
// Key security principles:
// - User must approve datastore creation and each participant
// - Each datastore has its own encryption key (DEK)
// - All access is permission-controlled and audited
// - Data never leaves the user's vault
type CombinedDatastoreHandler struct {
	ownerSpace       string
	storage          *EncryptedStorage
	eventHandler     *EventHandler
	connectionHandler *ServiceConnectionHandler
	publisher        *VsockPublisher
}

// NewCombinedDatastoreHandler creates a new combined datastore handler
func NewCombinedDatastoreHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	eventHandler *EventHandler,
	connectionHandler *ServiceConnectionHandler,
	publisher *VsockPublisher,
) *CombinedDatastoreHandler {
	return &CombinedDatastoreHandler{
		ownerSpace:        ownerSpace,
		storage:           storage,
		eventHandler:      eventHandler,
		connectionHandler: connectionHandler,
		publisher:         publisher,
	}
}

// --- Data Models ---

// CombinedDatastore represents a shared datastore between multiple services
type CombinedDatastore struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	OwnerSpace    string                 `json:"owner_space"` // User who owns this
	CreatedAt     time.Time              `json:"created_at"`
	CreatedBy     string                 `json:"created_by"` // Service that initiated
	Status        string                 `json:"status"`     // "pending", "active", "archived"
	Participants  []DatastoreParticipant `json:"participants"`
	Schema        *DatastoreSchema       `json:"schema,omitempty"`
	EncryptionKey []byte                 `json:"encryption_key"` // DEK for this datastore
	Version       int64                  `json:"version"`        // For optimistic locking
	UpdatedAt     time.Time              `json:"updated_at"`
	UpdatedBy     string                 `json:"updated_by"`
}

// DatastoreParticipant represents a service participating in a combined datastore
type DatastoreParticipant struct {
	ServiceID   string              `json:"service_id"`
	ServiceName string              `json:"service_name"`
	Status      string              `json:"status"` // "invited", "accepted", "active", "removed"
	JoinedAt    *time.Time          `json:"joined_at,omitempty"`
	Permissions DatastorePermission `json:"permissions"`
	ApprovedAt  *time.Time          `json:"approved_at,omitempty"` // User approval timestamp
	InvitedBy   string              `json:"invited_by,omitempty"`  // Service that invited them
	InvitedAt   time.Time           `json:"invited_at"`
}

// DatastorePermission defines what a participant can do
type DatastorePermission struct {
	Read   bool     `json:"read"`
	Write  bool     `json:"write"`
	Delete bool     `json:"delete"`
	Fields []string `json:"fields,omitempty"` // Specific fields, empty = all
}

// DatastoreSchema defines optional schema validation
type DatastoreSchema struct {
	Version int                       `json:"version"`
	Fields  []DatastoreFieldSchema    `json:"fields"`
}

// DatastoreFieldSchema defines a field in the schema
type DatastoreFieldSchema struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "string", "number", "boolean", "object", "array"
	Required    bool   `json:"required"`
	Description string `json:"description,omitempty"`
}

// DatastoreData holds the actual data in the datastore
type DatastoreData struct {
	DatastoreID string                 `json:"datastore_id"`
	Data        map[string]interface{} `json:"data"`
	Version     int64                  `json:"version"`
	UpdatedAt   time.Time              `json:"updated_at"`
	UpdatedBy   string                 `json:"updated_by"`
}

// DatastoreInvitation represents a pending invitation
type DatastoreInvitation struct {
	InvitationID string              `json:"invitation_id"`
	DatastoreID  string              `json:"datastore_id"`
	ServiceID    string              `json:"service_id"`
	ServiceName  string              `json:"service_name"`
	Permissions  DatastorePermission `json:"permissions"`
	InvitedBy    string              `json:"invited_by"`
	InvitedAt    time.Time           `json:"invited_at"`
	ExpiresAt    time.Time           `json:"expires_at"`
	Status       string              `json:"status"` // "pending", "accepted", "rejected", "expired"
}

// --- Storage Keys ---

const (
	KeyDatastorePrefix     = "datastores/"           // datastores/{id}
	KeyDatastoreIndex      = "datastores-index"      // List of datastore IDs
	KeyDatastoreDataPrefix = "datastore-data/"       // datastore-data/{id}
	KeyInvitationPrefix    = "datastore-invites/"    // datastore-invites/{id}
	KeyInvitationIndex     = "datastore-invites-index"
)

// --- Request/Response Types ---

// CreateDatastoreRequest is the payload for datastore.create
type CreateDatastoreRequest struct {
	Name         string                  `json:"name"`
	Description  string                  `json:"description"`
	InitiatorID  string                  `json:"initiator_id"` // Service creating the datastore
	Participants []ParticipantRequest    `json:"participants"` // Initial participants to invite
	Schema       *DatastoreSchema        `json:"schema,omitempty"`
}

// ParticipantRequest describes a participant to add
type ParticipantRequest struct {
	ServiceID   string              `json:"service_id"`
	Permissions DatastorePermission `json:"permissions"`
}

// CreateDatastoreResponse is the response for datastore.create
type CreateDatastoreResponse struct {
	Success     bool   `json:"success"`
	DatastoreID string `json:"datastore_id"`
	Status      string `json:"status"` // "pending_approval"
	Message     string `json:"message,omitempty"`
}

// ApproveDatastoreRequest is for user approving datastore creation
type ApproveDatastoreRequest struct {
	DatastoreID string `json:"datastore_id"`
}

// ApproveDatastoreResponse is the response for approval
type ApproveDatastoreResponse struct {
	Success     bool   `json:"success"`
	DatastoreID string `json:"datastore_id"`
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
}

// InviteParticipantRequest is for inviting a new service to join
type InviteParticipantRequest struct {
	DatastoreID string              `json:"datastore_id"`
	ServiceID   string              `json:"service_id"`
	Permissions DatastorePermission `json:"permissions"`
}

// InviteParticipantResponse is the response for invitation
type InviteParticipantResponse struct {
	Success      bool   `json:"success"`
	InvitationID string `json:"invitation_id"`
	Message      string `json:"message,omitempty"`
}

// AcceptInvitationRequest is for a service accepting an invitation
type AcceptInvitationRequest struct {
	InvitationID string `json:"invitation_id"`
	ServiceID    string `json:"service_id"`
}

// AcceptInvitationResponse is the response for accepting invitation
type AcceptInvitationResponse struct {
	Success     bool   `json:"success"`
	DatastoreID string `json:"datastore_id"`
	Status      string `json:"status"` // "pending_user_approval" or "active"
	Message     string `json:"message,omitempty"`
}

// ApproveParticipantRequest is for user approving a participant
type ApproveParticipantRequest struct {
	DatastoreID string `json:"datastore_id"`
	ServiceID   string `json:"service_id"`
}

// ApproveParticipantResponse is the response for participant approval
type ApproveParticipantResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ListDatastoresRequest is for listing datastores
type ListDatastoresRequest struct {
	Status string `json:"status,omitempty"` // Filter by status
}

// ListDatastoresResponse is the response for listing
type ListDatastoresResponse struct {
	Datastores []DatastoreInfo `json:"datastores"`
}

// DatastoreInfo is the public view of a datastore
type DatastoreInfo struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Status       string                 `json:"status"`
	CreatedAt    time.Time              `json:"created_at"`
	CreatedBy    string                 `json:"created_by"`
	Participants []ParticipantInfo      `json:"participants"`
	Version      int64                  `json:"version"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

// ParticipantInfo is the public view of a participant
type ParticipantInfo struct {
	ServiceID   string              `json:"service_id"`
	ServiceName string              `json:"service_name"`
	Status      string              `json:"status"`
	Permissions DatastorePermission `json:"permissions"`
	JoinedAt    *time.Time          `json:"joined_at,omitempty"`
}

// GetDatastoreRequest is for getting a specific datastore
type GetDatastoreRequest struct {
	DatastoreID string `json:"datastore_id"`
}

// GetDatastoreResponse is the response for getting a datastore
type GetDatastoreResponse struct {
	Datastore DatastoreInfo `json:"datastore"`
}

// --- Handlers ---

// HandleCreate handles datastore.create - service requests a new combined datastore
func (h *CombinedDatastoreHandler) HandleCreate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CreateDatastoreRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Validate initiator is a connected service
	conn, err := h.connectionHandler.GetConnectionByServiceID(req.InitiatorID)
	if err != nil || conn == nil || conn.Status != "active" {
		return h.errorResponse(msg.GetID(), "initiator service not connected")
	}

	// Generate unique DEK for this datastore
	dek := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(dek); err != nil {
		return h.errorResponse(msg.GetID(), "failed to generate encryption key")
	}

	// Create datastore
	datastoreID := generateDatastoreID()
	now := time.Now()

	initiatorName := conn.ServiceProfile.ServiceName
	if initiatorName == "" {
		initiatorName = req.InitiatorID
	}

	participants := []DatastoreParticipant{
		{
			ServiceID:   req.InitiatorID,
			ServiceName: initiatorName,
			Status:      "active", // Initiator is automatically active
			JoinedAt:    &now,
			Permissions: DatastorePermission{Read: true, Write: true, Delete: false},
			ApprovedAt:  nil, // Will be set when user approves entire datastore
			InvitedAt:   now,
		},
	}

	// Add invited participants
	for _, p := range req.Participants {
		// Look up service name
		pConn, err := h.connectionHandler.GetConnectionByServiceID(p.ServiceID)
		serviceName := p.ServiceID
		if err == nil && pConn != nil && pConn.ServiceProfile.ServiceName != "" {
			serviceName = pConn.ServiceProfile.ServiceName
		}

		participants = append(participants, DatastoreParticipant{
			ServiceID:   p.ServiceID,
			ServiceName: serviceName,
			Status:      "invited",
			Permissions: p.Permissions,
			InvitedBy:   req.InitiatorID,
			InvitedAt:   now,
		})
	}

	datastore := &CombinedDatastore{
		ID:            datastoreID,
		Name:          req.Name,
		Description:   req.Description,
		OwnerSpace:    h.ownerSpace,
		CreatedAt:     now,
		CreatedBy:     req.InitiatorID,
		Status:        "pending", // Needs user approval
		Participants:  participants,
		Schema:        req.Schema,
		EncryptionKey: dek,
		Version:       1,
		UpdatedAt:     now,
		UpdatedBy:     req.InitiatorID,
	}

	// Store datastore
	if err := h.storeDatastore(datastore); err != nil {
		return h.errorResponse(msg.GetID(), "failed to store datastore")
	}

	// Initialize empty data
	data := &DatastoreData{
		DatastoreID: datastoreID,
		Data:        make(map[string]interface{}),
		Version:     1,
		UpdatedAt:   now,
		UpdatedBy:   req.InitiatorID,
	}
	if err := h.storeDatastoreData(data); err != nil {
		log.Warn().Err(err).Msg("Failed to initialize datastore data")
	}

	// Create feed event for user approval
	h.logDatastoreEvent("datastore.creation_pending", datastoreID, req.Name, req.InitiatorID, initiatorName)

	// Send invitations to other participants
	for _, p := range participants {
		if p.Status == "invited" {
			h.sendInvitation(datastore, &p)
		}
	}

	log.Info().
		Str("datastore_id", datastoreID).
		Str("name", req.Name).
		Str("initiator", req.InitiatorID).
		Int("participants", len(participants)).
		Msg("Combined datastore creation requested")

	return h.successResponse(msg.GetID(), CreateDatastoreResponse{
		Success:     true,
		DatastoreID: datastoreID,
		Status:      "pending_approval",
		Message:     "Datastore created, awaiting user approval",
	})
}

// HandleApprove handles datastore.approve - user approves the datastore
func (h *CombinedDatastoreHandler) HandleApprove(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ApproveDatastoreRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	datastore, err := h.getDatastore(req.DatastoreID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "datastore not found")
	}

	if datastore.Status != "pending" {
		return h.errorResponse(msg.GetID(), "datastore is not pending approval")
	}

	// Activate datastore
	now := time.Now()
	datastore.Status = "active"
	datastore.UpdatedAt = now

	// Approve the initiator participant
	for i := range datastore.Participants {
		if datastore.Participants[i].ServiceID == datastore.CreatedBy {
			datastore.Participants[i].ApprovedAt = &now
		}
	}

	if err := h.storeDatastore(datastore); err != nil {
		return h.errorResponse(msg.GetID(), "failed to update datastore")
	}

	// Log event
	h.logDatastoreEvent("datastore.approved", datastore.ID, datastore.Name, datastore.CreatedBy, "")

	// Notify initiator that datastore is now active
	h.notifyParticipant(datastore, datastore.CreatedBy, "datastore_activated", map[string]interface{}{
		"datastore_id": datastore.ID,
		"name":         datastore.Name,
	})

	log.Info().
		Str("datastore_id", datastore.ID).
		Msg("Datastore approved by user")

	return h.successResponse(msg.GetID(), ApproveDatastoreResponse{
		Success:     true,
		DatastoreID: datastore.ID,
		Status:      "active",
		Message:     "Datastore approved and active",
	})
}

// HandleReject handles datastore.reject - user rejects the datastore
func (h *CombinedDatastoreHandler) HandleReject(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ApproveDatastoreRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	datastore, err := h.getDatastore(req.DatastoreID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "datastore not found")
	}

	// Archive the datastore
	datastore.Status = "rejected"
	datastore.UpdatedAt = time.Now()

	if err := h.storeDatastore(datastore); err != nil {
		return h.errorResponse(msg.GetID(), "failed to update datastore")
	}

	// Notify initiator
	h.notifyParticipant(datastore, datastore.CreatedBy, "datastore_rejected", map[string]interface{}{
		"datastore_id": datastore.ID,
		"name":         datastore.Name,
	})

	log.Info().
		Str("datastore_id", datastore.ID).
		Msg("Datastore rejected by user")

	return h.successResponse(msg.GetID(), ApproveDatastoreResponse{
		Success:     true,
		DatastoreID: datastore.ID,
		Status:      "rejected",
		Message:     "Datastore rejected",
	})
}

// HandleInviteParticipant handles datastore.invite - invite another service
func (h *CombinedDatastoreHandler) HandleInviteParticipant(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req InviteParticipantRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	datastore, err := h.getDatastore(req.DatastoreID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "datastore not found")
	}

	if datastore.Status != "active" {
		return h.errorResponse(msg.GetID(), "datastore is not active")
	}

	// Check if service is already a participant
	for _, p := range datastore.Participants {
		if p.ServiceID == req.ServiceID {
			return h.errorResponse(msg.GetID(), "service is already a participant")
		}
	}

	// Look up service name
	conn, _ := h.connectionHandler.GetConnectionByServiceID(req.ServiceID)
	serviceName := req.ServiceID
	if conn != nil && conn.ServiceProfile.ServiceName != "" {
		serviceName = conn.ServiceProfile.ServiceName
	}

	// Add as invited participant
	now := time.Now()
	participant := DatastoreParticipant{
		ServiceID:   req.ServiceID,
		ServiceName: serviceName,
		Status:      "invited",
		Permissions: req.Permissions,
		InvitedBy:   "", // TODO: Get from message context
		InvitedAt:   now,
	}

	datastore.Participants = append(datastore.Participants, participant)
	datastore.UpdatedAt = now

	if err := h.storeDatastore(datastore); err != nil {
		return h.errorResponse(msg.GetID(), "failed to update datastore")
	}

	// Create and store invitation
	invitation := &DatastoreInvitation{
		InvitationID: generateInvitationID(),
		DatastoreID:  datastore.ID,
		ServiceID:    req.ServiceID,
		ServiceName:  serviceName,
		Permissions:  req.Permissions,
		InvitedAt:    now,
		ExpiresAt:    now.Add(7 * 24 * time.Hour), // 7 days
		Status:       "pending",
	}

	if err := h.storeInvitation(invitation); err != nil {
		log.Warn().Err(err).Msg("Failed to store invitation")
	}

	// Send invitation to service
	h.sendInvitation(datastore, &participant)

	log.Info().
		Str("datastore_id", datastore.ID).
		Str("service_id", req.ServiceID).
		Msg("Service invited to datastore")

	return h.successResponse(msg.GetID(), InviteParticipantResponse{
		Success:      true,
		InvitationID: invitation.InvitationID,
		Message:      "Invitation sent",
	})
}

// HandleAcceptInvitation handles datastore.join - service accepts invitation
func (h *CombinedDatastoreHandler) HandleAcceptInvitation(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AcceptInvitationRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Find invitation
	invitation, err := h.getInvitation(req.InvitationID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invitation not found")
	}

	if invitation.ServiceID != req.ServiceID {
		return h.errorResponse(msg.GetID(), "invitation is not for this service")
	}

	if invitation.Status != "pending" {
		return h.errorResponse(msg.GetID(), "invitation is no longer pending")
	}

	if time.Now().After(invitation.ExpiresAt) {
		invitation.Status = "expired"
		h.storeInvitation(invitation)
		return h.errorResponse(msg.GetID(), "invitation has expired")
	}

	// Get datastore
	datastore, err := h.getDatastore(invitation.DatastoreID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "datastore not found")
	}

	// Update participant status
	now := time.Now()
	for i := range datastore.Participants {
		if datastore.Participants[i].ServiceID == req.ServiceID {
			datastore.Participants[i].Status = "pending_approval" // Needs user approval
			datastore.Participants[i].JoinedAt = &now
		}
	}
	datastore.UpdatedAt = now

	if err := h.storeDatastore(datastore); err != nil {
		return h.errorResponse(msg.GetID(), "failed to update datastore")
	}

	// Update invitation
	invitation.Status = "accepted"
	h.storeInvitation(invitation)

	// Create feed event for user approval
	h.logDatastoreEvent("datastore.participant_pending", datastore.ID, datastore.Name, req.ServiceID, invitation.ServiceName)

	log.Info().
		Str("datastore_id", datastore.ID).
		Str("service_id", req.ServiceID).
		Msg("Service accepted datastore invitation, pending user approval")

	return h.successResponse(msg.GetID(), AcceptInvitationResponse{
		Success:     true,
		DatastoreID: datastore.ID,
		Status:      "pending_user_approval",
		Message:     "Invitation accepted, awaiting user approval",
	})
}

// HandleApproveParticipant handles datastore.approve-participant - user approves a participant
func (h *CombinedDatastoreHandler) HandleApproveParticipant(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ApproveParticipantRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	datastore, err := h.getDatastore(req.DatastoreID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "datastore not found")
	}

	// Find and approve participant
	now := time.Now()
	found := false
	var participantName string
	for i := range datastore.Participants {
		if datastore.Participants[i].ServiceID == req.ServiceID {
			if datastore.Participants[i].Status != "pending_approval" {
				return h.errorResponse(msg.GetID(), "participant is not pending approval")
			}
			datastore.Participants[i].Status = "active"
			datastore.Participants[i].ApprovedAt = &now
			participantName = datastore.Participants[i].ServiceName
			found = true
			break
		}
	}

	if !found {
		return h.errorResponse(msg.GetID(), "participant not found")
	}

	datastore.UpdatedAt = now

	if err := h.storeDatastore(datastore); err != nil {
		return h.errorResponse(msg.GetID(), "failed to update datastore")
	}

	// Notify the participant
	h.notifyParticipant(datastore, req.ServiceID, "participant_approved", map[string]interface{}{
		"datastore_id":   datastore.ID,
		"datastore_name": datastore.Name,
	})

	// Log event
	h.logDatastoreEvent("datastore.participant_approved", datastore.ID, datastore.Name, req.ServiceID, participantName)

	log.Info().
		Str("datastore_id", datastore.ID).
		Str("service_id", req.ServiceID).
		Msg("Participant approved by user")

	return h.successResponse(msg.GetID(), ApproveParticipantResponse{
		Success: true,
		Message: "Participant approved",
	})
}

// HandleList handles datastore.list - list all datastores
func (h *CombinedDatastoreHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListDatastoresRequest
	if msg.Payload != nil {
		json.Unmarshal(msg.Payload, &req)
	}

	datastoreIDs, err := h.storage.GetIndex(KeyDatastoreIndex)
	if err != nil {
		return h.errorResponse(msg.GetID(), "failed to list datastores")
	}

	var datastores []DatastoreInfo
	for _, id := range datastoreIDs {
		ds, err := h.getDatastore(id)
		if err != nil {
			continue
		}

		// Filter by status if specified
		if req.Status != "" && ds.Status != req.Status {
			continue
		}

		// Convert to info
		var participants []ParticipantInfo
		for _, p := range ds.Participants {
			participants = append(participants, ParticipantInfo{
				ServiceID:   p.ServiceID,
				ServiceName: p.ServiceName,
				Status:      p.Status,
				Permissions: p.Permissions,
				JoinedAt:    p.JoinedAt,
			})
		}

		datastores = append(datastores, DatastoreInfo{
			ID:           ds.ID,
			Name:         ds.Name,
			Description:  ds.Description,
			Status:       ds.Status,
			CreatedAt:    ds.CreatedAt,
			CreatedBy:    ds.CreatedBy,
			Participants: participants,
			Version:      ds.Version,
			UpdatedAt:    ds.UpdatedAt,
		})
	}

	return h.successResponse(msg.GetID(), ListDatastoresResponse{
		Datastores: datastores,
	})
}

// HandleGet handles datastore.get - get a specific datastore
func (h *CombinedDatastoreHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetDatastoreRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	ds, err := h.getDatastore(req.DatastoreID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "datastore not found")
	}

	var participants []ParticipantInfo
	for _, p := range ds.Participants {
		participants = append(participants, ParticipantInfo{
			ServiceID:   p.ServiceID,
			ServiceName: p.ServiceName,
			Status:      p.Status,
			Permissions: p.Permissions,
			JoinedAt:    p.JoinedAt,
		})
	}

	return h.successResponse(msg.GetID(), GetDatastoreResponse{
		Datastore: DatastoreInfo{
			ID:           ds.ID,
			Name:         ds.Name,
			Description:  ds.Description,
			Status:       ds.Status,
			CreatedAt:    ds.CreatedAt,
			CreatedBy:    ds.CreatedBy,
			Participants: participants,
			Version:      ds.Version,
			UpdatedAt:    ds.UpdatedAt,
		},
	})
}

// --- Helper Methods ---

func (h *CombinedDatastoreHandler) storeDatastore(ds *CombinedDatastore) error {
	key := KeyDatastorePrefix + ds.ID
	if err := h.storage.PutJSON(key, ds); err != nil {
		return err
	}
	return h.storage.AddToIndex(KeyDatastoreIndex, ds.ID)
}

func (h *CombinedDatastoreHandler) getDatastore(id string) (*CombinedDatastore, error) {
	key := KeyDatastorePrefix + id
	var ds CombinedDatastore
	if err := h.storage.GetJSON(key, &ds); err != nil {
		return nil, err
	}
	return &ds, nil
}

func (h *CombinedDatastoreHandler) storeDatastoreData(data *DatastoreData) error {
	key := KeyDatastoreDataPrefix + data.DatastoreID
	return h.storage.PutJSON(key, data)
}

func (h *CombinedDatastoreHandler) getDatastoreData(datastoreID string) (*DatastoreData, error) {
	key := KeyDatastoreDataPrefix + datastoreID
	var data DatastoreData
	if err := h.storage.GetJSON(key, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

func (h *CombinedDatastoreHandler) storeInvitation(inv *DatastoreInvitation) error {
	key := KeyInvitationPrefix + inv.InvitationID
	if err := h.storage.PutJSON(key, inv); err != nil {
		return err
	}
	return h.storage.AddToIndex(KeyInvitationIndex, inv.InvitationID)
}

func (h *CombinedDatastoreHandler) getInvitation(id string) (*DatastoreInvitation, error) {
	key := KeyInvitationPrefix + id
	var inv DatastoreInvitation
	if err := h.storage.GetJSON(key, &inv); err != nil {
		return nil, err
	}
	return &inv, nil
}

func (h *CombinedDatastoreHandler) sendInvitation(ds *CombinedDatastore, participant *DatastoreParticipant) {
	// Send invitation via NATS to the service's vault
	payload := map[string]interface{}{
		"type":           "datastore_invitation",
		"datastore_id":   ds.ID,
		"datastore_name": ds.Name,
		"description":    ds.Description,
		"permissions":    participant.Permissions,
		"invited_by":     participant.InvitedBy,
		"expires_at":     time.Now().Add(7 * 24 * time.Hour),
	}

	data, _ := json.Marshal(payload)

	// Publish to the service's message space
	subject := fmt.Sprintf("ServiceSpace.%s.fromVault.%s.datastore.invitation",
		participant.ServiceID, h.ownerSpace)

	h.publisher.PublishRaw(subject, data)
}

func (h *CombinedDatastoreHandler) notifyParticipant(ds *CombinedDatastore, serviceID string, eventType string, payload map[string]interface{}) {
	data, _ := json.Marshal(payload)
	subject := fmt.Sprintf("ServiceSpace.%s.fromVault.%s.datastore.%s",
		serviceID, h.ownerSpace, eventType)
	h.publisher.PublishRaw(subject, data)
}

func generateDatastoreID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "DS-" + hex.EncodeToString(b)
}

func generateInvitationID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "INV-" + hex.EncodeToString(b)
}

// logDatastoreEvent logs a datastore-related event
func (h *CombinedDatastoreHandler) logDatastoreEvent(eventType, datastoreID, datastoreName, serviceID, serviceName string) {
	metadata := map[string]string{
		"datastore_id":   datastoreID,
		"datastore_name": datastoreName,
	}
	if serviceID != "" {
		metadata["service_id"] = serviceID
	}
	if serviceName != "" {
		metadata["service_name"] = serviceName
	}

	h.eventHandler.LogServiceEvent(
		nil,
		EventType(eventType),
		datastoreID,
		serviceID,
		serviceName,
		eventType,
		metadata,
	)
}

func (h *CombinedDatastoreHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshalJSON(map[string]interface{}{"success": false, "error": message}),
	}, nil
}

func (h *CombinedDatastoreHandler) successResponse(requestID string, payload interface{}) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshalJSON(payload),
	}, nil
}

func mustMarshalJSON(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"error":"marshal failed"}`)
	}
	return data
}
