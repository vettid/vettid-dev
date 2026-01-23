package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// ProfileManager manages the service's profile and trusted resources.
// The profile includes organization info, contact details, and trusted downloads.
type ProfileManager struct {
	ownerSpace string
	storage    *EncryptedStorage
	sendFn     func(msg *OutgoingMessage) error
}

// NewProfileManager creates a new profile manager
func NewProfileManager(
	ownerSpace string,
	storage *EncryptedStorage,
	sendFn func(msg *OutgoingMessage) error,
) *ProfileManager {
	return &ProfileManager{
		ownerSpace: ownerSpace,
		storage:    storage,
		sendFn:     sendFn,
	}
}

// --- Request/Response Types ---

// GetProfileRequest is the payload for profile.get
type GetProfileRequest struct{}

// GetProfileResponse is the response for profile.get
type GetProfileResponse struct {
	Profile *ServiceProfile `json:"profile,omitempty"`
	Message string          `json:"message,omitempty"`
}

// UpdateProfileRequest is the payload for profile.update
type UpdateProfileRequest struct {
	ServiceName        string             `json:"service_name"`
	ServiceDescription string             `json:"service_description"`
	ServiceLogoURL     string             `json:"service_logo_url,omitempty"`
	ServiceCategory    string             `json:"service_category"`
	Organization       OrganizationInfo   `json:"organization"`
	ContactInfo        ServiceContactInfo `json:"contact_info"`
}

// UpdateProfileResponse is the response for profile.update
type UpdateProfileResponse struct {
	Success        bool   `json:"success"`
	ProfileVersion int    `json:"profile_version"`
	Message        string `json:"message,omitempty"`
}

// AddResourceRequest is the payload for profile.resource.add
type AddResourceRequest struct {
	Type        string        `json:"type"` // "website", "app_download", "document", "api"
	Label       string        `json:"label"`
	Description string        `json:"description,omitempty"`
	URL         string        `json:"url"`
	Download    *DownloadInfo `json:"download,omitempty"`
}

// AddResourceResponse is the response for profile.resource.add
type AddResourceResponse struct {
	Success    bool   `json:"success"`
	ResourceID string `json:"resource_id"`
	Message    string `json:"message,omitempty"`
}

// RemoveResourceRequest is the payload for profile.resource.remove
type RemoveResourceRequest struct {
	ResourceID string `json:"resource_id"`
}

// RemoveResourceResponse is the response for profile.resource.remove
type RemoveResourceResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ListResourcesRequest is the payload for profile.resource.list
type ListResourcesRequest struct {
	Type string `json:"type,omitempty"` // Filter by type
}

// ListResourcesResponse is the response for profile.resource.list
type ListResourcesResponse struct {
	Resources []TrustedResource `json:"resources"`
}

// SignDownloadRequest is the payload for profile.resource.sign
type SignDownloadRequest struct {
	ResourceID string `json:"resource_id"`
	FileHash   string `json:"file_hash"` // SHA256 hash of the file
	Algorithm  string `json:"algorithm"` // "sha256" or "sha512"
}

// SignDownloadResponse is the response for profile.resource.sign
type SignDownloadResponse struct {
	Success   bool   `json:"success"`
	Signature string `json:"signature"` // Ed25519 signature
	PublicKey string `json:"public_key"` // Service's Ed25519 public key
	Message   string `json:"message,omitempty"`
}

// --- Handlers ---

// InitializeSigningKeys generates Ed25519 signing keys if not present
func (pm *ProfileManager) InitializeSigningKeys() error {
	// Check if keys exist
	privData, err := pm.storage.Get(KeySigningPrivate)
	if err != nil {
		return err
	}
	if privData != nil {
		log.Debug().Msg("Signing keys already initialized")
		return nil
	}

	// Generate new Ed25519 keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate signing keys: %w", err)
	}

	// Store keys
	if err := pm.storage.Put(KeySigningPrivate, privateKey); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}
	if err := pm.storage.Put(KeySigningPublic, publicKey); err != nil {
		return fmt.Errorf("failed to store public key: %w", err)
	}

	log.Info().Msg("Generated new Ed25519 signing keys")
	return nil
}

// HandleGetProfile returns the current service profile
func (pm *ProfileManager) HandleGetProfile(msg *IncomingMessage) (*OutgoingMessage, error) {
	profile, err := pm.GetCurrentProfile()
	if err != nil {
		return pm.errorResponse(msg.GetID(), "failed to get profile")
	}

	if profile == nil {
		return pm.successResponse(msg.GetID(), GetProfileResponse{
			Message: "No profile configured yet",
		})
	}

	return pm.successResponse(msg.GetID(), GetProfileResponse{
		Profile: profile,
	})
}

// HandleUpdateProfile updates the service profile
func (pm *ProfileManager) HandleUpdateProfile(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req UpdateProfileRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return pm.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Get current profile to determine version
	currentProfile, _ := pm.GetCurrentProfile()
	newVersion := 1
	if currentProfile != nil {
		newVersion = currentProfile.ProfileVersion + 1
	}

	// Get current contract
	contractData, _ := pm.storage.Get(KeyContractCurrent)
	var currentContract ServiceDataContract
	if contractData != nil {
		json.Unmarshal(contractData, &currentContract)
	}

	// Create updated profile
	profile := &ServiceProfile{
		ServiceGUID:        pm.ownerSpace,
		ServiceName:        req.ServiceName,
		ServiceDescription: req.ServiceDescription,
		ServiceLogoURL:     req.ServiceLogoURL,
		ServiceCategory:    req.ServiceCategory,
		Organization:       req.Organization,
		ContactInfo:        req.ContactInfo,
		CurrentContract:    currentContract,
		ProfileVersion:     newVersion,
		UpdatedAt:          time.Now(),
	}

	// Store profile
	if err := pm.storage.PutJSON(KeyProfileCurrent, profile); err != nil {
		return pm.errorResponse(msg.GetID(), "failed to store profile")
	}

	// Broadcast update to connected users
	pm.broadcastProfileUpdate(profile)

	log.Info().
		Int("version", newVersion).
		Str("service_name", profile.ServiceName).
		Msg("Profile updated")

	return pm.successResponse(msg.GetID(), UpdateProfileResponse{
		Success:        true,
		ProfileVersion: newVersion,
		Message:        "Profile updated successfully",
	})
}

// HandleAddResource adds a trusted resource to the profile
func (pm *ProfileManager) HandleAddResource(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AddResourceRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return pm.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Validate type
	validTypes := []string{"website", "app_download", "document", "api"}
	isValid := false
	for _, t := range validTypes {
		if t == req.Type {
			isValid = true
			break
		}
	}
	if !isValid {
		return pm.errorResponse(msg.GetID(), "invalid resource type")
	}

	// Create resource
	resource := &TrustedResource{
		ResourceID:  generateID(),
		Type:        req.Type,
		Label:       req.Label,
		Description: req.Description,
		URL:         req.URL,
		Download:    req.Download,
		AddedAt:     time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Store resource
	resourceKey := KeyProfileResourcePrefix + resource.ResourceID
	if err := pm.storage.PutJSON(resourceKey, resource); err != nil {
		return pm.errorResponse(msg.GetID(), "failed to store resource")
	}

	// Add to index
	if err := pm.storage.AddToIndex(KeyResourceIndex, resource.ResourceID); err != nil {
		log.Warn().Err(err).Msg("Failed to add resource to index")
	}

	log.Info().
		Str("resource_id", resource.ResourceID).
		Str("type", resource.Type).
		Str("label", resource.Label).
		Msg("Resource added")

	return pm.successResponse(msg.GetID(), AddResourceResponse{
		Success:    true,
		ResourceID: resource.ResourceID,
		Message:    "Resource added successfully",
	})
}

// HandleRemoveResource removes a trusted resource from the profile
func (pm *ProfileManager) HandleRemoveResource(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RemoveResourceRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return pm.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Delete resource
	resourceKey := KeyProfileResourcePrefix + req.ResourceID
	if err := pm.storage.Delete(resourceKey); err != nil {
		return pm.errorResponse(msg.GetID(), "failed to delete resource")
	}

	// Remove from index
	if err := pm.storage.RemoveFromIndex(KeyResourceIndex, req.ResourceID); err != nil {
		log.Warn().Err(err).Msg("Failed to remove resource from index")
	}

	log.Info().
		Str("resource_id", req.ResourceID).
		Msg("Resource removed")

	return pm.successResponse(msg.GetID(), RemoveResourceResponse{
		Success: true,
		Message: "Resource removed successfully",
	})
}

// HandleListResources lists all trusted resources
func (pm *ProfileManager) HandleListResources(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListResourcesRequest
	if msg.Payload != nil {
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			return pm.errorResponse(msg.GetID(), "invalid request payload")
		}
	}

	// Get all resource IDs
	resourceIDs, err := pm.storage.GetIndex(KeyResourceIndex)
	if err != nil {
		return pm.errorResponse(msg.GetID(), "failed to list resources")
	}

	var resources []TrustedResource
	for _, resourceID := range resourceIDs {
		var resource TrustedResource
		resourceKey := KeyProfileResourcePrefix + resourceID
		if err := pm.storage.GetJSON(resourceKey, &resource); err != nil {
			continue
		}

		// Filter by type if specified
		if req.Type != "" && resource.Type != req.Type {
			continue
		}

		resources = append(resources, resource)
	}

	return pm.successResponse(msg.GetID(), ListResourcesResponse{
		Resources: resources,
	})
}

// HandleSignDownload signs a file hash with the service's Ed25519 key
func (pm *ProfileManager) HandleSignDownload(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SignDownloadRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return pm.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Verify resource exists
	var resource TrustedResource
	resourceKey := KeyProfileResourcePrefix + req.ResourceID
	if err := pm.storage.GetJSON(resourceKey, &resource); err != nil {
		return pm.errorResponse(msg.GetID(), "resource not found")
	}

	// Get signing keys
	privateKeyData, err := pm.storage.Get(KeySigningPrivate)
	if err != nil || privateKeyData == nil {
		return pm.errorResponse(msg.GetID(), "signing keys not initialized")
	}
	publicKeyData, err := pm.storage.Get(KeySigningPublic)
	if err != nil || publicKeyData == nil {
		return pm.errorResponse(msg.GetID(), "signing keys not initialized")
	}

	// Parse keys
	if len(privateKeyData) != ed25519.PrivateKeySize {
		return pm.errorResponse(msg.GetID(), "invalid private key")
	}
	privateKey := ed25519.PrivateKey(privateKeyData)

	// Validate file hash format
	if _, err := hex.DecodeString(req.FileHash); err != nil {
		return pm.errorResponse(msg.GetID(), "invalid file hash format")
	}

	// Create message to sign: resource_id + algorithm + file_hash
	messageToSign := fmt.Sprintf("%s:%s:%s", req.ResourceID, req.Algorithm, req.FileHash)
	messageHash := sha256.Sum256([]byte(messageToSign))

	// Sign the message
	signature := ed25519.Sign(privateKey, messageHash[:])

	// Update resource with new signature
	if resource.Download != nil {
		resource.Download.Signatures = append(resource.Download.Signatures, DownloadSignature{
			Algorithm: req.Algorithm,
			Hash:      req.FileHash,
			SignedBy:  pm.ownerSpace,
			Signature: hex.EncodeToString(signature),
		})
		resource.UpdatedAt = time.Now()
		if err := pm.storage.PutJSON(resourceKey, resource); err != nil {
			log.Warn().Err(err).Msg("Failed to update resource with signature")
		}
	}

	log.Info().
		Str("resource_id", req.ResourceID).
		Str("algorithm", req.Algorithm).
		Msg("Download signed")

	return pm.successResponse(msg.GetID(), SignDownloadResponse{
		Success:   true,
		Signature: hex.EncodeToString(signature),
		PublicKey: hex.EncodeToString(publicKeyData),
		Message:   "Download signed successfully",
	})
}

// --- Helper Methods ---

// GetCurrentProfile returns the current service profile
func (pm *ProfileManager) GetCurrentProfile() (*ServiceProfile, error) {
	data, err := pm.storage.Get(KeyProfileCurrent)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}

	var profile ServiceProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

// GetPublicKey returns the service's Ed25519 public key
func (pm *ProfileManager) GetPublicKey() ([]byte, error) {
	return pm.storage.Get(KeySigningPublic)
}

func (pm *ProfileManager) broadcastProfileUpdate(profile *ServiceProfile) {
	// Get all connections
	connIDs, err := pm.storage.GetIndex(KeyConnectionIndex)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get connection index for profile broadcast")
		return
	}

	for _, connID := range connIDs {
		var conn UserConnectionRecord
		connKey := KeyConnectionPrefix + connID
		if err := pm.storage.GetJSON(connKey, &conn); err != nil {
			continue
		}

		// Only notify active connections
		if conn.Status != "active" {
			continue
		}

		// Send profile update
		payload := map[string]interface{}{
			"type":            "profile_update",
			"service_id":      pm.ownerSpace,
			"profile_version": profile.ProfileVersion,
			"service_name":    profile.ServiceName,
		}
		data, _ := json.Marshal(payload)

		msg := &OutgoingMessage{
			Type:    MessageTypeNATSPublish,
			Subject: fmt.Sprintf("OwnerSpace.%s.fromService.%s.profile.update", conn.UserGUID, pm.ownerSpace),
			Payload: data,
		}

		if err := pm.sendFn(msg); err != nil {
			log.Warn().Err(err).Str("user_guid", conn.UserGUID).Msg("Failed to notify user of profile update")
		}
	}
}

func (pm *ProfileManager) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(map[string]interface{}{"success": false, "error": message}),
	}, nil
}

func (pm *ProfileManager) successResponse(requestID string, payload interface{}) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(payload),
	}, nil
}
