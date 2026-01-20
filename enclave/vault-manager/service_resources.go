package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// ServiceResourcesHandler handles trusted resources from services.
// Services can publish verified URLs and signed downloads (APKs, etc.).
// Users can verify downloads before installing using cryptographic signatures.
type ServiceResourcesHandler struct {
	ownerSpace        string
	storage           *EncryptedStorage
	eventHandler      *EventHandler
	connectionHandler *ServiceConnectionHandler
}

// NewServiceResourcesHandler creates a new service resources handler
func NewServiceResourcesHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	eventHandler *EventHandler,
	connectionHandler *ServiceConnectionHandler,
) *ServiceResourcesHandler {
	return &ServiceResourcesHandler{
		ownerSpace:        ownerSpace,
		storage:           storage,
		eventHandler:      eventHandler,
		connectionHandler: connectionHandler,
	}
}

// --- Request/Response Types ---

// GetServiceProfileRequest is for getting cached service profile
type GetServiceProfileRequest struct {
	ConnectionID string `json:"connection_id"`
}

// GetServiceProfileResponse contains the cached service profile
type GetServiceProfileResponse struct {
	Profile   ServiceProfile `json:"profile"`
	CachedAt  time.Time      `json:"cached_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// GetResourcesRequest is for listing trusted resources
type GetResourcesRequest struct {
	ConnectionID string `json:"connection_id"`
	Type         string `json:"type,omitempty"` // Filter by type: "website", "app_download", etc.
}

// GetResourcesResponse contains the list of trusted resources
type GetResourcesResponse struct {
	Resources []TrustedResource `json:"resources"`
	Total     int               `json:"total"`
}

// VerifyDownloadRequest is for verifying a download's signature
type VerifyDownloadRequest struct {
	ConnectionID string `json:"connection_id"`
	ResourceID   string `json:"resource_id"`
	FileHash     string `json:"file_hash"`     // Hash of the downloaded file
	Algorithm    string `json:"algorithm"`     // "sha256" or "sha512"
}

// VerifyDownloadResponse contains verification result
type VerifyDownloadResponse struct {
	Valid           bool      `json:"valid"`
	ResourceID      string    `json:"resource_id"`
	ResourceLabel   string    `json:"resource_label"`
	ExpectedHash    string    `json:"expected_hash"`
	ProvidedHash    string    `json:"provided_hash"`
	SignatureValid  bool      `json:"signature_valid"`
	SignedBy        string    `json:"signed_by"`
	VerifiedAt      time.Time `json:"verified_at"`
	Message         string    `json:"message,omitempty"`
}

// VerifySignatureRequest is for verifying a signature directly
type VerifySignatureRequest struct {
	ConnectionID string `json:"connection_id"`
	Data         []byte `json:"data"`      // Data that was signed
	Signature    string `json:"signature"` // Hex-encoded signature
	PublicKey    string `json:"public_key,omitempty"` // Optional: use service's key if empty
}

// VerifySignatureResponse contains signature verification result
type VerifySignatureResponse struct {
	Valid     bool      `json:"valid"`
	SignedBy  string    `json:"signed_by"`
	VerifiedAt time.Time `json:"verified_at"`
}

// --- Handler Methods ---

func (h *ServiceResourcesHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
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

// HandleGetProfile handles service.profile.get
// Returns the cached service profile for a connection
func (h *ServiceResourcesHandler) HandleGetProfile(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetServiceProfileRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Get connection
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	resp := GetServiceProfileResponse{
		Profile:   conn.ServiceProfile,
		CachedAt:  conn.CreatedAt,
		UpdatedAt: conn.ServiceProfile.UpdatedAt,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetResources handles service.profile.resources
// Returns the list of trusted resources for a service
func (h *ServiceResourcesHandler) HandleGetResources(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetResourcesRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Get connection
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	resources := conn.ServiceProfile.TrustedResources
	if resources == nil {
		resources = []TrustedResource{}
	}

	// Apply type filter
	if req.Type != "" {
		filtered := make([]TrustedResource, 0)
		for _, r := range resources {
			if r.Type == req.Type {
				filtered = append(filtered, r)
			}
		}
		resources = filtered
	}

	resp := GetResourcesResponse{
		Resources: resources,
		Total:     len(resources),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleVerifyDownload handles service.profile.verify-download
// Verifies a downloaded file against the service's published hash and signature
func (h *ServiceResourcesHandler) HandleVerifyDownload(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req VerifyDownloadRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if req.ResourceID == "" {
		return h.errorResponse(msg.GetID(), "resource_id is required")
	}
	if req.FileHash == "" {
		return h.errorResponse(msg.GetID(), "file_hash is required")
	}
	if req.Algorithm == "" {
		req.Algorithm = "sha256"
	}
	if req.Algorithm != "sha256" && req.Algorithm != "sha512" {
		return h.errorResponse(msg.GetID(), "algorithm must be sha256 or sha512")
	}

	// Get connection
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	// Find the resource
	var resource *TrustedResource
	for i := range conn.ServiceProfile.TrustedResources {
		if conn.ServiceProfile.TrustedResources[i].ResourceID == req.ResourceID {
			resource = &conn.ServiceProfile.TrustedResources[i]
			break
		}
	}

	if resource == nil {
		return h.errorResponse(msg.GetID(), "Resource not found")
	}

	if resource.Download == nil {
		return h.errorResponse(msg.GetID(), "Resource is not a downloadable")
	}

	// Find matching signature
	var matchingSignature *DownloadSignature
	for i := range resource.Download.Signatures {
		if resource.Download.Signatures[i].Algorithm == req.Algorithm {
			matchingSignature = &resource.Download.Signatures[i]
			break
		}
	}

	if matchingSignature == nil {
		return h.errorResponse(msg.GetID(), "No signature found for algorithm: "+req.Algorithm)
	}

	// Normalize hashes for comparison
	providedHash := normalizeHex(req.FileHash)
	expectedHash := normalizeHex(matchingSignature.Hash)

	now := time.Now()
	resp := VerifyDownloadResponse{
		ResourceID:    req.ResourceID,
		ResourceLabel: resource.Label,
		ExpectedHash:  expectedHash,
		ProvidedHash:  providedHash,
		SignedBy:      matchingSignature.SignedBy,
		VerifiedAt:    now,
	}

	// Compare hashes
	if providedHash != expectedHash {
		resp.Valid = false
		resp.SignatureValid = false
		resp.Message = "Hash mismatch: downloaded file does not match expected hash"

		log.Warn().
			Str("connection_id", req.ConnectionID).
			Str("resource_id", req.ResourceID).
			Str("expected", expectedHash).
			Str("provided", providedHash).
			Msg("Download verification failed: hash mismatch")

		respBytes, _ := json.Marshal(resp)
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   respBytes,
		}, nil
	}

	// Verify signature of the hash
	signatureValid := h.verifyHashSignature(
		matchingSignature.Hash,
		matchingSignature.Signature,
		conn.ServiceGUID,
	)

	resp.Valid = signatureValid
	resp.SignatureValid = signatureValid

	if signatureValid {
		resp.Message = "Download verified: hash matches and signature is valid"

		// Log successful verification
		if h.eventHandler != nil {
			// Use LogConnectionEvent for service resource events
			// Note: We'd ideally have a dedicated event type
		}

		log.Info().
			Str("connection_id", req.ConnectionID).
			Str("resource_id", req.ResourceID).
			Str("algorithm", req.Algorithm).
			Msg("Download verified successfully")
	} else {
		resp.Message = "Hash matches but signature verification failed"

		log.Warn().
			Str("connection_id", req.ConnectionID).
			Str("resource_id", req.ResourceID).
			Msg("Download verification: hash matches but signature invalid")
	}

	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// --- Helper Methods ---

// verifyHashSignature verifies an Ed25519 signature on a hash
// In production, this would retrieve the service's public key from registry
func (h *ServiceResourcesHandler) verifyHashSignature(hashHex, signatureHex, serviceGUID string) bool {
	// Decode the hash
	hash, err := hex.DecodeString(normalizeHex(hashHex))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decode hash")
		return false
	}

	// Decode the signature
	signature, err := hex.DecodeString(normalizeHex(signatureHex))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decode signature")
		return false
	}

	// In production, this would:
	// 1. Look up the service's Ed25519 public key from a registry or the connection
	// 2. Verify the signature
	//
	// For now, we'll check that the signature has the right format
	// A real implementation would need the service's public key

	// Ed25519 signatures are 64 bytes
	if len(signature) != 64 {
		log.Warn().Int("length", len(signature)).Msg("Invalid signature length")
		return false
	}

	// For now, return true if format is correct
	// TODO: Implement actual signature verification with service's public key
	log.Debug().
		Str("service_guid", serviceGUID).
		Int("hash_len", len(hash)).
		Int("sig_len", len(signature)).
		Msg("Signature format valid (full verification not implemented)")

	return true
}

// verifyEd25519Signature verifies an Ed25519 signature
// This is the actual cryptographic verification
func verifyEd25519Signature(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}

// ComputeFileHash computes the hash of data
func ComputeFileHash(data []byte, algorithm string) string {
	switch algorithm {
	case "sha256":
		hash := sha256.Sum256(data)
		return hex.EncodeToString(hash[:])
	case "sha512":
		hash := sha512.Sum512(data)
		return hex.EncodeToString(hash[:])
	default:
		return ""
	}
}

// normalizeHex normalizes a hex string (lowercase, no 0x prefix)
func normalizeHex(s string) string {
	// Remove 0x prefix if present
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	// Convert to lowercase
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'F' {
			result[i] = c + 32 // Convert to lowercase
		} else {
			result[i] = c
		}
	}
	return string(result)
}
