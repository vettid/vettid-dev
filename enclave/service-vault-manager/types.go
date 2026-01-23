// Package main implements the Service Vault Manager for VettID.
// Service vaults handle the service side of B2C connections.
// Key security principle: Services cannot cache user profile data.
package main

import (
	"time"
)

// --- User Connection Types ---

// UserConnectionRecord stores connection state for a connected user.
// SECURITY: This intentionally does NOT include any user profile data.
// Services must request data on-demand via HandleRequestData.
type UserConnectionRecord struct {
	ConnectionID    string    `json:"connection_id"`
	UserGUID        string    `json:"user_guid"` // User's GUID only (no profile!)
	LocalPrivateKey []byte    `json:"local_private_key"` // X25519 for E2E encryption
	LocalPublicKey  []byte    `json:"local_public_key"`
	PeerPublicKey   []byte    `json:"peer_public_key"`  // User's public key
	SharedSecret    []byte    `json:"shared_secret"`    // ECDH derived secret
	ContractVersion int       `json:"contract_version"` // Which contract version they accepted
	Status          string    `json:"status"`           // "pending", "active", "suspended", "revoked"
	ConnectedAt     time.Time `json:"connected_at"`
	LastActivityAt  time.Time `json:"last_activity_at"`
	// NO UserProfile field - this is intentional!
}

// UserConnectionInfo is the public view of a connection (no secrets)
type UserConnectionInfo struct {
	ConnectionID    string    `json:"connection_id"`
	UserGUID        string    `json:"user_guid"`
	ContractVersion int       `json:"contract_version"`
	Status          string    `json:"status"`
	ConnectedAt     time.Time `json:"connected_at"`
	LastActivityAt  time.Time `json:"last_activity_at"`
}

// --- Contract Types ---

// ServiceDataContract defines what data and capabilities the service requests.
// This is the master contract that users accept when connecting.
type ServiceDataContract struct {
	ContractID      string      `json:"contract_id"`
	ServiceGUID     string      `json:"service_guid"`
	Version         int         `json:"version"`
	Title           string      `json:"title"`
	Description     string      `json:"description"`
	TermsURL        string      `json:"terms_url,omitempty"`
	PrivacyURL      string      `json:"privacy_url,omitempty"`
	RequiredFields  []FieldSpec `json:"required_fields"`
	OptionalFields  []FieldSpec `json:"optional_fields"`
	OnDemandFields  []string    `json:"on_demand_fields"`  // Fields service can request anytime
	ConsentFields   []string    `json:"consent_fields"`    // Fields requiring explicit user consent
	CanStoreData    bool        `json:"can_store_data"`
	StorageCategories []string  `json:"storage_categories,omitempty"`
	CanSendMessages    bool     `json:"can_send_messages"`
	CanRequestAuth     bool     `json:"can_request_auth"`
	CanRequestPayment  bool     `json:"can_request_payment"`
	CanRequestVoiceCall bool    `json:"can_request_voice_call"`
	CanRequestVideoCall bool    `json:"can_request_video_call"`
	MaxRequestsPerHour int      `json:"max_requests_per_hour,omitempty"`
	MaxNotificationsPerHour int `json:"max_notifications_per_hour,omitempty"`
	MaxStorageMB       int      `json:"max_storage_mb,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// FieldSpec describes a field in the contract
type FieldSpec struct {
	Field       string `json:"field"`
	Purpose     string `json:"purpose"`
	Required    bool   `json:"required"`
	RetentionDays int  `json:"retention_days,omitempty"`
}

// ContractVersion stores historical contract versions
type ContractVersion struct {
	Version     int                 `json:"version"`
	Contract    ServiceDataContract `json:"contract"`
	PublishedAt time.Time           `json:"published_at"`
	SupersededAt *time.Time         `json:"superseded_at,omitempty"`
}

// --- Service Profile Types ---

// ServiceProfile represents the service's public profile
type ServiceProfile struct {
	ServiceGUID        string            `json:"service_guid"`
	ServiceName        string            `json:"service_name"`
	ServiceDescription string            `json:"service_description"`
	ServiceLogoURL     string            `json:"service_logo_url,omitempty"`
	ServiceCategory    string            `json:"service_category"` // "retail", "healthcare", "finance"
	Organization       OrganizationInfo  `json:"organization"`
	ContactInfo        ServiceContactInfo `json:"contact_info"`
	CurrentContract    ServiceDataContract `json:"current_contract"`
	ProfileVersion     int               `json:"profile_version"`
	UpdatedAt          time.Time         `json:"updated_at"`
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

// ServiceContactInfo contains service contact methods
type ServiceContactInfo struct {
	SupportURL   string `json:"support_url,omitempty"`
	SupportEmail string `json:"support_email,omitempty"`
	SupportPhone string `json:"support_phone,omitempty"`
}

// TrustedResource represents a trusted URL or download
type TrustedResource struct {
	ResourceID  string       `json:"resource_id"`
	Type        string       `json:"type"` // "website", "app_download", "document", "api"
	Label       string       `json:"label"`
	Description string       `json:"description,omitempty"`
	URL         string       `json:"url"`
	Download    *DownloadInfo `json:"download,omitempty"`
	AddedAt     time.Time    `json:"added_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// DownloadInfo contains information for downloadable resources
type DownloadInfo struct {
	Platform     string              `json:"platform"` // "android", "ios", "windows", etc.
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

// --- Request Types ---

// OutboundRequest tracks requests sent to users
type OutboundRequest struct {
	RequestID     string          `json:"request_id"`
	ConnectionID  string          `json:"connection_id"`
	UserGUID      string          `json:"user_guid"`
	RequestType   string          `json:"request_type"` // "data", "auth", "consent", "payment"
	Fields        []string        `json:"fields,omitempty"`
	Purpose       string          `json:"purpose,omitempty"`
	Amount        *PaymentAmount  `json:"amount,omitempty"`
	Status        string          `json:"status"` // "pending", "approved", "denied", "expired"
	CreatedAt     time.Time       `json:"created_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
	RespondedAt   *time.Time      `json:"responded_at,omitempty"`
	ResponseData  []byte          `json:"response_data,omitempty"` // Encrypted response
}

// PaymentAmount for payment requests
type PaymentAmount struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}

// --- Storage Keys ---

// Storage key patterns for service vault
const (
	// Connections
	KeyConnectionPrefix      = "connections/"        // connections/{connection_id}
	KeyConnectionIndex       = "connections-index"   // List of all connection IDs

	// Contracts
	KeyContractCurrent       = "contracts/current"   // Current contract
	KeyContractHistoryPrefix = "contracts/history/"  // contracts/history/{version}

	// Profile
	KeyProfileCurrent        = "profile/current"     // ServiceProfile
	KeyProfileResourcePrefix = "profile/resources/"  // profile/resources/{resource_id}
	KeyResourceIndex         = "profile/resources-index" // List of resource IDs

	// Requests
	KeyRequestPrefix         = "requests/"           // requests/{request_id}
	KeyRequestIndex          = "requests-index"      // List of request IDs

	// Signing keys
	KeySigningPrivate        = "keys/signing/private" // Ed25519 private key
	KeySigningPublic         = "keys/signing/public"  // Ed25519 public key
)
