// Package main implements the Org Vault Manager for VettID Nitro Enclave.
//
// Org vaults hold organizational secrets (database credentials, API keys,
// certificates) and proxy operations using them. Each operation is attributed
// to a specific operator via per-operator cryptographic connections.
//
// Key security principles:
// - Credentials never leave the enclave in plaintext
// - Each operator has their own X25519 connection (identity = connection)
// - All operations produce structured HIPAA-compliant audit events
// - Access policies enforce role-based, rate-limited credential usage
package main

import (
	"encoding/json"
	"time"
)

// --- Credential Types ---

// StoredCredential holds metadata about a credential stored in the org vault.
// The actual secret value is stored separately and only decrypted in-memory
// when needed for a proxy operation.
type StoredCredential struct {
	CredentialID   string            `json:"credential_id"`
	CredentialType string            `json:"credential_type"` // "database", "api_key", "certificate", "signing_key"
	Label          string            `json:"label"`
	Metadata       map[string]string `json:"metadata"`     // Non-sensitive: host, port, db name
	AccessPolicy   AccessPolicy      `json:"access_policy"`
	CreatedAt      time.Time         `json:"created_at"`
	RotatedAt      time.Time         `json:"rotated_at"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty"`
}

// AccessPolicy defines who can use a credential and how.
type AccessPolicy struct {
	AllowedRoles      []string `json:"allowed_roles,omitempty"`      // ["billing", "physician", "admin"]
	AllowedOperations []string `json:"allowed_operations,omitempty"` // ["query", "sign", "retrieve"]
	RequirePurpose    bool     `json:"require_purpose"`
	MaxQueryRate      int      `json:"max_query_rate,omitempty"` // Per operator per hour, 0 = unlimited
}

// DatabaseCredential holds the secret values for a database connection.
// SECURITY: Only exists in-memory during proxy operations, then zeroed.
type DatabaseCredential struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
	SSLMode  string `json:"ssl_mode"`
}

// APIKeyCredential holds the secret values for an API key.
type APIKeyCredential struct {
	Key      string            `json:"key"`
	Secret   string            `json:"secret,omitempty"`
	Endpoint string            `json:"endpoint,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

// --- Operator Connection Types ---

// OperatorConnection stores the connection state for a connected operator.
// Each operator has their own X25519 keypair — the connection IS the identity.
type OperatorConnection struct {
	ConnectionID   string    `json:"connection_id"`
	OperatorEmail  string    `json:"operator_email"`
	OperatorRole   string    `json:"operator_role"`
	Status         string    `json:"status"` // "active", "suspended", "revoked"
	LocalPrivateKey []byte   `json:"local_private_key"`
	LocalPublicKey  []byte   `json:"local_public_key"`
	PeerPublicKey   []byte   `json:"peer_public_key"`
	SharedSecret    []byte   `json:"-"` // SECURITY: Never serialized
	ConnectedAt    time.Time `json:"connected_at"`
	LastActiveAt   time.Time `json:"last_active_at"`
	QueryCount     int64     `json:"query_count"`
}

// OperatorInfo is the public view of an operator connection (no secrets).
type OperatorInfo struct {
	ConnectionID  string    `json:"connection_id"`
	OperatorEmail string    `json:"operator_email"`
	OperatorRole  string    `json:"operator_role"`
	Status        string    `json:"status"`
	ConnectedAt   time.Time `json:"connected_at"`
	LastActiveAt  time.Time `json:"last_active_at"`
	QueryCount    int64     `json:"query_count"`
}

// ToInfo converts an OperatorConnection to its public view.
func (oc *OperatorConnection) ToInfo() OperatorInfo {
	return OperatorInfo{
		ConnectionID:  oc.ConnectionID,
		OperatorEmail: oc.OperatorEmail,
		OperatorRole:  oc.OperatorRole,
		Status:        oc.Status,
		ConnectedAt:   oc.ConnectedAt,
		LastActiveAt:  oc.LastActiveAt,
		QueryCount:    oc.QueryCount,
	}
}

// --- Proxy Types ---

// ProxyQueryRequest is the request payload for a credential proxy operation.
type ProxyQueryRequest struct {
	CredentialID string        `json:"credential_id"`
	Query        string        `json:"query"`
	QueryParams  []interface{} `json:"query_params,omitempty"`
	Purpose      string        `json:"purpose"`       // "billing_inquiry", "treatment_lookup"
	ResourceType string        `json:"resource_type"` // "patient_record", "account"
	ResourceID   string        `json:"resource_id"`   // "MRN-12345"
}

// ProxyQueryResponse is the response from a credential proxy operation.
type ProxyQueryResponse struct {
	Success    bool            `json:"success"`
	Results    json.RawMessage `json:"results,omitempty"`
	Columns    []string        `json:"columns,omitempty"`
	RowCount   int             `json:"row_count"`
	DurationMs int64           `json:"duration_ms"`
	AuditID    string          `json:"audit_id"`
	Error      string          `json:"error,omitempty"`
}

// --- Audit Types ---

// OrgAuditEvent is a structured audit event for HIPAA-compliant logging.
type OrgAuditEvent struct {
	EventID        string `json:"event_id"`
	Timestamp      int64  `json:"timestamp"`          // Unix milliseconds
	OrgVaultID     string `json:"org_vault_id"`
	ConnectionID   string `json:"connection_id"`
	OperatorEmail  string `json:"operator_email"`
	OperatorRole   string `json:"operator_role"`
	Action         string `json:"action"`              // "credential_proxy_query", "credential_store", "operator_invited", "operator_revoked"
	CredentialID   string `json:"credential_id,omitempty"`
	CredentialType string `json:"credential_type,omitempty"`
	ResourceType   string `json:"resource_type,omitempty"`
	ResourceID     string `json:"resource_id,omitempty"`
	Purpose        string `json:"purpose,omitempty"`
	Outcome        string `json:"outcome"`             // "success", "denied_policy", "denied_rate_limit", "error"
	DurationMs     int64  `json:"duration_ms,omitempty"`
	RowCount       int    `json:"row_count,omitempty"`
	QueryHash      string `json:"query_hash,omitempty"` // SHA-256 (never the query itself)
}

// --- Contract Types ---

// OrgVaultContract defines the access contract for the org vault.
// This is simpler than the service vault contract — it controls
// which roles can access which credentials.
type OrgVaultContract struct {
	ContractID  string          `json:"contract_id"`
	OrgVaultID  string          `json:"org_vault_id"`
	Version     int             `json:"version"`
	Roles       []RoleDefinition `json:"roles"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// RoleDefinition defines what a role can do within the org vault.
type RoleDefinition struct {
	Role               string   `json:"role"`                // "billing", "physician", "admin"
	AllowedCredentials []string `json:"allowed_credentials"` // Credential IDs or "*" for all
	AllowedOperations  []string `json:"allowed_operations"`  // ["query", "sign"]
	RequirePurpose     bool     `json:"require_purpose"`
	MaxQueriesPerHour  int      `json:"max_queries_per_hour,omitempty"`
}

// --- Storage Keys ---

const (
	// Credentials
	KeyCredentialPrefix = "credentials/"     // credentials/{credential_id}
	KeyCredentialIndex  = "credentials-index" // List of credential IDs
	KeyCredentialSecret = "credential-secrets/" // credential-secrets/{credential_id} (actual secret values)

	// Operator connections
	KeyOperatorPrefix = "operators/"      // operators/{connection_id}
	KeyOperatorIndex  = "operators-index" // List of connection IDs

	// Audit
	KeyAuditPrefix = "audit/"       // audit/{event_id}
	KeyAuditIndex  = "audit-index"  // List of recent audit event IDs

	// Contract
	KeyContractCurrent = "contract/current" // Current OrgVaultContract

	// Rate limiting
	KeyRateLimitPrefix = "rate-limits/" // rate-limits/{connection_id} (hourly counters)
)
