package main

import (
	"sync"
)

// VaultState holds all cryptographic state for a vault
// This is the in-memory state that vault-manager maintains for its user
type VaultState struct {
	mu sync.RWMutex

	// ECIES keypair for PIN/password encryption (X25519)
	// Generated once and reused
	eciesPrivateKey []byte
	eciesPublicKey  []byte

	// Credential Encryption Key pair (CEK)
	// Used to encrypt the Protean Credential before sending to app
	cekPair *CEKPair

	// User Transaction Keys (UTK/LTK pairs)
	// UTKs are sent to app, LTKs are kept in vault
	utkPairs []*UTKPair

	// The unsealed credential (decrypted in enclave memory)
	credential *UnsealedCredential

	// KMS-sealed material for DEK derivation
	// This is PCR-bound and used with the user's PIN to derive the DEK
	sealedMaterial []byte

	// Block list for call filtering
	blockList map[string]*BlockListEntry

	// Call history for rate limiting
	callHistory []*CallRecord
}

// CEKPair holds the Credential Encryption Key pair (X25519)
// Used to encrypt credentials before sending to the app
type CEKPair struct {
	PublicKey  []byte // X25519 public key (sent to app)
	PrivateKey []byte // X25519 private key (kept in vault)
	Version    int    // Incremented on rotation
	CreatedAt  int64
}

// UTKPair holds a User Transaction Key (public) and corresponding Ledger Transaction Key (private)
// Used for transport encryption of sensitive operations
type UTKPair struct {
	UTK       []byte // X25519 public key (sent to app)
	LTK       []byte // X25519 private key (kept in vault)
	ID        string // Unique identifier for this key pair
	CreatedAt int64
	UsedAt    int64 // 0 if not yet used
}

// UnsealedCredential holds the decrypted Protean Credential in memory
// SECURITY: This is only held in enclave memory, never persisted to disk
type UnsealedCredential struct {
	IdentityPrivateKey []byte      `json:"identity_private_key"` // Ed25519 private key
	IdentityPublicKey  []byte      `json:"identity_public_key"`  // Ed25519 public key
	VaultMasterSecret  []byte      `json:"vault_master_secret"`  // Master secret for key derivation
	AuthHash           []byte      `json:"auth_hash"`            // Argon2id hash of password
	AuthSalt           []byte      `json:"auth_salt"`            // Salt for Argon2id
	AuthType           string      `json:"auth_type"`            // "password" or "pin"
	CryptoKeys         []CryptoKey `json:"crypto_keys"`          // Additional keys (secp256k1, etc.)
	CreatedAt          int64       `json:"created_at"`
	Version            int         `json:"version"`
}

// CryptoKey represents a cryptographic key stored in the credential
type CryptoKey struct {
	Label      string `json:"label"`
	Type       string `json:"type"` // "secp256k1", "ed25519", etc.
	PrivateKey []byte `json:"private_key"`
	CreatedAt  int64  `json:"created_at"`
}

// NOTE: BlockListEntry and CallRecord are defined in calls.go

// --- Request/Response types ---

// BootstrapRequest is the request from the mobile app
type BootstrapRequest struct {
	BootstrapToken string `json:"bootstrap_token,omitempty"` // Optional validation token
}

// BootstrapResponse is returned after successful bootstrap
type BootstrapResponse struct {
	Status           string   `json:"status"`
	UTKs             []string `json:"utks"`              // Base64-encoded: "id:base64(utk)"
	ECIESPublicKey   string   `json:"ecies_public_key"`  // For encrypting PIN/password
	EnclavePublicKey string   `json:"enclave_public_key"` // Vault's identity public key (if credential exists)
	Capabilities     []string `json:"capabilities"`
	RequiresPassword bool     `json:"requires_password"` // App should prompt for password
	RequiresPIN      bool     `json:"requires_pin"`      // App should prompt for PIN
}

// PasswordSetupRequest is the request from the mobile app for password setup
type PasswordSetupRequest struct {
	UTKIndex         int    `json:"utk_index"`         // Which UTK was used for encryption
	UTKID            string `json:"utk_id"`            // ID of the UTK used
	EncryptedPayload string `json:"encrypted_payload"` // Base64-encoded encrypted payload
}

// PasswordSetupPayload is the decrypted content of EncryptedPayload
type PasswordSetupPayload struct {
	PasswordHash []byte `json:"password_hash"` // Argon2id hash computed by app
	PasswordSalt []byte `json:"password_salt"` // Salt used by app
}

// PasswordSetupResponse is returned after successful password setup
type PasswordSetupResponse struct {
	Status              string   `json:"status"`
	EncryptedCredential string   `json:"encrypted_credential"`  // CEK-encrypted Protean Credential
	IdentityPublicKey   string   `json:"identity_public_key"`   // Ed25519 public key for identity
	NewUTKs             []string `json:"new_utks"`              // Fresh UTKs for future operations
	BackupKey           string   `json:"backup_key,omitempty"`  // Key for backup encryption
}

// PINSetupRequest is the request for initial PIN setup
type PINSetupRequest struct {
	UTKID            string `json:"utk_id"`            // ID of the UTK used
	EncryptedPayload string `json:"encrypted_payload"` // Base64-encoded encrypted PIN
}

// PINSetupPayload is the decrypted PIN payload
type PINSetupPayload struct {
	PIN string `json:"pin"` // The actual PIN
}

// PINSetupResponse is returned after PIN setup
type PINSetupResponse struct {
	Status              string   `json:"status"`
	EncryptedCredential string   `json:"encrypted_credential"` // DEK-encrypted credential
	NewUTKs             []string `json:"new_utks"`
}

// PINUnlockRequest is the request to unlock with PIN
type PINUnlockRequest struct {
	UTKID            string `json:"utk_id"`
	EncryptedPayload string `json:"encrypted_payload"`
}

// PINUnlockResponse is returned after successful unlock
type PINUnlockResponse struct {
	Status              string   `json:"status"`
	EncryptedCredential string   `json:"encrypted_credential"`
	NewUTKs             []string `json:"new_utks"`
}

// PINChangeRequest is the request to change PIN
type PINChangeRequest struct {
	UTKID            string `json:"utk_id"`
	EncryptedPayload string `json:"encrypted_payload"` // Contains old_pin and new_pin
}

// PINChangePayload is the decrypted payload for PIN change
type PINChangePayload struct {
	OldPIN string `json:"old_pin"`
	NewPIN string `json:"new_pin"`
}

// PINChangeResponse is returned after successful PIN change
type PINChangeResponse struct {
	Status              string   `json:"status"`
	EncryptedCredential string   `json:"encrypted_credential"` // Re-encrypted with new DEK
	NewUTKs             []string `json:"new_utks"`
}

// NewVaultState creates a new vault state
func NewVaultState() *VaultState {
	return &VaultState{
		blockList:   make(map[string]*BlockListEntry),
		callHistory: make([]*CallRecord, 0),
	}
}
