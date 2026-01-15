package main

import (
	"encoding/json"
	"sync"
)

// SensitiveBytes is a []byte wrapper that can be zeroed after use
// SECURITY: Use this type for PIN, password, and other sensitive data
// to ensure the underlying memory can be cleared
type SensitiveBytes []byte

// UnmarshalJSON implements json.Unmarshaler for SensitiveBytes
// Handles both string and base64-encoded values
func (s *SensitiveBytes) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as a string first (most common case for PIN)
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = SensitiveBytes(str)
	return nil
}

// MarshalJSON implements json.Marshaler for SensitiveBytes
func (s SensitiveBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

// Zero overwrites the underlying bytes with zeros
// SECURITY: Call this via defer immediately after decrypting sensitive data
func (s SensitiveBytes) Zero() {
	for i := range s {
		s[i] = 0
	}
}

// String returns the string representation (use sparingly)
func (s SensitiveBytes) String() string {
	return string(s)
}

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
	// SECURITY: Attestation-bound key exchange fields
	SessionID      string `json:"session_id,omitempty"`       // Enrollment session ID
	AppPublicKey   string `json:"app_public_key,omitempty"`   // App's X25519 public key (base64)
	BindingToken   string `json:"binding_token,omitempty"`    // HMAC token from attestation verification
	PCRHash        string `json:"pcr_hash,omitempty"`         // PCR hash from attestation (first 24 hex chars)
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
	// SECURITY: Attestation binding proof
	BindingVerified bool `json:"binding_verified,omitempty"` // True if attestation binding was verified
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
// SECURITY: Uses SensitiveBytes so PIN can be zeroed after use
type PINSetupPayload struct {
	PIN SensitiveBytes `json:"pin"` // The actual PIN (zeroable)
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
// SECURITY: Uses SensitiveBytes so PINs can be zeroed after use
type PINChangePayload struct {
	OldPIN SensitiveBytes `json:"old_pin"` // Current PIN (zeroable)
	NewPIN SensitiveBytes `json:"new_pin"` // New PIN (zeroable)
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

// SecureErase zeros all sensitive data in the vault state
// SECURITY: This must be called before process exit to prevent credential leakage
func (vs *VaultState) SecureErase() {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	// Zero ECIES keys
	zeroBytes(vs.eciesPrivateKey)
	zeroBytes(vs.eciesPublicKey)
	vs.eciesPrivateKey = nil
	vs.eciesPublicKey = nil

	// Zero CEK pair
	if vs.cekPair != nil {
		zeroBytes(vs.cekPair.PrivateKey)
		zeroBytes(vs.cekPair.PublicKey)
		vs.cekPair = nil
	}

	// Zero all UTK pairs
	for _, utk := range vs.utkPairs {
		if utk != nil {
			zeroBytes(utk.UTK)
			zeroBytes(utk.LTK)
		}
	}
	vs.utkPairs = nil

	// Zero unsealed credential
	if vs.credential != nil {
		vs.credential.SecureErase()
		vs.credential = nil
	}

	// Zero sealed material
	zeroBytes(vs.sealedMaterial)
	vs.sealedMaterial = nil

	// Clear block list (no sensitive data)
	vs.blockList = nil
	vs.callHistory = nil
}

// SecureErase zeros all sensitive data in the credential
// SECURITY: This must be called before credential is released
func (uc *UnsealedCredential) SecureErase() {
	if uc == nil {
		return
	}

	zeroBytes(uc.IdentityPrivateKey)
	zeroBytes(uc.IdentityPublicKey)
	zeroBytes(uc.VaultMasterSecret)
	zeroBytes(uc.AuthHash)
	zeroBytes(uc.AuthSalt)

	// Zero all crypto keys
	for i := range uc.CryptoKeys {
		zeroBytes(uc.CryptoKeys[i].PrivateKey)
	}
	uc.CryptoKeys = nil

	uc.IdentityPrivateKey = nil
	uc.IdentityPublicKey = nil
	uc.VaultMasterSecret = nil
	uc.AuthHash = nil
	uc.AuthSalt = nil
}

// SecureErase zeros the CEK pair
func (cp *CEKPair) SecureErase() {
	if cp == nil {
		return
	}
	zeroBytes(cp.PrivateKey)
	zeroBytes(cp.PublicKey)
	cp.PrivateKey = nil
	cp.PublicKey = nil
}

// SecureErase zeros the UTK pair
func (up *UTKPair) SecureErase() {
	if up == nil {
		return
	}
	zeroBytes(up.UTK)
	zeroBytes(up.LTK)
	up.UTK = nil
	up.LTK = nil
}
