package main

import (
	"encoding/json"
	"fmt"
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

	// DEK (Data Encryption Key) - temporarily stored between PIN setup and credential creation
	// SECURITY: This is cleared after credential creation or on timeout
	dek []byte

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

	// PasswordHash is the credential password in PHC string format:
	// $argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
	// This self-describing format includes all parameters for verification.
	// Used for credential operations (signing, key derivation, etc.)
	PasswordHash string `json:"password_hash,omitempty"`

	// AuthHash and AuthSalt are used for PIN-based vault unlock operations.
	// These are set during PIN setup and used for PIN verification.
	// NOTE: For credential password, use PasswordHash (PHC format) instead.
	AuthHash []byte `json:"auth_hash,omitempty"` // Argon2id hash of PIN
	AuthSalt []byte `json:"auth_salt,omitempty"` // Salt for PIN Argon2id

	AuthType   string      `json:"auth_type"` // "password" or "pin"
	CryptoKeys []CryptoKey `json:"crypto_keys"` // Additional keys (secp256k1, etc.)
	CreatedAt  int64       `json:"created_at"`
	Version    int         `json:"version"`
}

// CryptoKey represents a cryptographic key stored in the credential (V1 format)
type CryptoKey struct {
	Label      string `json:"label"`
	Type       string `json:"type"` // "secp256k1", "ed25519", etc.
	PrivateKey []byte `json:"private_key"`
	CreatedAt  int64  `json:"created_at"`
}

// --- Protean Credential Format V2 ---
// This is the new structured format with grouped fields and metadata

// ProteanCredentialV2 is the new credential format with grouped fields
// See docs/specs/credential-format.md for specification
type ProteanCredentialV2 struct {
	FormatVersion int `json:"format_version"` // Should be 2

	Identity CredentialIdentity `json:"identity"`

	MasterSecret []byte `json:"master_secret"`

	Auth CredentialAuth `json:"auth"`

	CryptoMetadata CredentialCryptoMetadata `json:"crypto_metadata"`

	Binding *CredentialBinding `json:"binding,omitempty"`

	CryptoKeys []CryptoKeyV2 `json:"crypto_keys"`

	Secrets []CredentialSecretEntry `json:"secrets,omitempty"`

	Timestamps CredentialTimestamps `json:"timestamps"`

	Version int `json:"version"` // Instance version, increments on changes
}

// CredentialIdentity holds the Ed25519 identity keypair
type CredentialIdentity struct {
	PrivateKey []byte `json:"private_key"` // Ed25519 seed (32 bytes)
	PublicKey  []byte `json:"public_key"`  // Ed25519 public key (32 bytes)
}

// CredentialAuth holds authentication information
type CredentialAuth struct {
	Type string `json:"type"` // "password" or "pin"
	Hash string `json:"hash"` // PHC format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
}

// CredentialCryptoMetadata enables algorithm agility
type CredentialCryptoMetadata struct {
	Cipher string `json:"cipher"` // e.g., "xchacha20-poly1305"
	Kex    string `json:"kex"`    // Key exchange: "x25519"
	Kdf    string `json:"kdf"`    // Key derivation: "hkdf-sha256"
	Domain string `json:"domain"` // HKDF domain: "vettid-cek-v1"
}

// CredentialBinding ties the credential to a specific vault
type CredentialBinding struct {
	VaultID string `json:"vault_id"` // Owner space / vault ID
	BoundAt int64  `json:"bound_at"` // Unix timestamp
}

// CredentialTimestamps tracks credential lifecycle
type CredentialTimestamps struct {
	CreatedAt     int64 `json:"created_at"`
	LastModified  int64 `json:"last_modified"`
	AuthChangedAt int64 `json:"auth_changed_at"`
}

// CryptoKeyV2 represents a cryptographic key with enhanced metadata
type CryptoKeyV2 struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	Type           string `json:"type"` // "secp256k1", "ed25519", etc.
	PrivateKey     []byte `json:"private_key"`
	PublicKey      []byte `json:"public_key"`            // Stored for efficiency
	DerivationPath string `json:"derivation_path,omitempty"` // BIP32 path for HD keys
	CreatedAt      int64  `json:"created_at"`
}

// CredentialSecretEntry is a critical secret embedded in the Protean Credential.
// The value is stored as plaintext within the credential because the credential
// blob itself is already encrypted with CEK. No double-encryption needed.
type CredentialSecretEntry struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Category    SecretCategory `json:"category"`
	Description string         `json:"description,omitempty"`
	Value       []byte         `json:"value"`
	Owner       string         `json:"owner"`
	CreatedAt   int64          `json:"created_at"`
	UpdatedAt   int64          `json:"updated_at"`
}

// SecureErase zeros the secret value in a CredentialSecretEntry
func (e *CredentialSecretEntry) SecureErase() {
	if e == nil {
		return
	}
	zeroBytes(e.Value)
	e.Value = nil
}

// DefaultCryptoMetadata returns the current default cryptographic parameters
func DefaultCryptoMetadata() CredentialCryptoMetadata {
	return CredentialCryptoMetadata{
		Cipher: "xchacha20-poly1305",
		Kex:    "x25519",
		Kdf:    "hkdf-sha256",
		Domain: DomainCEK,
	}
}

// MigrateV1ToV2 converts a V1 UnsealedCredential to V2 format
func MigrateV1ToV2(v1 *UnsealedCredential, vaultID string) *ProteanCredentialV2 {
	now := currentTimestamp()

	// Determine auth hash - prefer PHC format PasswordHash, fall back to constructing from AuthHash/AuthSalt
	authHash := v1.PasswordHash
	if authHash == "" && len(v1.AuthHash) > 0 && len(v1.AuthSalt) > 0 {
		// Legacy format - would need to reconstruct PHC string
		// For now, this signals migration is needed at the application level
		authHash = ""
	}

	// Migrate crypto keys
	cryptoKeys := make([]CryptoKeyV2, len(v1.CryptoKeys))
	for i, k := range v1.CryptoKeys {
		cryptoKeys[i] = CryptoKeyV2{
			ID:         fmt.Sprintf("key-%d", i),
			Label:      k.Label,
			Type:       k.Type,
			PrivateKey: k.PrivateKey,
			PublicKey:  nil, // Will need to be derived from private key
			CreatedAt:  k.CreatedAt,
		}
	}

	return &ProteanCredentialV2{
		FormatVersion: 2,
		Identity: CredentialIdentity{
			PrivateKey: v1.IdentityPrivateKey,
			PublicKey:  v1.IdentityPublicKey,
		},
		MasterSecret: v1.VaultMasterSecret,
		Auth: CredentialAuth{
			Type: v1.AuthType,
			Hash: authHash,
		},
		CryptoMetadata: DefaultCryptoMetadata(),
		Binding: &CredentialBinding{
			VaultID: vaultID,
			BoundAt: now,
		},
		CryptoKeys: cryptoKeys,
		Timestamps: CredentialTimestamps{
			CreatedAt:     v1.CreatedAt,
			LastModified:  now,
			AuthChangedAt: v1.CreatedAt,
		},
		Version: v1.Version,
	}
}

// ToV1 converts a V2 credential back to V1 format for backward compatibility
func (v2 *ProteanCredentialV2) ToV1() *UnsealedCredential {
	// Migrate crypto keys back
	cryptoKeys := make([]CryptoKey, len(v2.CryptoKeys))
	for i, k := range v2.CryptoKeys {
		cryptoKeys[i] = CryptoKey{
			Label:      k.Label,
			Type:       k.Type,
			PrivateKey: k.PrivateKey,
			CreatedAt:  k.CreatedAt,
		}
	}

	return &UnsealedCredential{
		IdentityPrivateKey: v2.Identity.PrivateKey,
		IdentityPublicKey:  v2.Identity.PublicKey,
		VaultMasterSecret:  v2.MasterSecret,
		PasswordHash:       v2.Auth.Hash,
		AuthType:           v2.Auth.Type,
		CryptoKeys:         cryptoKeys,
		CreatedAt:          v2.Timestamps.CreatedAt,
		Version:            v2.Version,
	}
}

// SecureErase zeros all sensitive data in the V2 credential
func (v2 *ProteanCredentialV2) SecureErase() {
	if v2 == nil {
		return
	}

	zeroBytes(v2.Identity.PrivateKey)
	zeroBytes(v2.Identity.PublicKey)
	zeroBytes(v2.MasterSecret)

	v2.Auth.Hash = ""

	for i := range v2.CryptoKeys {
		zeroBytes(v2.CryptoKeys[i].PrivateKey)
		zeroBytes(v2.CryptoKeys[i].PublicKey)
	}
	v2.CryptoKeys = nil

	for i := range v2.Secrets {
		v2.Secrets[i].SecureErase()
	}
	v2.Secrets = nil

	v2.Identity.PrivateKey = nil
	v2.Identity.PublicKey = nil
	v2.MasterSecret = nil
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
	PIN     SensitiveBytes       `json:"pin"`               // The actual PIN (zeroable)
	Profile *RegistrationProfile `json:"profile,omitempty"` // Optional registration profile
}

// RegistrationProfile contains the user's registration information
// This is collected during member registration and sent to the vault during enrollment
type RegistrationProfile struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}

// PINSetupResponse is returned after PIN setup
// Returns vault_ready + UTKs for credential creation (Phase 2)
// Does NOT return the credential - that comes from credential.create (Phase 3)
// Note: sealed_material is stored to S3, not returned to the app
type PINSetupResponse struct {
	Status        string      `json:"status"`          // "vault_ready"
	UTKs          []UTKPublic `json:"utks"`            // UTKs for credential creation
	ECIESPublicKey string     `json:"ecies_public_key"` // Base64-encoded X25519 public key for PIN unlock
}

// UTKPublic is the public representation of a UTK sent to the app
type UTKPublic struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"` // Base64-encoded X25519 public key
}

// CredentialCreateRequest is the request to create the Protean Credential
// This is Phase 3 of enrollment, after PIN setup (Phase 2)
type CredentialCreateRequest struct {
	UTKID            string `json:"utk_id"`            // UTK used for encryption
	EncryptedPayload string `json:"encrypted_payload"` // UTK-encrypted password hash
}

// CredentialCreatePayload is the decrypted content of EncryptedPayload
// Contains the Argon2id-hashed credential password in PHC string format
type CredentialCreatePayload struct {
	// PasswordHash is the Argon2id hash in PHC format:
	// $argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
	// This self-describing format includes all parameters needed for verification
	PasswordHash string `json:"password_hash"`
}

// CredentialCreateResponse is returned after Protean Credential creation
// Note: Cold vault recovery data (encrypted_vault_state, sealed_ecies_keys) is stored to S3, not returned to the app
type CredentialCreateResponse struct {
	Status              string      `json:"status"`               // "created"
	EncryptedCredential string      `json:"encrypted_credential"` // CEK-encrypted Protean Credential
	NewUTKs             []UTKPublic `json:"new_utks"`             // Fresh UTKs for future operations
}

// PINUnlockRequest is the request to unlock with PIN
// For cold vault unlock, the vault loads sealed_material, sealed_ecies_keys, and
// encrypted_vault_state from S3 - the app does not send these.
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

	// Zero DEK
	zeroBytes(vs.dek)
	vs.dek = nil

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

	// Zero the password hash string (PHC format)
	// While Go strings are immutable, we clear the field for defense in depth
	uc.PasswordHash = ""

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

// --- Credential Secret Types (for credential.secret.* operations) ---
// These are critical secrets stored inside the sealed Protean Credential

// SecretCategory defines the type of secret stored
type SecretCategory string

const (
	SecretCategorySeedPhrase     SecretCategory = "SEED_PHRASE"
	SecretCategoryPrivateKey     SecretCategory = "PRIVATE_KEY"
	SecretCategorySigningKey     SecretCategory = "SIGNING_KEY"
	SecretCategoryMasterPassword SecretCategory = "MASTER_PASSWORD"
	SecretCategoryOther          SecretCategory = "OTHER"
)

// --- Request/Response types for credential.secret.* operations ---

// CredentialSecretAddRequest is the request for credential.secret.add
// Requires the encrypted credential blob so the vault can add the secret to it
type CredentialSecretAddRequest struct {
	EncryptedCredential   string `json:"encrypted_credential"`    // CEK-encrypted credential blob
	EncryptedPasswordHash string `json:"encrypted_password_hash"` // Base64-encoded, UTK-encrypted
	KeyID                 string `json:"key_id"`                  // UTK ID used for encryption
	Name                  string `json:"name"`
	Category              string `json:"category"`                // SEED_PHRASE, PRIVATE_KEY, etc.
	Description           string `json:"description,omitempty"`
	Value                 string `json:"value"`                   // Base64-encoded secret value (transport-encrypted via UTK)
}

// CredentialSecretAddResponse is the response for credential.secret.add
type CredentialSecretAddResponse struct {
	ID                  string      `json:"id"`
	CreatedAt           string      `json:"created_at"`           // ISO8601
	EncryptedCredential string      `json:"encrypted_credential"` // Updated CEK-encrypted credential
	NewUTKs             []UTKPublic `json:"new_utks,omitempty"`   // Replacement UTKs
}

// CredentialSecretGetRequest is the request for credential.secret.get
// Requires password verification and the encrypted credential blob
type CredentialSecretGetRequest struct {
	EncryptedCredential   string `json:"encrypted_credential"`    // CEK-encrypted credential blob
	ID                    string `json:"id"`
	EncryptedPasswordHash string `json:"encrypted_password_hash"` // Base64-encoded, UTK-encrypted
	KeyID                 string `json:"key_id"`                  // UTK ID used for encryption
}

// CredentialSecretGetResponse is the response for credential.secret.get
type CredentialSecretGetResponse struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Category string      `json:"category"`
	Value    string      `json:"value"`              // Base64-encoded plaintext secret value
	NewUTKs  []UTKPublic `json:"new_utks,omitempty"` // Replacement UTKs after consumption
}

// CredentialSecretListRequest is the request for credential.secret.list
// Password required for initial authentication
type CredentialSecretListRequest struct {
	EncryptedPasswordHash string `json:"encrypted_password_hash,omitempty"` // Optional: for first auth
	KeyID                 string `json:"key_id,omitempty"`                  // UTK ID used for encryption
}

// CredentialSecretListResponse is the response for credential.secret.list
// Returns metadata only, no secret values
type CredentialSecretListResponse struct {
	Secrets    []CredentialSecretMetadata `json:"secrets"`
	CryptoKeys []CryptoKeyMetadata       `json:"crypto_keys,omitempty"`
	Credential *CredentialInfoMetadata    `json:"credential,omitempty"`
}

// CredentialSecretMetadata is the metadata for a secret in list response
type CredentialSecretMetadata struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description,omitempty"`
	Owner       string `json:"owner,omitempty"`
	CreatedAt   string `json:"created_at"` // ISO8601
}

// CryptoKeyMetadata is metadata for a crypto key (no private key data)
type CryptoKeyMetadata struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	Type           string `json:"type"`
	PublicKey      string `json:"public_key,omitempty"`       // Base64-encoded (public, safe to show)
	DerivationPath string `json:"derivation_path,omitempty"`
	CreatedAt      string `json:"created_at"`                 // ISO8601
}

// CredentialInfoMetadata is metadata about the credential itself
type CredentialInfoMetadata struct {
	IdentityFingerprint string `json:"identity_fingerprint"` // Hex fingerprint of identity public key
	VaultID             string `json:"vault_id,omitempty"`
	BoundAt             string `json:"bound_at,omitempty"`   // ISO8601
	Version             int    `json:"version"`
	CreatedAt           string `json:"created_at"`           // ISO8601
	LastModified        string `json:"last_modified"`        // ISO8601
}

// CredentialSecretDeleteRequest is the request for credential.secret.delete
// Requires password verification and the encrypted credential blob
type CredentialSecretDeleteRequest struct {
	EncryptedCredential   string `json:"encrypted_credential"`    // CEK-encrypted credential blob
	ID                    string `json:"id"`
	EncryptedPasswordHash string `json:"encrypted_password_hash"` // Base64-encoded, UTK-encrypted
	KeyID                 string `json:"key_id"`                  // UTK ID used for encryption
}

// CredentialSecretDeleteResponse is the response for credential.secret.delete
type CredentialSecretDeleteResponse struct {
	Success             bool        `json:"success"`
	EncryptedCredential string      `json:"encrypted_credential,omitempty"` // Updated CEK-encrypted credential
	NewUTKs             []UTKPublic `json:"new_utks,omitempty"`             // Replacement UTKs after consumption
}

// SecretMetadataRecord is stored in vault SQLite for the metadata index
// This allows listing secrets without needing the credential blob
type SecretMetadataRecord struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description,omitempty"`
	Owner       string `json:"owner"`
	CreatedAt   int64  `json:"created_at"`
}

// --- Personal Data Types ---
// For structured profile fields with dotted namespace naming

// FieldType defines the type of a personal data field
type FieldType string

const (
	FieldTypeText     FieldType = "text"     // General text
	FieldTypePassword FieldType = "password" // Masked display
	FieldTypeNumber   FieldType = "number"   // Numeric keyboard
	FieldTypeDate     FieldType = "date"     // Date picker (YYYY-MM-DD)
	FieldTypeEmail    FieldType = "email"    // Email keyboard
	FieldTypePhone    FieldType = "phone"    // Phone keyboard
	FieldTypeURL      FieldType = "url"      // URL keyboard
	FieldTypeNote     FieldType = "note"     // Multi-line text
)

// PredefinedCategory represents the built-in categories
type PredefinedCategory struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Icon string `json:"icon"`
}

// PredefinedCategories is the list of built-in categories
var PredefinedCategories = []PredefinedCategory{
	{ID: "identity", Name: "Identity", Icon: "person"},
	{ID: "contact", Name: "Contact", Icon: "phone"},
	{ID: "address", Name: "Address", Icon: "location"},
	{ID: "financial", Name: "Financial", Icon: "account_balance"},
	{ID: "medical", Name: "Medical", Icon: "medical"},
	{ID: "other", Name: "Other", Icon: "more"},
}

// PersonalDataField represents a user's personal data field stored in the vault
// Uses dotted namespace naming: personal.legal.first_name, contact.phone.mobile
type PersonalDataField struct {
	ID          string    `json:"id"`           // UUID
	Name        string    `json:"name"`         // Dotted namespace: "contact.phone.mobile"
	DisplayName string    `json:"display_name"` // Human-readable: "Mobile Phone"
	Value       string    `json:"value"`        // The actual value (encrypted in vault)
	FieldType   FieldType `json:"field_type"`   // TEXT, PASSWORD, NUMBER, DATE, EMAIL, PHONE, URL, NOTE
	Category    string    `json:"category"`     // Category ID (predefined or custom)
	IsSensitive bool      `json:"is_sensitive"` // If true, treated like minor secret
	CreatedAt   int64     `json:"created_at"`   // Unix timestamp
	UpdatedAt   int64     `json:"updated_at"`
}

// CustomCategory represents a user-defined category for organizing personal data
type CustomCategory struct {
	ID        string `json:"id"`             // UUID
	Name      string `json:"name"`           // User-defined name
	Icon      string `json:"icon,omitempty"` // Optional icon
	CreatedAt int64  `json:"created_at"`
}

// PublicProfileSettings stores which fields to include in the public profile
// Stored at profile/_public
type PublicProfileSettings struct {
	Version     int      `json:"version"`
	Fields      []string `json:"fields"`       // Field names to include in public profile
	UpdatedAt   int64    `json:"updated_at"`
	PublishedAt int64    `json:"published_at"` // When last published to NATS
}

// PublishedField represents a single field in the published profile
type PublishedField struct {
	DisplayName string `json:"display_name"`
	Value       string `json:"value"`
	FieldType   string `json:"field_type"`
}

// PublishedProfile is the structure published to NATS for connections to see
// Published to topic: {ownerSpace}.profile.public
type PublishedProfile struct {
	UserGUID      string                    `json:"user_guid"`
	PublicKey     string                    `json:"public_key"`      // Ed25519 public key (base64)
	FirstName     string                    `json:"first_name"`      // Always included from registration
	LastName      string                    `json:"last_name"`       // Always included
	Email         string                    `json:"email"`           // Always included
	EmailVerified bool                      `json:"email_verified"`  // From registration
	Photo         string                    `json:"photo,omitempty"` // Base64-encoded JPEG profile photo
	Fields        map[string]PublishedField `json:"fields"`          // Selected personal data fields
	Version       int                       `json:"profile_version"`
	UpdatedAt     string                    `json:"updated_at"` // ISO8601
}

// --- Profile Request/Response Types ---

// ProfileCategoriesGetResponse is the response for profile.categories.get
type ProfileCategoriesGetResponse struct {
	Predefined []PredefinedCategory `json:"predefined"`
	Custom     []CustomCategory     `json:"custom"`
}

// ProfileCategoriesUpdateRequest is the request for profile.categories.update
type ProfileCategoriesUpdateRequest struct {
	Categories []CustomCategory `json:"categories"`
}

// ProfilePublishRequest is the request for profile.publish
type ProfilePublishRequest struct {
	Fields []string `json:"fields,omitempty"` // Optional: update selected fields before publishing
}

// ProfilePublishResponse is the response for profile.publish
type ProfilePublishResponse struct {
	Success     bool   `json:"success"`
	Version     int    `json:"version"`
	PublishedAt string `json:"published_at"` // ISO8601
}
