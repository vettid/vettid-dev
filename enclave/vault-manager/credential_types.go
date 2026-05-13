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

	// Identity-key carve-out.
	//
	// The Ed25519 private key is loaded at PIN unlock and gated by a
	// user-configurable sliding TTL (settings.credential.session_ttl_seconds,
	// 30s–60min, default 5min). Every signed action / contract / vote
	// extends the window via consumeIdentityKey(); after the window
	// passes idle, the key is wiped and the next signing op returns
	// "identity_locked". The client re-authenticates with the user's
	// password via credential.identity-unlock to repopulate the field
	// for another window.
	//
	// The public key has no TTL — it's public and stays loaded for
	// the session so profile.publish, bootstrap, etc. can surface it
	// without prompting.
	identityPrivateKey   []byte // ed25519.PrivateKey (64 bytes)
	identityPublicKey    []byte // ed25519.PublicKey (32 bytes)
	identityKeyExpiresAt int64  // unix seconds; zero == not unlocked / expired

	// Audit-key derivation — see audit_key.go for the rationale.
	//
	// Derived once per PIN unlock via HKDF(identity_priv, "vettid-audit-key-v1")
	// and held in vault memory for the session (no TTL — wiped only on
	// PIN-lock alongside identity_priv). Every audit-log write is signed
	// with audit_priv so the resulting chain is independently verifiable
	// by anyone who has the user's identity_pub (via the one-time
	// audit.binding event the vault emits on first derivation).
	//
	// The point of a *derived* signing key rather than reusing identity
	// directly: identity-key use is intentionally gated by a per-event
	// password prompt for vote / verify / contract signing — wiring
	// every audit row through that gate would either kill performance
	// or force us to TTL-cache the identity key (which we explicitly
	// don't want, see feedback-audit-log-mirroring.md). The audit key
	// is a derivative that lives in vault memory only and can be used
	// without prompting, while still being bound to the identity key.
	auditPrivateKey       []byte // ed25519.PrivateKey (64 bytes); derived
	auditPublicKey        []byte // ed25519.PublicKey (32 bytes); derived
	auditBindingSignature []byte // ed25519 sig of "vettid-audit-binding-v1" || audit_pub by identity_priv
	auditBindingEmitted   bool   // whether the binding event has been written this session

	// PIN auth carve-out (Phase D). Populated at PIN unlock so PIN
	// change can verify the old PIN without retaining the full
	// credential plaintext. Updated atomically with the credential
	// blob persistence in HandlePINChange.
	pinAuthHash []byte // Argon2id hash of the user's PIN
	pinAuthSalt []byte // 16-byte salt used to compute pinAuthHash

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

	// vaultDataLoaded is set true once this enclave instance has loaded
	// the user's persistent data into memory — either by cold-unlocking
	// from S3 (PIN unlock decrypts vault_state.enc + restores SQLite
	// backup) or by completing a fresh enrollment that wrote the initial
	// state.
	//
	// SECURITY: persistVaultStateToS3 refuses to write when this is
	// false. The 2026-05-09 incident: a migration-start request landed
	// on the same enclave that handled PIN unlock, but somehow the
	// in-memory storage was incomplete; the migration's gratuitous
	// persistFn ran and overwrote a 220KB S3 vault_state with a 12KB
	// stub, wiping the user's data. Migration no longer calls persist
	// (M4 / 2026-05-09 architect redesign), but this guard remains as
	// defense-in-depth against any future code path that would persist
	// without first having loaded the user's existing data.
	vaultDataLoaded bool

	// loadedVaultStateSize tracks the byte size of the encrypted vault
	// state this instance most recently loaded or wrote. Used by
	// persistVaultStateToS3's shrink guard (architect §3 storage
	// invariants): refuse to overwrite when an existing object >= 50 KB
	// would shrink to < 50% of its size. Zero means we don't know the
	// previous size (e.g. fresh enrollment before first persist) — in
	// that case the shrink guard is a no-op. Set on cold-unlock S3
	// load, on fresh-enrollment first write, and on every successful
	// persistVaultStateToS3.
	loadedVaultStateSize int64
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

// --- Protean Credential Format V2 ---
// V2 is the only supported format. The V1 UnsealedCredential / CryptoKey
// structs and their MigrateV1ToV2 / ToV1 helpers were removed once all
// users were re-enrolled.

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

// CredentialAuth holds authentication information.
//
// Hash is the PHC-format hash of the credential password — verified on
// every signed op (wallet add, secret reveal, password change).
//
// PinHash + PinSalt are the Argon2id raw-bytes hash of the device PIN,
// used during pin.unlock to verify the PIN before deriving the DEK.
// They are populated on PIN setup (or first PIN change) and rotated
// on every subsequent PIN change.
type CredentialAuth struct {
	Type    string `json:"type"`     // "password" (always — PIN is a separate factor below)
	Hash    string `json:"hash"`     // PHC string for the password
	PinHash []byte `json:"pin_hash,omitempty"`
	PinSalt []byte `json:"pin_salt,omitempty"`
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

// SecureErase zeros all sensitive data in the V2 credential
func (v2 *ProteanCredentialV2) SecureErase() {
	if v2 == nil {
		return
	}

	zeroBytes(v2.Identity.PrivateKey)
	zeroBytes(v2.Identity.PublicKey)
	zeroBytes(v2.MasterSecret)

	v2.Auth.Hash = ""
	zeroBytes(v2.Auth.PinHash)
	zeroBytes(v2.Auth.PinSalt)
	v2.Auth.PinHash = nil
	v2.Auth.PinSalt = nil

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
	// MigrateConsent (M1, 2026-05-09 architect redesign): when true,
	// the user has approved the post-deploy migration via the unified
	// PIN screen. After successful PIN verify, the handler will
	// re-seal sealed_material.bin against the running PCR0 (if it
	// matches the published migration config's NewPCR0) or emit a
	// routing handoff so the NEW enclave reclaims the user (if the
	// request landed on OLD). Either way the unlock itself succeeds.
	MigrateConsent bool `json:"migrate_consent,omitempty"`
}

// PINUnlockResponse is returned after successful unlock
type PINUnlockResponse struct {
	Status              string   `json:"status"`
	EncryptedCredential string   `json:"encrypted_credential,omitempty"`
	NewUTKs             []string `json:"new_utks"`
	// Vault-issued NATS credentials (full OwnerSpace/MessageSpace access)
	// Only the vault can issue these — Lambda only issues narrow bootstrap creds
	NatsCredentials string `json:"nats_credentials,omitempty"`
	NatsEndpoint    string `json:"nats_endpoint,omitempty"`
	OwnerSpace      string `json:"owner_space,omitempty"`
	MessageSpace    string `json:"message_space,omitempty"`
	CredentialsTTL  int    `json:"credentials_ttl_seconds,omitempty"`
	// MigrationStatus (M1) is the canonical signal the app uses to
	// learn the result of a migrate_consent=true unlock. Values:
	//   "completed"            - re-seal landed on this enclave; user
	//                            is fully migrated to MigrationVersion.
	//   "pending_new_enclave"  - request landed on the OLD enclave;
	//                            handoff was emitted, app should retry.
	//                            Unlock itself still succeeded.
	//   "failed"               - re-seal attempted but errored. Unlock
	//                            still succeeded. App can retry next
	//                            session.
	//   "not_requested"        - migrate_consent=false, or no signed
	//                            migration config is published.
	//   "" (omitted)           - no migration in flight at all.
	MigrationStatus  string `json:"migration_status,omitempty"`
	MigrationVersion string `json:"migration_version,omitempty"`
}

// PINChangeRequest is the request to change PIN
type PINChangeRequest struct {
	UTKID            string `json:"utk_id"`
	EncryptedPayload string `json:"encrypted_payload"` // Contains old_pin and new_pin
	// Phase D: caller supplies the CEK-encrypted credential blob so
	// the vault decrypts in-flight, mutates AuthHash/AuthSalt/Version,
	// re-encrypts, and returns the new blob without holding the
	// credential plaintext in memory.
	EncryptedCredential string `json:"encrypted_credential,omitempty"`
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

// PasswordChangeRequest is the request to change the credential password
// Uses UTK encryption (same as credential.create) for transport security
type PasswordChangeRequest struct {
	UTKID            string `json:"utk_id"`
	EncryptedPayload string `json:"encrypted_payload"` // UTK-encrypted old + new password hashes
	// Phase D: caller supplies the encrypted credential blob so the
	// vault decrypts in-flight rather than reading vaultState.credential.
	EncryptedCredential string `json:"encrypted_credential,omitempty"`
}

// PasswordChangePayload is the decrypted payload for password change
// Both hashes are in PHC format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
type PasswordChangePayload struct {
	OldPasswordHash string `json:"old_password_hash"` // Current password hash (PHC format)
	NewPasswordHash string `json:"new_password_hash"` // New password hash (PHC format)
}

// PasswordChangeResponse is returned after successful password change
type PasswordChangeResponse struct {
	Status              string      `json:"status"`               // "password_changed"
	EncryptedCredential string      `json:"encrypted_credential"` // Re-encrypted credential with updated password
	NewUTKs             []UTKPublic `json:"new_utks"`             // Fresh UTKs
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

	// Phase D: full credential plaintext is no longer cached. Wipe
	// the narrow carve-outs (identity keypair + PIN auth hash/salt)
	// instead.
	if vs.identityPrivateKey != nil {
		zeroBytes(vs.identityPrivateKey)
		vs.identityPrivateKey = nil
	}
	vs.identityPublicKey = nil
	if vs.pinAuthHash != nil {
		zeroBytes(vs.pinAuthHash)
		vs.pinAuthHash = nil
	}
	if vs.pinAuthSalt != nil {
		zeroBytes(vs.pinAuthSalt)
		vs.pinAuthSalt = nil
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
	SecretCategoryRecoveryKey    SecretCategory = "RECOVERY_KEY"
	SecretCategoryOther          SecretCategory = "OTHER"
)

// --- Request/Response types for credential.secret.* operations ---

// CredentialSecretAddRequest is the request for credential.secret.add
// Requires the encrypted credential blob so the vault can add the secret to it
type CredentialSecretAddRequest struct {
	EncryptedCredential   string `json:"encrypted_credential"`    // CEK-encrypted credential blob
	EncryptedPasswordHash string `json:"encrypted_password_hash"` // Base64-encoded, UTK-encrypted ciphertext
	EphemeralPublicKey    string `json:"ephemeral_public_key"`    // Base64-encoded X25519 ephemeral public key
	Nonce                 string `json:"nonce"`                   // Base64-encoded XChaCha20 nonce
	KeyID                 string `json:"key_id"`                  // UTK ID used for encryption
	Name                  string `json:"name"`
	Category              string `json:"category"`                // SEED_PHRASE, PRIVATE_KEY, etc.
	Description           string `json:"description,omitempty"`
	Alias                 string `json:"alias,omitempty"`         // user-defined label that groups related secrets in the catalog
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
	EncryptedPasswordHash string `json:"encrypted_password_hash"` // Base64-encoded, UTK-encrypted ciphertext
	EphemeralPublicKey    string `json:"ephemeral_public_key"`    // Base64-encoded X25519 ephemeral public key
	Nonce                 string `json:"nonce"`                   // Base64-encoded XChaCha20 nonce
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
	// Plain list (metadata index only) needs no auth fields. To get
	// the enriched response (crypto keys + credential info) the caller
	// supplies the encrypted credential blob alongside the password
	// material; the vault decrypts per-op rather than holding the
	// credential in memory.
	EncryptedCredential   string `json:"encrypted_credential,omitempty"`
	EncryptedPasswordHash string `json:"encrypted_password_hash,omitempty"`
	EphemeralPublicKey    string `json:"ephemeral_public_key,omitempty"`
	Nonce                 string `json:"nonce,omitempty"`
	KeyID                 string `json:"key_id,omitempty"`
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
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Category        string          `json:"category"`
	Description     string          `json:"description,omitempty"`
	Owner           string          `json:"owner,omitempty"`
	Discoverability Discoverability `json:"discoverability,omitempty"` // public | cataloged | private
	Alias           string          `json:"alias,omitempty"`           // user-defined label that groups related critical secrets
	CreatedAt       string          `json:"created_at"`                // ISO8601
}

// CredentialSecretSetDiscoverabilityRequest is the request for
// credential.secret.set-discoverability — updates only the metadata
// row, never touches the credential blob (the value stays sealed).
type CredentialSecretSetDiscoverabilityRequest struct {
	ID              string          `json:"id"`
	Discoverability Discoverability `json:"discoverability"` // public | cataloged | private
}

// CredentialSecretSetDiscoverabilityResponse is the response shape.
type CredentialSecretSetDiscoverabilityResponse struct {
	ID              string          `json:"id"`
	Discoverability Discoverability `json:"discoverability"`
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
	EncryptedPasswordHash string `json:"encrypted_password_hash"` // Base64-encoded, UTK-encrypted ciphertext
	EphemeralPublicKey    string `json:"ephemeral_public_key"`    // Base64-encoded X25519 ephemeral public key
	Nonce                 string `json:"nonce"`                   // Base64-encoded XChaCha20 nonce
	KeyID                 string `json:"key_id"`                  // UTK ID used for encryption
}

// CredentialSecretDeleteResponse is the response for credential.secret.delete
type CredentialSecretDeleteResponse struct {
	Success             bool        `json:"success"`
	EncryptedCredential string      `json:"encrypted_credential,omitempty"` // Updated CEK-encrypted credential
	NewUTKs             []UTKPublic `json:"new_utks,omitempty"`             // Replacement UTKs after consumption
}

// SecretMetadataRecord is stored in vault SQLite for the metadata index
// This allows listing secrets without needing the credential blob.
// Discoverability mirrors the personal-data flag: cataloged (default —
// peers see metadata, can request value), public (metadata + the user
// has elected to publish — currently same as cataloged for secrets),
// private (excluded from any peer-visible catalog).
type SecretMetadataRecord struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Category        string          `json:"category"`
	Description     string          `json:"description,omitempty"`
	Owner           string          `json:"owner"`
	Discoverability Discoverability `json:"discoverability,omitempty"`
	Alias           string          `json:"alias,omitempty"` // user-defined label (groups related critical secrets)
	CreatedAt       int64           `json:"created_at"`
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

// Discoverability controls how a personal-data field (or secret entry)
// shows up to peers. Three states:
//
//   public     — value goes into the published profile and is visible
//                to every connection. The user explicitly promoted it
//                to their calling-card.
//   cataloged  — only metadata (name, type, category) is visible. Peers
//                see "Al has a credit card called Personal Visa" and
//                can request the value through a future capability flow.
//                This is the default for new entries.
//   private    — invisible to peers. The vault holds the value but
//                doesn't list it in any catalog. Use for genuinely
//                sensitive items the user doesn't want any connection
//                to know they possess (e.g. medical info, seed
//                phrases).
//
// Empty string is treated as "cataloged" so legacy fields written
// before the discoverability work behave per the new default.
type Discoverability string

const (
	DiscoverabilityPublic    Discoverability = "public"
	DiscoverabilityCataloged Discoverability = "cataloged"
	DiscoverabilityPrivate   Discoverability = "private"
	// DiscoverabilityCatalogedForUse is a distinct state for critical
	// secrets (plans/data-request-grants.md Phase 6 — 2026-05-12 UX
	// refinement): peers see the secret exists and can request the
	// owner to USE it on their behalf (sign / decrypt / derive / auth),
	// but the value itself stays in the vault forever. The grant
	// resolver still hard-rejects critical secrets, so this state is
	// "metadata visible, value never leaves" — strictly more restrictive
	// than cataloged.
	DiscoverabilityCatalogedForUse Discoverability = "cataloged-for-use"
)

// PersonalDataField represents a user's personal data field stored in the vault
// Uses dotted namespace naming: personal.legal.first_name, contact.phone.mobile
type PersonalDataField struct {
	ID              string          `json:"id"`           // UUID
	Name            string          `json:"name"`         // Dotted namespace: "contact.phone.mobile"
	DisplayName     string          `json:"display_name"` // Human-readable: "Mobile Phone"
	// Alias is a short user-defined identifier that disambiguates
	// multiple entries within the same category — e.g. "Wife",
	// "Maria", "Mom", "Work". Surfaced in the catalog so peers see
	// "Family · Phone — Wife" instead of two indistinguishable
	// "Family · Phone" rows. Optional; never carries the value.
	Alias           string          `json:"alias,omitempty"`
	Value           string          `json:"value"`        // The actual value (encrypted in vault)
	FieldType       FieldType       `json:"field_type"`   // TEXT, PASSWORD, NUMBER, DATE, EMAIL, PHONE, URL, NOTE
	Category        string          `json:"category"`     // Category ID (predefined or custom)
	IsSensitive     bool            `json:"is_sensitive"` // If true, treated like minor secret
	Discoverability Discoverability `json:"discoverability,omitempty"` // public | cataloged | private
	CreatedAt       int64           `json:"created_at"`   // Unix timestamp
	UpdatedAt       int64           `json:"updated_at"`
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
// PublishedWallet is a wallet address included in the published profile
type PublishedWallet struct {
	WalletID string `json:"wallet_id"`
	Label    string `json:"label"`
	Address  string `json:"address"` // bech32 P2WPKH
	Network  string `json:"network"` // "mainnet" or "testnet"
}

// PublishedHandler is a single vault capability entry in the peer
// profile. Peers see the full operation set so the "what can this
// connection do?" row in the profile preview is honest, not just a
// count. All vaults of the same version share the same list; the
// app still renders it per-peer so each connection card can answer
// the question independently even if the viewer upgrades later.
type PublishedHandler struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Operations  []string `json:"operations,omitempty"`
	// Classification baked into the enclave's handler catalog. Peers
	// see these so their UI can render "system / default / optional"
	// badges and avoid offering toggles the owner cannot flip.
	Category  string `json:"category,omitempty"`
	Required  bool   `json:"required,omitempty"`
	Shareable bool   `json:"shareable,omitempty"`
}

// PublishedSecretMetadata is metadata (never value) about a secret
// the user has opted into publishing to connections. Comes from the
// app's MinorSecretsStore via profile.publish and is stored in the
// vault so peers see the same metadata rows the user sees in their
// own public-profile preview.
type PublishedSecretMetadata struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Category string `json:"category,omitempty"`
}

// CatalogedDataItem is a metadata-only entry surfaced via the public
// profile's data catalog. Peers see what kinds of data the user has
// stored (e.g. "Home Address" / "Mobile Phone") and can later request
// access to specific values through the capability flow. Items
// flagged Discoverability=private never appear here.
type CatalogedDataItem struct {
	Name        string `json:"name"`         // Dotted namespace, e.g. "contact.phone.mobile"
	DisplayName string `json:"display_name"` // Human-readable name
	FieldType   string `json:"field_type"`   // text, email, phone, ...
	Category    string `json:"category,omitempty"`
	// Alias mirrors PersonalDataField.Alias — surfaces user-defined
	// disambiguator so peers can tell "Family · Phone — Wife" apart
	// from "Family · Phone — Daughter".
	Alias       string `json:"alias,omitempty"`
}

// CatalogedSecretItem mirrors CatalogedDataItem for vault secrets.
// Like data items, items flagged private are excluded.
type CatalogedSecretItem struct {
	Name     string `json:"name"`
	Type     string `json:"type"`               // SEED_PHRASE, PRIVATE_KEY, etc.
	Category string `json:"category,omitempty"` // user-defined grouping
	Alias    string `json:"alias,omitempty"`    // user-defined label (groups related secrets)
}

type PublishedProfile struct {
	UserGUID      string                    `json:"user_guid"`
	PublicKey     string                    `json:"public_key"`                // Ed25519 public key (base64)
	FirstName     string                    `json:"first_name"`                // Always included from registration
	LastName      string                    `json:"last_name"`                 // Always included
	Email         string                    `json:"email"`                     // Always included
	EmailVerified bool                      `json:"email_verified"`            // From registration
	Photo         string                    `json:"photo,omitempty"`           // Base64-encoded JPEG profile photo
	Fields        map[string]PublishedField `json:"fields"`                    // Personal data fields the user marked Public — value visible
	// FieldOrder is the user-intended display order of the keys in
	// Fields. Old clients that ignore this render in JSON-map order
	// (Go encodes maps with keys sorted alphabetically); new clients
	// iterate FieldOrder and look up Fields[name] so the user's
	// drag-to-reorder propagates to peer + own preview alike.
	FieldOrder    []string                  `json:"field_order,omitempty"`
	Wallets       []PublishedWallet         `json:"wallets,omitempty"`         // Public wallet addresses
	Handlers      []PublishedHandler        `json:"handlers,omitempty"`        // Vault capability catalog (shareable handlers only)
	Actions       []PublishedAction         `json:"actions,omitempty"`         // Shared-action catalog (Phase 1: visibility-filtered per viewer)
	PublicSecrets []PublishedSecretMetadata `json:"public_secrets,omitempty"`  // Legacy: kept for older app builds; superseded by SecretCatalog
	// Catalogs are the metadata-only surfaces a peer browses. They
	// list every personal-data / secret entry the user has NOT marked
	// private. Values are never carried — peers must request them
	// through the capability flow.
	DataCatalog   []CatalogedDataItem   `json:"data_catalog,omitempty"`
	SecretCatalog []CatalogedSecretItem `json:"secret_catalog,omitempty"`
	Version       int                   `json:"profile_version"`
	UpdatedAt     string                `json:"updated_at"` // ISO8601
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
	// PublicSecrets is metadata (name/type/category — never values)
	// that the app sources from MinorSecretsStore. The vault stores
	// it alongside the published field selection so peers see the
	// same "Secrets (N)" badge row the user sees on their own
	// public-profile preview. Empty list explicitly clears prior.
	PublicSecrets []PublishedSecretMetadata `json:"public_secrets,omitempty"`
}

// ProfilePublishResponse is the response for profile.publish
type ProfilePublishResponse struct {
	Success     bool   `json:"success"`
	Version     int    `json:"version"`
	PublishedAt string `json:"published_at"` // ISO8601
}
