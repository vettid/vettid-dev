package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/argon2"
)

// NitroSealer handles sealing/unsealing data using Nitro KMS attestation
type NitroSealer struct {
	conn         Connection // vsock connection to parent
	connMu       sync.Mutex // mutex for connection access
	isNitro      bool       // true if running in actual Nitro enclave
	devModeKey   []byte     // fixed key for development mode
}

// SealedData is the structure stored when sealing data
type SealedData struct {
	Version       int    `json:"version"`       // Schema version
	Algorithm     string `json:"algorithm"`     // "nitro-kms-aes256-gcm" or "dev-aes256-gcm"
	EncryptedDEK  []byte `json:"encrypted_dek"` // DEK encrypted by KMS
	Nonce         []byte `json:"nonce"`         // AES-GCM nonce
	Ciphertext    []byte `json:"ciphertext"`    // Data encrypted with DEK
	PCRBound      bool   `json:"pcr_bound"`     // true if sealed with attestation
}

// NewNitroSealer creates a new Nitro sealer
// Connection can be nil initially and set later via SetConnection
func NewNitroSealer(conn Connection) *NitroSealer {
	isNitro := isNitroEnclaveEnv()

	sealer := &NitroSealer{
		conn:    conn,
		isNitro: isNitro,
		// Development mode key - NOT SECURE, only for testing
		devModeKey: []byte("vettid-dev-mode-key-32-bytes!!!"),
	}

	if isNitro {
		log.Info().Msg("Nitro sealer initialized in production mode (using KMS with attestation)")
	} else {
		log.Warn().Msg("Nitro sealer initialized in development mode (using fixed key - NOT SECURE)")
	}

	return sealer
}

// SetConnection updates the connection used for KMS operations
// This is called when the parent process connects
func (s *NitroSealer) SetConnection(conn Connection) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.conn = conn
	log.Debug().Bool("connected", conn != nil).Msg("Sealer connection updated")
}

// isNitroEnclaveEnv checks if we're running in a Nitro enclave
func isNitroEnclaveEnv() bool {
	_, err := os.Stat("/dev/nsm")
	return err == nil
}

// Seal encrypts data using envelope encryption with KMS
// In production: DEK is encrypted by KMS, data is encrypted with DEK
// In dev mode: Uses a fixed key for testing
func (s *NitroSealer) Seal(plaintext []byte) ([]byte, error) {
	if !s.isNitro {
		return s.devModeSeal(plaintext)
	}

	return s.nitroKMSSeal(plaintext)
}

// Unseal decrypts sealed data
// In production: Requires attestation to decrypt DEK from KMS
// In dev mode: Uses a fixed key for testing
func (s *NitroSealer) Unseal(sealedData []byte) ([]byte, error) {
	// Parse sealed data
	var sealed SealedData
	if err := json.Unmarshal(sealedData, &sealed); err != nil {
		return nil, fmt.Errorf("failed to parse sealed data: %w", err)
	}

	if sealed.Algorithm == "dev-aes256-gcm" {
		return s.devModeUnseal(&sealed)
	}

	if !s.isNitro {
		return nil, fmt.Errorf("cannot unseal production data in development mode")
	}

	return s.nitroKMSUnseal(&sealed)
}

// nitroKMSSeal seals data using KMS envelope encryption
func (s *NitroSealer) nitroKMSSeal(plaintext []byte) ([]byte, error) {
	log.Debug().Int("plaintext_len", len(plaintext)).Msg("Sealing data with Nitro KMS")

	// 1. Generate a random 256-bit DEK
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// 2. Send DEK to parent for KMS encryption
	encryptedDEK, err := s.kmsEncrypt(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK with KMS: %w", err)
	}

	// 3. Encrypt data locally with DEK using AES-GCM
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// 4. Package sealed data
	sealed := SealedData{
		Version:      1,
		Algorithm:    "nitro-kms-aes256-gcm",
		EncryptedDEK: encryptedDEK,
		Nonce:        nonce,
		Ciphertext:   ciphertext,
		PCRBound:     true,
	}

	// Zero out DEK from memory
	for i := range dek {
		dek[i] = 0
	}

	result, err := json.Marshal(sealed)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sealed data: %w", err)
	}

	log.Debug().
		Int("sealed_len", len(result)).
		Int("encrypted_dek_len", len(encryptedDEK)).
		Msg("Data sealed successfully")

	return result, nil
}

// nitroKMSUnseal unseals data using KMS with attestation
func (s *NitroSealer) nitroKMSUnseal(sealed *SealedData) ([]byte, error) {
	log.Debug().
		Int("ciphertext_len", len(sealed.Ciphertext)).
		Int("encrypted_dek_len", len(sealed.EncryptedDEK)).
		Msg("Unsealing data with Nitro KMS")

	// 1. Generate attestation with RSA public key for KMS
	attestation, privateKey, err := s.generateAttestationForKMS()
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %w", err)
	}

	// 2. Send encrypted DEK to parent for KMS decryption with attestation
	// KMS returns CiphertextForRecipient - a CBOR envelope containing the DEK encrypted to our RSA public key
	ciphertextForRecipient, err := s.kmsDecrypt(sealed.EncryptedDEK, attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK with KMS: %w", err)
	}

	// 3. Parse the CMS/PKCS#7 EnvelopedData to get the RSA-encrypted key material
	// AWS KMS returns CiphertextForRecipient as PKCS#7 EnvelopedData (OID 1.2.840.113549.1.7.3)
	// The encrypted content is our DEK, encrypted to our RSA public key
	log.Debug().
		Int("envelope_len", len(ciphertextForRecipient)).
		Hex("first_16_bytes", ciphertextForRecipient[:min(16, len(ciphertextForRecipient))]).
		Msg("CiphertextForRecipient from KMS (PKCS#7 EnvelopedData)")

	// AWS KMS CiphertextForRecipient is CMS EnvelopedData but the pkcs7 library
	// has trouble parsing it. Extract the encrypted key manually from the ASN.1.
	//
	// CMS EnvelopedData structure:
	// SEQUENCE {
	//   OID envelopedData
	//   [0] SEQUENCE {
	//     INTEGER version
	//     SET {
	//       SEQUENCE (RecipientInfo) {
	//         ...
	//         OCTET STRING (encryptedKey) <-- this is what we need
	//       }
	//     }
	//     ...
	//   }
	// }
	//
	// We search for a 256-byte OCTET STRING which is our RSA-encrypted DEK
	encryptedKey := findEncryptedKeyInCMS(ciphertextForRecipient)
	if encryptedKey == nil {
		return nil, fmt.Errorf("failed to find encrypted key in CMS envelope")
	}

	log.Debug().
		Int("encrypted_key_len", len(encryptedKey)).
		Msg("Extracted encrypted key from CMS envelope")

	// Decrypt the key with RSA-OAEP-SHA256 (what Nitro attestation uses)
	ciphertext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedKey, nil)
	if err != nil {
		// Try PKCS1v15 as fallback
		ciphertext, err = rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt CMS encrypted key: %w", err)
		}
	}

	// The decrypted content is the DEK
	dek := ciphertext
	log.Debug().
		Int("dek_len", len(dek)).
		Msg("Successfully decrypted DEK from PKCS#7 envelope")

	defer func() {
		// Zero out DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	// 4. Decrypt data locally with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, sealed.Nonce, sealed.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	log.Debug().Int("plaintext_len", len(plaintext)).Msg("Data unsealed successfully")

	return plaintext, nil
}

// generateAttestationForKMS generates an attestation with an RSA public key
// KMS requires RSA for the Recipient feature
func (s *NitroSealer) generateAttestationForKMS() ([]byte, *rsa.PrivateKey, error) {
	// Generate RSA key pair (2048 bits as required by KMS)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Open NSM session
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open NSM session: %w", err)
	}
	defer sess.Close()

	// Marshal RSA public key to PKCS#1 format for NSM
	// Note: NSM expects raw public key bytes, we'll use the DER-encoded form
	pubKeyBytes := publicKeyToBytes(&privateKey.PublicKey)

	// Request attestation with the RSA public key embedded
	res, err := sess.Send(&request.Attestation{
		PublicKey: pubKeyBytes,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attestation from NSM: %w", err)
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, nil, fmt.Errorf("NSM returned empty attestation document")
	}

	log.Debug().
		Int("attestation_len", len(res.Attestation.Document)).
		Int("pubkey_len", len(pubKeyBytes)).
		Msg("Generated attestation for KMS")

	return res.Attestation.Document, privateKey, nil
}

// publicKeyToBytes serializes an RSA public key for inclusion in attestation
// SECURITY: Uses standard SPKI/DER encoding as required by AWS KMS
func publicKeyToBytes(pub *rsa.PublicKey) []byte {
	// For KMS Recipient, we need the SubjectPublicKeyInfo (SPKI) DER encoding
	// This is the standard format that AWS KMS expects and uses for CiphertextForRecipient
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// This should never happen with a valid RSA public key
		log.Error().Err(err).Msg("Failed to marshal RSA public key to SPKI/DER")
		return nil
	}
	return der
}

// kmsEncrypt sends plaintext to parent for KMS encryption
func (s *NitroSealer) kmsEncrypt(plaintext []byte) ([]byte, error) {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	msg := &Message{
		Type:      MessageTypeKMSEncrypt,
		Plaintext: plaintext,
	}

	if err := s.conn.WriteMessage(msg); err != nil {
		return nil, fmt.Errorf("failed to send KMS encrypt request: %w", err)
	}

	response, err := s.conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to read KMS encrypt response: %w", err)
	}

	if response.Type == MessageTypeError {
		return nil, fmt.Errorf("KMS encrypt error: %s", response.Error)
	}

	if response.Type != MessageTypeKMSResponse {
		return nil, fmt.Errorf("unexpected response type: %s", response.Type)
	}

	return response.CiphertextDEK, nil
}

// kmsDecrypt sends ciphertext to parent for KMS decryption with attestation
func (s *NitroSealer) kmsDecrypt(ciphertext []byte, attestation []byte) ([]byte, error) {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	msg := &Message{
		Type:          MessageTypeKMSDecrypt,
		CiphertextDEK: ciphertext,
		Attestation: &Attestation{
			Document: attestation,
		},
	}

	if err := s.conn.WriteMessage(msg); err != nil {
		return nil, fmt.Errorf("failed to send KMS decrypt request: %w", err)
	}

	response, err := s.conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to read KMS decrypt response: %w", err)
	}

	if response.Type == MessageTypeError {
		return nil, fmt.Errorf("KMS decrypt error: %s", response.Error)
	}

	if response.Type != MessageTypeKMSResponse {
		return nil, fmt.Errorf("unexpected response type: %s", response.Type)
	}

	// The ciphertext contains CiphertextForRecipient
	return response.Ciphertext, nil
}

// Development mode implementations (NOT SECURE - for testing only)

func (s *NitroSealer) devModeSeal(plaintext []byte) ([]byte, error) {
	log.Warn().Msg("Using development mode sealing - NOT SECURE")

	block, err := aes.NewCipher(s.devModeKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	sealed := SealedData{
		Version:    1,
		Algorithm:  "dev-aes256-gcm",
		Nonce:      nonce,
		Ciphertext: ciphertext,
		PCRBound:   false,
	}

	return json.Marshal(sealed)
}

func (s *NitroSealer) devModeUnseal(sealed *SealedData) ([]byte, error) {
	log.Warn().Msg("Using development mode unsealing - NOT SECURE")

	block, err := aes.NewCipher(s.devModeKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return gcm.Open(nil, sealed.Nonce, sealed.Ciphertext, nil)
}

// GenerateAttestationWithECDSA generates an attestation with an ECDSA public key
// This is used for non-KMS attestation (e.g., for client verification)
func GenerateAttestationWithECDSA(nonce []byte) (*Attestation, *ecdsa.PrivateKey, error) {
	if !isNitroEnclaveEnv() {
		return generateMockAttestationWithECDSA(nonce)
	}

	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	pubKeyBytes := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)

	// Open NSM session
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open NSM session: %w", err)
	}
	defer sess.Close()

	// Request attestation
	res, err := sess.Send(&request.Attestation{
		Nonce:     nonce,
		PublicKey: pubKeyBytes,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attestation from NSM: %w", err)
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, nil, fmt.Errorf("NSM returned empty attestation document")
	}

	return &Attestation{
		Document:  res.Attestation.Document,
		PublicKey: pubKeyBytes,
	}, privateKey, nil
}

func generateMockAttestationWithECDSA(nonce []byte) (*Attestation, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	pubKeyBytes := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)

	// Create mock attestation (same format as attestation.go)
	mockDoc := fmt.Sprintf(
		"MOCK_ATTESTATION:nonce=%x,pubkey=%x",
		nonce,
		pubKeyBytes,
	)

	return &Attestation{
		Document:  []byte(mockDoc),
		PublicKey: pubKeyBytes,
	}, privateKey, nil
}

// findEncryptedKeyInCMS extracts the RSA-encrypted key from a CMS EnvelopedData structure.
// AWS KMS returns CiphertextForRecipient as PKCS#7/CMS EnvelopedData (OID 1.2.840.113549.1.7.3).
// We search for the 256-byte OCTET STRING containing the RSA-encrypted DEK.
//
// CMS EnvelopedData structure:
// SEQUENCE {
//   contentType OID (1.2.840.113549.1.7.3)
//   [0] SEQUENCE (EnvelopedData) {
//     version INTEGER
//     recipientInfos SET {
//       KeyTransRecipientInfo SEQUENCE {
//         version INTEGER
//         rid (RecipientIdentifier)
//         keyEncryptionAlgorithm AlgorithmIdentifier
//         encryptedKey OCTET STRING  <-- 256 bytes for 2048-bit RSA
//       }
//     }
//     encryptedContentInfo SEQUENCE { ... }
//   }
// }
func findEncryptedKeyInCMS(data []byte) []byte {
	// Debug: log all OCTET STRING tags found in the data
	log.Debug().
		Int("data_len", len(data)).
		Hex("full_data", data).
		Msg("CMS data received for parsing")

	// Find all OCTET STRING (0x04) tags and their lengths
	for i := 0; i < len(data)-2; i++ {
		if data[i] == 0x04 {
			// Parse ASN.1 length
			length := 0
			headerLen := 0
			if data[i+1] < 0x80 {
				// Short form: length is the byte itself
				length = int(data[i+1])
				headerLen = 2
			} else if data[i+1] == 0x81 && i+2 < len(data) {
				// Long form: 1 byte length
				length = int(data[i+2])
				headerLen = 3
			} else if data[i+1] == 0x82 && i+3 < len(data) {
				// Long form: 2 byte length
				length = int(data[i+2])<<8 | int(data[i+3])
				headerLen = 4
			}
			if length > 0 && length <= len(data)-i-headerLen {
				log.Debug().
					Int("offset", i).
					Int("length", length).
					Int("header_len", headerLen).
					Msg("Found OCTET STRING in CMS")

				// If this looks like our RSA encrypted key (256 bytes for 2048-bit RSA)
				if length == 256 {
					start := i + headerLen
					end := start + 256
					if end <= len(data) {
						log.Info().
							Int("offset", i).
							Msg("Found 256-byte encrypted key OCTET STRING in CMS")
						return data[start:end]
					}
				}
			}
		}
	}

	// Search for specific patterns as fallback
	// 04 82 01 00 = OCTET STRING with 2-byte length 0x0100 (256)
	pattern := []byte{0x04, 0x82, 0x01, 0x00}

	for i := 0; i <= len(data)-len(pattern)-256; i++ {
		if data[i] == pattern[0] && data[i+1] == pattern[1] &&
			data[i+2] == pattern[2] && data[i+3] == pattern[3] {
			start := i + 4
			end := start + 256
			if end <= len(data) {
				log.Debug().
					Int("offset", i).
					Msg("Found encrypted key via pattern match")
				return data[start:end]
			}
		}
	}

	// Also try looking for 128-byte key (1024-bit RSA) in case of different key sizes
	// 04 81 80 = OCTET STRING with 1-byte length 0x80 (128)
	pattern128 := []byte{0x04, 0x81, 0x80}
	for i := 0; i <= len(data)-len(pattern128)-128; i++ {
		if data[i] == pattern128[0] && data[i+1] == pattern128[1] && data[i+2] == pattern128[2] {
			start := i + 3
			end := start + 128
			if end <= len(data) {
				log.Debug().
					Int("offset", i).
					Msg("Found 128-byte encrypted key OCTET STRING in CMS")
				return data[start:end]
			}
		}
	}

	log.Error().
		Int("data_len", len(data)).
		Hex("first_64_bytes", data[:min(64, len(data))]).
		Msg("Could not find encrypted key pattern in CMS data")

	return nil
}

// ============================================================================
// PIN-Based DEK Derivation (Architecture v2.0 Section 5.7)
// ============================================================================

// SealedMaterialData contains the KMS-sealed random material used for DEK derivation
type SealedMaterialData struct {
	Version        int    `json:"version"`
	SealedMaterial []byte `json:"sealed_material"` // KMS-sealed random bytes
	OwnerID        string `json:"owner_id"`        // User GUID (for key binding)
	CreatedAt      int64  `json:"created_at"`
}

// GenerateSealedMaterial creates new random material and seals it with KMS
// This is called during PIN setup (enrollment Phase 2)
// Returns the sealed material blob to be stored in S3
func (s *NitroSealer) GenerateSealedMaterial(ownerID string) ([]byte, error) {
	log.Info().Str("owner_id", ownerID).Msg("Generating sealed material for PIN-DEK derivation")

	// Generate 32 bytes of random material
	randomMaterial := make([]byte, 32)
	if _, err := rand.Read(randomMaterial); err != nil {
		return nil, fmt.Errorf("failed to generate random material: %w", err)
	}

	// Seal the material using KMS (this creates PCR-bound ciphertext)
	sealedData, err := s.Seal(randomMaterial)
	if err != nil {
		// Zero the material before returning
		for i := range randomMaterial {
			randomMaterial[i] = 0
		}
		return nil, fmt.Errorf("failed to seal material: %w", err)
	}

	// Zero the plaintext material
	for i := range randomMaterial {
		randomMaterial[i] = 0
	}

	// Wrap in SealedMaterialData for storage
	smData := SealedMaterialData{
		Version:        1,
		SealedMaterial: sealedData,
		OwnerID:        ownerID,
		CreatedAt:      getCurrentTimestamp(),
	}

	result, err := json.Marshal(smData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sealed material: %w", err)
	}

	log.Info().
		Str("owner_id", ownerID).
		Int("sealed_len", len(sealedData)).
		Msg("Sealed material generated successfully")

	return result, nil
}

// DeriveDEKFromPIN unseals the material and derives DEK using Argon2id
// This is called on vault load (app open) when user provides PIN
// Returns the 32-byte DEK for vault storage encryption
//
// Per Architecture v2.0 Section 4.6:
// DEK = Argon2id(PIN, salt=SHA256(owner_id || material)) followed by
// HKDF.Extract(material, stretched_pin) → vault_dek
func (s *NitroSealer) DeriveDEKFromPIN(sealedMaterialBlob []byte, pin string, ownerID string) ([]byte, error) {
	log.Debug().Str("owner_id", ownerID).Msg("Deriving DEK from PIN")

	// Parse sealed material blob
	var smData SealedMaterialData
	if err := json.Unmarshal(sealedMaterialBlob, &smData); err != nil {
		return nil, fmt.Errorf("failed to parse sealed material: %w", err)
	}

	// Verify owner ID matches (prevents cross-user attacks)
	if smData.OwnerID != ownerID {
		return nil, fmt.Errorf("sealed material owner mismatch")
	}

	// Unseal the random material using KMS/attestation
	randomMaterial, err := s.Unseal(smData.SealedMaterial)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal material: %w", err)
	}

	defer func() {
		// Zero the random material after use
		for i := range randomMaterial {
			randomMaterial[i] = 0
		}
	}()

	// Step 1: Compute salt = SHA256(owner_id || material)
	saltInput := append([]byte(ownerID), randomMaterial...)
	salt := sha256.Sum256(saltInput)
	// Zero the salt input
	for i := range saltInput {
		saltInput[i] = 0
	}

	// Step 2: Stretch PIN using Argon2id
	// Parameters match mobile apps: time=3, memory=256MB, threads=4
	stretchedPIN := argon2IDKey([]byte(pin), salt[:], 3, 256*1024, 4, 32)

	defer func() {
		// Zero stretched PIN after use
		for i := range stretchedPIN {
			stretchedPIN[i] = 0
		}
	}()

	// Step 3: Extract final DEK using HKDF
	// DEK = HKDF-Extract(salt=randomMaterial, IKM=stretchedPIN)
	dek := hkdfExtract(randomMaterial, stretchedPIN)

	log.Debug().
		Str("owner_id", ownerID).
		Msg("DEK derived from PIN successfully")

	return dek, nil
}

// VerifyPINWithDEK checks if the provided PIN produces the expected DEK
// This is used for PIN verification before vault operations
// Returns true if PIN is correct, false otherwise
func (s *NitroSealer) VerifyPINWithDEK(sealedMaterialBlob []byte, pin string, ownerID string, expectedDEKHash []byte) (bool, error) {
	dek, err := s.DeriveDEKFromPIN(sealedMaterialBlob, pin, ownerID)
	if err != nil {
		return false, err
	}

	defer func() {
		// Zero DEK after use
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Compare hash of derived DEK with expected hash
	actualHash := sha256.Sum256(dek)
	return constantTimeEqual(actualHash[:], expectedDEKHash), nil
}

// argon2IDKey wraps golang.org/x/crypto/argon2
func argon2IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	// This uses the same parameters as vault_lifecycle.go
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

// hkdfExtract performs HKDF-Extract (RFC 5869)
func hkdfExtract(salt, ikm []byte) []byte {
	h := hmacSHA256(salt, ikm)
	return h
}

// hmacSHA256 computes HMAC-SHA256
func hmacSHA256(key, data []byte) []byte {
	// Using crypto/hmac
	h := sha256.New
	mac := hmac.New(h, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// constantTimeEqual compares two byte slices in constant time
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// getCurrentTimestamp returns current Unix timestamp
func getCurrentTimestamp() int64 {
	return time.Now().Unix()
}
