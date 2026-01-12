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

	// AWS KMS CiphertextForRecipient is CMS EnvelopedData with TWO stages of encryption:
	// 1. RSA-encrypted CEK (Content Encryption Key) - 256 bytes for 2048-bit RSA
	// 2. AES-256-GCM encrypted content (our DEK) using the CEK
	//
	// We must:
	// 1. Parse the CMS structure to extract encrypted key, IV, and encrypted content
	// 2. RSA decrypt the encrypted key to get the CEK
	// 3. Use CEK + IV to AES-GCM decrypt the content to get our actual DEK
	cms, err := parseCMSEnvelopedData(ciphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CMS envelope: %w", err)
	}

	log.Debug().
		Int("encrypted_key_len", len(cms.EncryptedKey)).
		Int("iv_len", len(cms.ContentIV)).
		Int("content_len", len(cms.EncryptedContent)).
		Msg("Parsed CMS EnvelopedData structure")

	// Stage 1: Decrypt the CEK (Content Encryption Key) with RSA-OAEP-SHA256
	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cms.EncryptedKey, nil)
	if err != nil {
		// Try PKCS1v15 as fallback
		cek, err = rsa.DecryptPKCS1v15(rand.Reader, privateKey, cms.EncryptedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt CEK from CMS: %w", err)
		}
		log.Debug().Msg("Decrypted CEK using RSA PKCS1v15")
	} else {
		log.Debug().Msg("Decrypted CEK using RSA-OAEP-SHA256")
	}

	log.Debug().
		Int("cek_len", len(cek)).
		Msg("Successfully decrypted CEK (Content Encryption Key)")

	// Stage 2: Decrypt the content with CEK to get our actual DEK
	dek, err := decryptCMSContent(cms, cek)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK from CMS content: %w", err)
	}

	// Zero out CEK after use
	for i := range cek {
		cek[i] = 0
	}

	log.Debug().
		Int("dek_len", len(dek)).
		Msg("Successfully extracted DEK from CMS EnvelopedData")

	// Log sealed data for comparison
	log.Debug().
		Int("nonce_len", len(sealed.Nonce)).
		Int("ciphertext_len", len(sealed.Ciphertext)).
		Int("encrypted_dek_len", len(sealed.EncryptedDEK)).
		Hex("nonce", sealed.Nonce).
		Hex("encrypted_dek_first_8", sealed.EncryptedDEK[:min(8, len(sealed.EncryptedDEK))]).
		Msg("Sealed data details")

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

	// Validate CiphertextForRecipient was received
	if len(response.Ciphertext) == 0 {
		log.Error().
			Int("payload_len", len(response.Payload)).
			Bool("has_error", response.Error != "").
			Str("error", response.Error).
			Msg("KMS response has empty Ciphertext field")
		return nil, fmt.Errorf("KMS response missing CiphertextForRecipient (ciphertext field empty)")
	}

	log.Debug().
		Int("ciphertext_len", len(response.Ciphertext)).
		Msg("KMS decrypt response received with CiphertextForRecipient")

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

// CMSEnvelopedData holds the parsed components of a CMS EnvelopedData structure
type CMSEnvelopedData struct {
	EncryptedKey      []byte // RSA-encrypted CEK (Content Encryption Key)
	ContentIV         []byte // IV/nonce for content decryption
	EncryptedContent  []byte // Content encrypted with CEK (our DEK is inside)
}

// parseCMSEnvelopedData extracts all necessary parts from a CMS EnvelopedData structure.
// AWS KMS returns CiphertextForRecipient as PKCS#7/CMS EnvelopedData.
// The structure contains:
// - RecipientInfo with RSA-encrypted CEK (Content Encryption Key)
// - EncryptedContentInfo with AES-256-GCM encrypted content (our DEK)
func parseCMSEnvelopedData(data []byte) (*CMSEnvelopedData, error) {
	result := &CMSEnvelopedData{}

	log.Debug().
		Int("cms_len", len(data)).
		Hex("cms_first_32", data[:min(32, len(data))]).
		Msg("Parsing CMS EnvelopedData")

	// Find the 256-byte RSA-encrypted key (OCTET STRING with length 256)
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 0x04 && data[i+1] == 0x82 && data[i+2] == 0x01 && data[i+3] == 0x00 {
			// Found OCTET STRING with length 0x0100 (256)
			start := i + 4
			if start+256 <= len(data) {
				result.EncryptedKey = data[start : start+256]
				log.Debug().
					Int("offset", i).
					Int("key_len", len(result.EncryptedKey)).
					Msg("Found RSA-encrypted CEK in CMS")
			}
			break
		}
	}

	if result.EncryptedKey == nil {
		return nil, fmt.Errorf("failed to find RSA-encrypted key in CMS")
	}

	// Find AES-256-CBC OID (2.16.840.1.101.3.4.1.42) = 0x06 0x09 0x60 0x86 0x48 0x01 0x65 0x03 0x04 0x01 0x2a
	// AWS KMS uses AES-CBC for CiphertextForRecipient, not AES-GCM
	aesCBCOID := []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a}

	var ivPos int
	for i := 0; i < len(data)-len(aesCBCOID)-16; i++ {
		match := true
		for j := 0; j < len(aesCBCOID); j++ {
			if data[i+j] != aesCBCOID[j] {
				match = false
				break
			}
		}
		if match {
			// Found AES-CBC OID, IV follows after OCTET STRING header (04 10 = 16 bytes)
			ivPos = i + len(aesCBCOID)
			if ivPos+2 < len(data) && data[ivPos] == 0x04 && data[ivPos+1] == 0x10 {
				// OCTET STRING with 16 bytes
				result.ContentIV = data[ivPos+2 : ivPos+2+16]
				log.Debug().
					Int("iv_offset", ivPos+2).
					Hex("iv", result.ContentIV).
					Msg("Found content IV in CMS")
			}
			break
		}
	}

	if result.ContentIV == nil {
		return nil, fmt.Errorf("failed to find content IV in CMS")
	}

	// Find encrypted content - it's in a context-specific [0] tag after the IV
	// Look for a0 80 04 (indefinite [0] with OCTET STRING) or a0 8X XX (definite)
	for i := ivPos + 2 + 16; i < len(data)-4; i++ {
		if data[i] == 0xa0 { // context-specific [0]
			contentStart := i + 1
			// Check for indefinite length (0x80) or definite
			if data[i+1] == 0x80 {
				// Indefinite length, look for OCTET STRING inside
				contentStart = i + 2
				if data[contentStart] == 0x04 {
					length := 0
					if data[contentStart+1] < 0x80 {
						length = int(data[contentStart+1])
						result.EncryptedContent = data[contentStart+2 : contentStart+2+length]
					} else if data[contentStart+1] == 0x81 {
						length = int(data[contentStart+2])
						result.EncryptedContent = data[contentStart+3 : contentStart+3+length]
					}
				}
			} else if data[i+1] < 0x80 {
				// Short definite length
				length := int(data[i+1])
				contentStart = i + 2
				result.EncryptedContent = data[contentStart : contentStart+length]
			}
			if len(result.EncryptedContent) > 0 {
				log.Debug().
					Int("content_len", len(result.EncryptedContent)).
					Hex("content_first_16", result.EncryptedContent[:min(16, len(result.EncryptedContent))]).
					Msg("Found encrypted content in CMS")
				break
			}
		}
	}

	if result.EncryptedContent == nil {
		return nil, fmt.Errorf("failed to find encrypted content in CMS")
	}

	return result, nil
}

// decryptCMSContent decrypts the content from CMS using the CEK
// AWS KMS CiphertextForRecipient uses AES-CBC with PKCS#7 padding (not GCM!)
// Returns the plaintext (our DEK)
func decryptCMSContent(cms *CMSEnvelopedData, cek []byte) ([]byte, error) {
	log.Debug().
		Int("cek_len", len(cek)).
		Int("iv_len", len(cms.ContentIV)).
		Int("content_len", len(cms.EncryptedContent)).
		Msg("Decrypting CMS content with AES-CBC")

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher for CMS content: %w", err)
	}

	// AWS KMS uses AES-CBC, not AES-GCM
	if len(cms.ContentIV) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV length for AES-CBC: got %d, expected %d", len(cms.ContentIV), aes.BlockSize)
	}

	if len(cms.EncryptedContent)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("encrypted content length %d is not a multiple of block size", len(cms.EncryptedContent))
	}

	// Decrypt with CBC mode
	mode := cipher.NewCBCDecrypter(block, cms.ContentIV)
	plaintext := make([]byte, len(cms.EncryptedContent))
	mode.CryptBlocks(plaintext, cms.EncryptedContent)

	// Remove PKCS#7 padding
	plaintext, err = removePKCS7Padding(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to remove PKCS#7 padding: %w", err)
	}

	log.Debug().
		Int("plaintext_len", len(plaintext)).
		Msg("CMS content decrypted successfully")

	return plaintext, nil
}

// removePKCS7Padding removes PKCS#7 padding from decrypted data
func removePKCS7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	paddingLen := int(data[len(data)-1])
	if paddingLen == 0 || paddingLen > aes.BlockSize || paddingLen > len(data) {
		return nil, fmt.Errorf("invalid padding length: %d", paddingLen)
	}

	// Verify all padding bytes are correct
	for i := len(data) - paddingLen; i < len(data); i++ {
		if data[i] != byte(paddingLen) {
			return nil, fmt.Errorf("invalid padding byte at position %d", i)
		}
	}

	return data[:len(data)-paddingLen], nil
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
