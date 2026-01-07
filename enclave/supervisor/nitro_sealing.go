package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/rs/zerolog/log"
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
	// KMS returns CiphertextForRecipient - the DEK encrypted to our RSA public key
	ciphertextForRecipient, err := s.kmsDecrypt(sealed.EncryptedDEK, attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK with KMS: %w", err)
	}

	// 3. Decrypt CiphertextForRecipient with our RSA private key to get DEK
	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertextForRecipient, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK from KMS response: %w", err)
	}
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

	// The payload contains CiphertextForRecipient
	return response.Payload, nil
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
