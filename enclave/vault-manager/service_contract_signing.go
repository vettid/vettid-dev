package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// ContractSigningDomain is the HKDF info for contract signing keys
// This provides domain separation for contract-specific operations
const ContractSigningDomain = "vettid-contract-sign-v1"

// ContractSignature represents a cryptographic signature on a contract
type ContractSignature struct {
	SignerID          string    `json:"signer_id"`         // Vault GUID or Service GUID
	SignerType        string    `json:"signer_type"`       // "vault" or "service"
	SignerPublicKey   string    `json:"signer_public_key"` // Ed25519 public key (base64)
	ContractVersion   int       `json:"contract_version"`
	CanonicalHash     string    `json:"canonical_hash"`    // SHA-256 of canonical JSON
	Signature         string    `json:"signature"`         // Ed25519 signature (base64)
	SignedAt          time.Time `json:"signed_at"`
}

// SignedContract represents a contract with cryptographic proof of acceptance
type SignedContract struct {
	Contract         ServiceDataContract `json:"contract"`
	UserSignature    *ContractSignature  `json:"user_signature,omitempty"`
	ServiceSignature *ContractSignature  `json:"service_signature,omitempty"`
}

// --- Canonical JSON Functions ---

// CanonicalJSON produces a deterministic JSON representation of any value
// Keys are sorted alphabetically to ensure consistent hashing/signing
// This is critical for signature verification - both parties must produce
// identical canonical forms to verify each other's signatures.
func CanonicalJSON(v interface{}) ([]byte, error) {
	// First marshal to get standard JSON
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal failed: %w", err)
	}

	// Unmarshal into interface{} to get ordered processing
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}

	// Recursively sort and re-encode
	sorted := sortInterface(obj)
	return json.Marshal(sorted)
}

// sortInterface recursively sorts maps and processes arrays
func sortInterface(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		// Get sorted keys
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Create ordered map using custom encoder
		sorted := make(map[string]interface{})
		for _, k := range keys {
			sorted[k] = sortInterface(val[k])
		}
		return &orderedMap{keys: keys, m: sorted}

	case []interface{}:
		// Process array elements
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = sortInterface(item)
		}
		return result

	default:
		return v
	}
}

// orderedMap maintains key ordering during JSON encoding
type orderedMap struct {
	keys []string
	m    map[string]interface{}
}

// MarshalJSON produces JSON with keys in the specified order
func (om *orderedMap) MarshalJSON() ([]byte, error) {
	if len(om.keys) == 0 {
		return []byte("{}"), nil
	}

	result := []byte("{")
	for i, k := range om.keys {
		if i > 0 {
			result = append(result, ',')
		}

		// Marshal key
		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		result = append(result, keyBytes...)
		result = append(result, ':')

		// Marshal value
		valBytes, err := json.Marshal(om.m[k])
		if err != nil {
			return nil, err
		}
		result = append(result, valBytes...)
	}
	result = append(result, '}')

	return result, nil
}

// --- Contract Signing ---

// SignContract signs a service contract using the vault's Ed25519 identity key
// The signature covers the canonical JSON representation of the contract
// SECURITY: Requires vault to be unlocked (credential loaded in memory)
func SignContract(vaultState *VaultState, ownerSpace string, contract *ServiceDataContract) (*ContractSignature, error) {
	if vaultState == nil {
		return nil, fmt.Errorf("vault state is nil")
	}

	// Get credential with lock
	vaultState.mu.RLock()
	credential := vaultState.credential
	vaultState.mu.RUnlock()

	if credential == nil {
		return nil, fmt.Errorf("vault is locked - unlock with PIN first")
	}
	if len(credential.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid identity key length")
	}

	// Create canonical JSON of contract
	canonicalData, err := CanonicalJSON(contract)
	if err != nil {
		return nil, fmt.Errorf("canonical serialization failed: %w", err)
	}

	// Hash the canonical JSON
	hash := hashSHA256(canonicalData)
	hashB64 := base64.StdEncoding.EncodeToString(hash)

	// Create signing payload: "contract-sign-v1|{contract_id}|{version}|{hash}"
	// This format provides context and prevents signature confusion attacks
	signingPayload := fmt.Sprintf("contract-sign-v1|%s|%d|%s",
		contract.ContractID,
		contract.Version,
		hashB64,
	)

	// Sign with Ed25519
	signature := ed25519.Sign(credential.IdentityPrivateKey, []byte(signingPayload))

	// Get public key
	publicKey := credential.IdentityPublicKey
	if len(publicKey) == 0 {
		// Derive from private key if not stored
		publicKey = ed25519.PrivateKey(credential.IdentityPrivateKey).Public().(ed25519.PublicKey)
	}

	return &ContractSignature{
		SignerID:        ownerSpace,
		SignerType:      "vault",
		SignerPublicKey: base64.StdEncoding.EncodeToString(publicKey),
		ContractVersion: contract.Version,
		CanonicalHash:   hashB64,
		Signature:       base64.StdEncoding.EncodeToString(signature),
		SignedAt:        time.Now().UTC(),
	}, nil
}

// VerifyContractSignature verifies an Ed25519 signature on a contract
// Used to verify service signatures before accepting contracts
func VerifyContractSignature(contract *ServiceDataContract, sig *ContractSignature, expectedPublicKeyB64 string) error {
	// Decode public key
	publicKey, err := base64.StdEncoding.DecodeString(sig.SignerPublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key encoding: %w", err)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length: expected %d, got %d", ed25519.PublicKeySize, len(publicKey))
	}

	// Verify public key matches expected if provided
	if expectedPublicKeyB64 != "" && sig.SignerPublicKey != expectedPublicKeyB64 {
		return fmt.Errorf("public key mismatch")
	}

	// Create canonical JSON of contract
	canonicalData, err := CanonicalJSON(contract)
	if err != nil {
		return fmt.Errorf("canonical serialization failed: %w", err)
	}

	// Hash and verify
	hash := hashSHA256(canonicalData)
	hashB64 := base64.StdEncoding.EncodeToString(hash)

	if hashB64 != sig.CanonicalHash {
		return fmt.Errorf("contract hash mismatch: content may have been modified")
	}

	// Reconstruct signing payload
	signingPayload := fmt.Sprintf("contract-sign-v1|%s|%d|%s",
		contract.ContractID,
		contract.Version,
		sig.CanonicalHash,
	)

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: expected %d, got %d", ed25519.SignatureSize, len(signature))
	}

	// Verify Ed25519 signature
	if !ed25519.Verify(publicKey, []byte(signingPayload), signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// --- Challenge Signing for Auth Requests ---

// SignAuthChallenge signs an authentication challenge from a service
// This proves the vault owner's identity to the service
func SignAuthChallenge(vaultState *VaultState, ownerSpace string, challenge string, serviceGUID string) (string, string, error) {
	if vaultState == nil {
		return "", "", fmt.Errorf("vault state is nil")
	}

	vaultState.mu.RLock()
	credential := vaultState.credential
	vaultState.mu.RUnlock()

	if credential == nil {
		return "", "", fmt.Errorf("vault is locked")
	}
	if len(credential.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return "", "", fmt.Errorf("invalid identity key")
	}

	// Create signing payload with context
	// Format: "auth-challenge-v1|{service_guid}|{challenge}|{timestamp}"
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signingPayload := fmt.Sprintf("auth-challenge-v1|%s|%s|%s",
		serviceGUID,
		challenge,
		timestamp,
	)

	// Sign
	signature := ed25519.Sign(credential.IdentityPrivateKey, []byte(signingPayload))

	return base64.StdEncoding.EncodeToString(signature), timestamp, nil
}

// VerifyAuthChallengeSignature verifies a vault's response to an auth challenge
// Used by services to verify vault identity
func VerifyAuthChallengeSignature(challenge, serviceGUID, timestamp, signatureB64, publicKeyB64 string) error {
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	signingPayload := fmt.Sprintf("auth-challenge-v1|%s|%s|%s",
		serviceGUID,
		challenge,
		timestamp,
	)

	if !ed25519.Verify(publicKey, []byte(signingPayload), signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}
