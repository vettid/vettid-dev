package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// S3 operation timeout
const s3OperationTimeout = 30 * time.Second

// SealerHandler handles sealer requests from vault-manager processes.
// The vault-manager cannot directly access KMS or S3 - it must proxy through the supervisor.
type SealerHandler struct {
	sealer     *NitroSealer
	parentConn Connection // Direct connection to parent for S3 operations
	connMu     sync.Mutex // Mutex for connection access
}

// NewSealerHandler creates a new sealer handler
func NewSealerHandler(sealer *NitroSealer) *SealerHandler {
	return &SealerHandler{
		sealer: sealer,
	}
}

// SetParentConnection sets the connection for S3 storage operations
func (sh *SealerHandler) SetParentConnection(conn Connection) {
	sh.connMu.Lock()
	defer sh.connMu.Unlock()
	sh.parentConn = conn
}

// --- Message types for sealer proxy operations ---

// MessageType constants for sealer operations
const (
	MessageTypeSealerRequest  MessageType = "sealer_request"
	MessageTypeSealerResponse MessageType = "sealer_response"
)

// SealerOperation identifies the sealing operation to perform
type SealerOperation string

const (
	SealerOpGenerateSealedMaterial SealerOperation = "generate_sealed_material"
	SealerOpDeriveDEKFromPIN       SealerOperation = "derive_dek_from_pin"
	SealerOpSealCredential         SealerOperation = "seal_credential"
	SealerOpUnsealCredential       SealerOperation = "unseal_credential"
	// S3 storage operations for vault state persistence
	SealerOpStoreSealedMaterial SealerOperation = "store_sealed_material"
	SealerOpLoadSealedMaterial  SealerOperation = "load_sealed_material"
	SealerOpStoreVaultState     SealerOperation = "store_vault_state"
	SealerOpLoadVaultState      SealerOperation = "load_vault_state"
	SealerOpStoreSealedECIES    SealerOperation = "store_sealed_ecies"
	SealerOpLoadSealedECIES     SealerOperation = "load_sealed_ecies"
)

// SealerRequest is received from vault-manager
type SealerRequest struct {
	Operation  SealerOperation `json:"operation"`
	OwnerSpace string          `json:"owner_space"`

	// For derive_dek_from_pin
	SealedMaterial []byte `json:"sealed_material,omitempty"`
	PIN            []byte `json:"pin,omitempty"` // SECURITY: []byte so it can be zeroed after use

	// For seal_credential / unseal_credential
	Data []byte `json:"data,omitempty"`
}

// SealerResponse is sent back to vault-manager
type SealerResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`

	// For generate_sealed_material
	SealedMaterial []byte `json:"sealed_material,omitempty"`

	// For derive_dek_from_pin
	DEK []byte `json:"dek,omitempty"`

	// For seal_credential
	SealedData []byte `json:"sealed_data,omitempty"`

	// For unseal_credential
	UnsealedData []byte `json:"unsealed_data,omitempty"`
}

// HandleSealerRequest processes a sealer request from vault-manager
func (sh *SealerHandler) HandleSealerRequest(msg *Message) *Message {
	var req SealerRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return sh.errorResponse(msg.RequestID, fmt.Sprintf("invalid sealer request: %v", err))
	}

	log.Debug().
		Str("operation", string(req.Operation)).
		Str("owner_space", req.OwnerSpace).
		Msg("Processing sealer request")

	var resp SealerResponse

	switch req.Operation {
	case SealerOpGenerateSealedMaterial:
		resp = sh.generateSealedMaterial(req)
	case SealerOpDeriveDEKFromPIN:
		resp = sh.deriveDEKFromPIN(req)
	case SealerOpSealCredential:
		resp = sh.sealCredential(req)
	case SealerOpUnsealCredential:
		resp = sh.unsealCredential(req)
	// S3 storage operations
	case SealerOpStoreSealedMaterial:
		resp = sh.storeSealedMaterial(req)
	case SealerOpLoadSealedMaterial:
		resp = sh.loadSealedMaterial(req)
	case SealerOpStoreVaultState:
		resp = sh.storeVaultState(req)
	case SealerOpLoadVaultState:
		resp = sh.loadVaultState(req)
	case SealerOpStoreSealedECIES:
		resp = sh.storeSealedECIES(req)
	case SealerOpLoadSealedECIES:
		resp = sh.loadSealedECIES(req)
	default:
		resp = SealerResponse{
			Success: false,
			Error:   fmt.Sprintf("unknown sealer operation: %s", req.Operation),
		}
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		return sh.errorResponse(msg.RequestID, "failed to marshal response")
	}

	return &Message{
		RequestID: msg.RequestID,
		Type:      MessageTypeSealerResponse,
		Payload:   respBytes,
	}
}

// generateSealedMaterial creates new PCR-bound sealed material
func (sh *SealerHandler) generateSealedMaterial(req SealerRequest) SealerResponse {
	if sh.sealer == nil {
		// Dev mode - return mock sealed material
		log.Warn().Msg("No sealer available, returning mock sealed material")
		return SealerResponse{
			Success:        true,
			SealedMaterial: []byte("mock-sealed-material-for-dev"),
		}
	}

	sealedMaterial, err := sh.sealer.GenerateSealedMaterial(req.OwnerSpace)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate sealed material")
		return SealerResponse{
			Success: false,
			Error:   "failed to generate sealed material",
		}
	}

	return SealerResponse{
		Success:        true,
		SealedMaterial: sealedMaterial,
	}
}

// deriveDEKFromPIN derives the DEK from PIN + sealed material
// SECURITY: PIN is received as []byte and zeroed after use
func (sh *SealerHandler) deriveDEKFromPIN(req SealerRequest) SealerResponse {
	// SECURITY: Zero PIN after processing (regardless of success/failure)
	defer zeroBytes(req.PIN)

	if sh.sealer == nil {
		// Dev mode - return mock DEK
		log.Warn().Msg("No sealer available, returning mock DEK")
		return SealerResponse{
			Success: true,
			DEK:     make([]byte, 32), // Zero key for dev
		}
	}

	dek, err := sh.sealer.DeriveDEKFromPIN(req.SealedMaterial, req.PIN, req.OwnerSpace)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive DEK from PIN")
		return SealerResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to derive DEK: %v", err),
		}
	}

	return SealerResponse{
		Success: true,
		DEK:     dek,
	}
}

// zeroBytes overwrites a byte slice with zeros
// SECURITY: Used to clear sensitive data from memory
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// sealCredential seals data using Nitro KMS
func (sh *SealerHandler) sealCredential(req SealerRequest) SealerResponse {
	if sh.sealer == nil {
		// Dev mode - return data as-is (no encryption)
		log.Warn().Msg("No sealer available, returning unencrypted data")
		return SealerResponse{
			Success:    true,
			SealedData: req.Data,
		}
	}

	sealed, err := sh.sealer.Seal(req.Data)
	if err != nil {
		log.Error().Err(err).Msg("Failed to seal credential")
		return SealerResponse{
			Success: false,
			Error:   "failed to seal credential",
		}
	}

	return SealerResponse{
		Success:    true,
		SealedData: sealed,
	}
}

// unsealCredential unseals data using Nitro KMS
func (sh *SealerHandler) unsealCredential(req SealerRequest) SealerResponse {
	if sh.sealer == nil {
		// Dev mode - return data as-is (no decryption)
		log.Warn().Msg("No sealer available, returning data as-is")
		return SealerResponse{
			Success:      true,
			UnsealedData: req.Data,
		}
	}

	unsealed, err := sh.sealer.Unseal(req.Data)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unseal credential")
		return SealerResponse{
			Success: false,
			Error:   "failed to unseal credential",
		}
	}

	return SealerResponse{
		Success:      true,
		UnsealedData: unsealed,
	}
}

func (sh *SealerHandler) errorResponse(requestID string, errMsg string) *Message {
	resp := SealerResponse{
		Success: false,
		Error:   errMsg,
	}
	respBytes, _ := json.Marshal(resp)
	return &Message{
		RequestID: requestID,
		Type:      MessageTypeSealerResponse,
		Payload:   respBytes,
	}
}

// S3 storage key helpers
func s3KeySealedMaterial(ownerSpace string) string {
	return fmt.Sprintf("vaults/%s/sealed_material.bin", ownerSpace)
}

func s3KeyVaultState(ownerSpace string) string {
	return fmt.Sprintf("vaults/%s/vault_state.enc", ownerSpace)
}

func s3KeySealedECIES(ownerSpace string) string {
	return fmt.Sprintf("vaults/%s/sealed_ecies.bin", ownerSpace)
}

// s3Put stores data to S3 via parent connection (synchronous request/response)
func (sh *SealerHandler) s3Put(key string, data []byte) error {
	sh.connMu.Lock()
	defer sh.connMu.Unlock()

	if sh.parentConn == nil {
		log.Warn().Str("key", key).Msg("No parent connection for S3 PUT - dev mode")
		return nil // Dev mode - pretend it worked
	}

	msg := &Message{
		Type:         MessageTypeStoragePut,
		StorageKey:   key,
		StorageValue: data, // Use StorageValue ([]byte) instead of Payload (json.RawMessage) for binary data
	}

	if err := sh.parentConn.WriteMessage(msg); err != nil {
		return fmt.Errorf("failed to send S3 PUT request: %w", err)
	}

	// Wait for response
	response, err := sh.parentConn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read S3 PUT response: %w", err)
	}

	if response.Type == MessageTypeError {
		return fmt.Errorf("S3 PUT error: %s", response.Error)
	}

	if response.Type != MessageTypeStorageResponse && response.Type != MessageTypeOK {
		return fmt.Errorf("unexpected response type for S3 PUT: %s", response.Type)
	}

	return nil
}

// s3Get retrieves data from S3 via parent connection (synchronous request/response)
func (sh *SealerHandler) s3Get(key string) ([]byte, error) {
	sh.connMu.Lock()
	defer sh.connMu.Unlock()

	if sh.parentConn == nil {
		log.Warn().Str("key", key).Msg("No parent connection for S3 GET - dev mode")
		return nil, fmt.Errorf("no S3 connection available")
	}

	msg := &Message{
		Type:       MessageTypeStorageGet,
		StorageKey: key,
	}

	if err := sh.parentConn.WriteMessage(msg); err != nil {
		return nil, fmt.Errorf("failed to send S3 GET request: %w", err)
	}

	// Wait for response
	response, err := sh.parentConn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to read S3 GET response: %w", err)
	}

	if response.Type == MessageTypeError {
		return nil, fmt.Errorf("S3 GET error: %s", response.Error)
	}

	if response.Type != MessageTypeStorageResponse {
		return nil, fmt.Errorf("unexpected response type for S3 GET: %s", response.Type)
	}

	// Data is in Payload or StorageValue
	if len(response.Payload) > 0 {
		return response.Payload, nil
	}
	return response.StorageValue, nil
}

// storeSealedMaterial stores sealed material to S3 via parent
func (sh *SealerHandler) storeSealedMaterial(req SealerRequest) SealerResponse {
	key := s3KeySealedMaterial(req.OwnerSpace)
	log.Info().Str("owner_space", req.OwnerSpace).Str("key", key).Msg("Storing sealed material to S3")

	if err := sh.s3Put(key, req.Data); err != nil {
		log.Error().Err(err).Msg("Failed to store sealed material to S3")
		return SealerResponse{Success: false, Error: err.Error()}
	}

	log.Info().Str("owner_space", req.OwnerSpace).Msg("Sealed material stored to S3 successfully")
	return SealerResponse{Success: true}
}

// loadSealedMaterial loads sealed material from S3 via parent
func (sh *SealerHandler) loadSealedMaterial(req SealerRequest) SealerResponse {
	key := s3KeySealedMaterial(req.OwnerSpace)
	log.Info().Str("owner_space", req.OwnerSpace).Str("key", key).Msg("Loading sealed material from S3")

	data, err := sh.s3Get(key)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load sealed material from S3")
		return SealerResponse{Success: false, Error: err.Error()}
	}

	log.Info().Str("owner_space", req.OwnerSpace).Int("data_len", len(data)).Msg("Sealed material loaded from S3 successfully")
	return SealerResponse{Success: true, SealedMaterial: data}
}

// storeVaultState stores encrypted vault state to S3 via parent
func (sh *SealerHandler) storeVaultState(req SealerRequest) SealerResponse {
	key := s3KeyVaultState(req.OwnerSpace)
	log.Info().Str("owner_space", req.OwnerSpace).Str("key", key).Msg("Storing vault state to S3")

	if err := sh.s3Put(key, req.Data); err != nil {
		log.Error().Err(err).Msg("Failed to store vault state to S3")
		return SealerResponse{Success: false, Error: err.Error()}
	}

	log.Info().Str("owner_space", req.OwnerSpace).Msg("Vault state stored to S3 successfully")
	return SealerResponse{Success: true}
}

// loadVaultState loads encrypted vault state from S3 via parent
func (sh *SealerHandler) loadVaultState(req SealerRequest) SealerResponse {
	key := s3KeyVaultState(req.OwnerSpace)
	log.Info().Str("owner_space", req.OwnerSpace).Str("key", key).Msg("Loading vault state from S3")

	data, err := sh.s3Get(key)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load vault state from S3")
		return SealerResponse{Success: false, Error: err.Error()}
	}

	log.Info().Str("owner_space", req.OwnerSpace).Int("data_len", len(data)).Msg("Vault state loaded from S3 successfully")
	// Return in UnsealedData field (reusing existing field)
	return SealerResponse{Success: true, UnsealedData: data}
}

// storeSealedECIES stores KMS-sealed ECIES keys to S3 via parent
func (sh *SealerHandler) storeSealedECIES(req SealerRequest) SealerResponse {
	key := s3KeySealedECIES(req.OwnerSpace)
	log.Info().Str("owner_space", req.OwnerSpace).Str("key", key).Msg("Storing sealed ECIES keys to S3")

	if err := sh.s3Put(key, req.Data); err != nil {
		log.Error().Err(err).Msg("Failed to store sealed ECIES keys to S3")
		return SealerResponse{Success: false, Error: err.Error()}
	}

	log.Info().Str("owner_space", req.OwnerSpace).Msg("Sealed ECIES keys stored to S3 successfully")
	return SealerResponse{Success: true}
}

// loadSealedECIES loads KMS-sealed ECIES keys from S3 via parent
func (sh *SealerHandler) loadSealedECIES(req SealerRequest) SealerResponse {
	key := s3KeySealedECIES(req.OwnerSpace)
	log.Info().Str("owner_space", req.OwnerSpace).Str("key", key).Msg("Loading sealed ECIES keys from S3")

	data, err := sh.s3Get(key)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load sealed ECIES keys from S3")
		return SealerResponse{Success: false, Error: err.Error()}
	}

	log.Info().Str("owner_space", req.OwnerSpace).Int("data_len", len(data)).Msg("Sealed ECIES keys loaded from S3 successfully")
	// Return in SealedData field (reusing existing field)
	return SealerResponse{Success: true, SealedData: data}
}
