package main

import (
	"crypto/sha256"
	"encoding/base64"
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
	// NATS account seed (fetched from DynamoDB via parent)
	SealerOpLoadAccountSeed SealerOperation = "load_account_seed"
	// Invitation broker (resolved from NATS JetStream via parent)
	SealerOpResolveInvite SealerOperation = "resolve_invite"
	// Proposals list (fetched from DynamoDB via parent)
	SealerOpListProposals SealerOperation = "list_proposals"
	// Vault-mediated vote submission (parent writes to DynamoDB)
	SealerOpSubmitSignedVote SealerOperation = "submit_signed_vote"
	// Vote inclusion proof (parent reads from S3 published votes)
	SealerOpGetVoteProof SealerOperation = "get_vote_proof"
	// Migration config (fetched from S3 via parent)
	SealerOpFetchMigrationConfig SealerOperation = "fetch_migration_config"
	// Migration marker (written to unencrypted S3 path after user migration completes)
	SealerOpWriteMigrationMarker SealerOperation = "write_migration_marker"
	// TURN credentials (parent fetches Secrets Manager + generates HMAC creds)
	SealerOpGetTurnCredentials SealerOperation = "get_turn_credentials"
	SealerOpUnsealMaterial     SealerOperation = "unseal_material"
	// PCR signing public key fetch (parent calls KMS GetPublicKey on
	// the pcr-signing key, returns DER-encoded SPKI bytes). Used by
	// the migration handler to verify config signatures.
	SealerOpFetchPCRSigningPublicKey SealerOperation = "fetch_pcr_signing_public_key"
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

	// For resolve_invite
	InviteCode string `json:"invite_code,omitempty"`

	// For write_migration_marker
	MigrationVersion string `json:"migration_version,omitempty"`

	// For submit_signed_vote: full vote-submission envelope as JSON.
	VoteSubmitPayload []byte `json:"vote_submit_payload,omitempty"`

	// For get_vote_proof
	ProposalID      string `json:"proposal_id,omitempty"`
	VotingPublicKey string `json:"voting_public_key,omitempty"`
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

	// For load_account_seed
	AccountSeed string `json:"account_seed,omitempty"`

	// For resolve_invite
	InviteData []byte `json:"invite_data,omitempty"`

	// For list_proposals
	ProposalsData []byte `json:"proposals_data,omitempty"`

	// For submit_signed_vote: { success: bool, already_voted: bool, error: string }
	VoteSubmitResult []byte `json:"vote_submit_result,omitempty"`

	// For get_vote_proof: full proof JSON (see VoteProofResponse in parent)
	VoteProofData []byte `json:"vote_proof_data,omitempty"`

	// For fetch_migration_config
	MigrationConfig []byte `json:"migration_config,omitempty"`

	// For get_turn_credentials (opaque JSON returned by parent)
	TurnCredentials []byte `json:"turn_credentials,omitempty"`

	// For fetch_pcr_signing_public_key (DER-encoded SPKI bytes)
	PCRSigningPublicKey []byte `json:"pcr_signing_public_key,omitempty"`

	// For internal sign-with-PCR-signing-key calls (used by the
	// migration-marker writer). Caller embeds the bytes in the
	// outbound JSON; not surfaced to vault-manager.
	Signature []byte `json:"-"`
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
	case SealerOpLoadAccountSeed:
		resp = sh.loadAccountSeed(req)
	case SealerOpResolveInvite:
		resp = sh.resolveInvite(req)
	case SealerOpListProposals:
		resp = sh.listProposals(req)
	case SealerOpSubmitSignedVote:
		resp = sh.submitSignedVote(req)
	case SealerOpGetVoteProof:
		resp = sh.getVoteProof(req)
	case SealerOpFetchMigrationConfig:
		resp = sh.fetchMigrationConfig(req)
	case SealerOpWriteMigrationMarker:
		resp = sh.writeMigrationMarker(req)
	case SealerOpGetTurnCredentials:
		resp = sh.getTurnCredentials(req)
	case SealerOpUnsealMaterial:
		resp = sh.unsealMaterial(req)
	case SealerOpFetchPCRSigningPublicKey:
		resp = sh.fetchPCRSigningPublicKey(req)
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
// unsealMaterial unseals the inner sealed material from a full SealedMaterialData blob.
// Used by migration to re-seal without deriving DEK.
func (sh *SealerHandler) unsealMaterial(req SealerRequest) SealerResponse {
	if sh.sealer == nil {
		log.Warn().Msg("No sealer available, returning data as-is")
		return SealerResponse{
			Success:      true,
			UnsealedData: req.SealedMaterial,
		}
	}

	// Parse the outer wrapper (same format as DeriveDEKFromPIN)
	var smData SealedMaterialData
	if err := json.Unmarshal(req.SealedMaterial, &smData); err != nil {
		log.Error().Err(err).Msg("Failed to parse sealed material blob")
		return SealerResponse{
			Success: false,
			Error:   "failed to parse sealed material blob",
		}
	}

	// Unseal the inner sealed data using KMS attestation
	unsealed, err := sh.sealer.Unseal(smData.SealedMaterial)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unseal material")
		return SealerResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to unseal material: %v", err),
		}
	}

	return SealerResponse{
		Success:      true,
		UnsealedData: unsealed,
	}
}

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

// loadAccountSeed fetches the NATS account seed from the parent process.
// The parent reads it from DynamoDB and decrypts via KMS.
func (sh *SealerHandler) loadAccountSeed(req SealerRequest) SealerResponse {
	sh.connMu.Lock()
	defer sh.connMu.Unlock()

	if sh.parentConn == nil {
		log.Warn().Str("owner_space", req.OwnerSpace).Msg("No parent connection for account seed - dev mode")
		return SealerResponse{Success: false, Error: "no parent connection available"}
	}

	log.Info().Str("owner_space", req.OwnerSpace).Msg("Requesting NATS account seed from parent")

	msg := &Message{
		Type:       MessageTypeNATSAccountSeedGet,
		OwnerSpace: req.OwnerSpace,
	}

	if err := sh.parentConn.WriteMessage(msg); err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to send account seed request: %v", err)}
	}

	// Wait for response from parent
	response, err := sh.parentConn.ReadMessage()
	if err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to read account seed response: %v", err)}
	}

	if response.Type == MessageTypeError {
		return SealerResponse{Success: false, Error: fmt.Sprintf("parent error: %s", response.Error)}
	}

	if response.Type != MessageTypeNATSAccountSeedResponse {
		return SealerResponse{Success: false, Error: fmt.Sprintf("unexpected response type: %s", response.Type)}
	}

	// Parse the account seed from the response payload
	var seedResp struct {
		AccountSeed string `json:"account_seed"`
		Error       string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(response.Payload, &seedResp); err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to parse seed response: %v", err)}
	}

	if seedResp.Error != "" {
		return SealerResponse{Success: false, Error: seedResp.Error}
	}

	if seedResp.AccountSeed == "" {
		return SealerResponse{Success: false, Error: "empty account seed from parent"}
	}

	log.Info().Str("owner_space", req.OwnerSpace).Msg("NATS account seed received from parent")
	return SealerResponse{Success: true, AccountSeed: seedResp.AccountSeed}
}

// resolveInvite fetches invitation data from the parent's NATS JetStream INVITATIONS stream.
func (sh *SealerHandler) resolveInvite(req SealerRequest) SealerResponse {
	sh.connMu.Lock()
	defer sh.connMu.Unlock()

	if sh.parentConn == nil {
		return SealerResponse{Success: false, Error: "no parent connection available"}
	}

	log.Info().Str("invite_code", req.InviteCode).Msg("Resolving invitation via parent")

	msg := &Message{
		Type:    MessageTypeInviteResolve,
		Subject: req.InviteCode,
	}

	if err := sh.parentConn.WriteMessage(msg); err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to send invite resolve request: %v", err)}
	}

	response, err := sh.parentConn.ReadMessage()
	if err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to read invite resolve response: %v", err)}
	}

	if response.Type == MessageTypeError {
		return SealerResponse{Success: false, Error: fmt.Sprintf("parent error: %s", response.Error)}
	}

	if response.Type != MessageTypeInviteResponse {
		return SealerResponse{Success: false, Error: fmt.Sprintf("unexpected response type: %s", response.Type)}
	}

	// Check for error in payload
	var check struct {
		Error string `json:"error,omitempty"`
	}
	if json.Unmarshal(response.Payload, &check) == nil && check.Error != "" {
		return SealerResponse{Success: false, Error: check.Error}
	}

	log.Info().Str("invite_code", req.InviteCode).Int("payload_len", len(response.Payload)).Msg("Invitation resolved from parent")
	return SealerResponse{Success: true, InviteData: response.Payload}
}

// submitSignedVote forwards a vault-signed vote payload to the parent for
// validation + DynamoDB write. Idempotency is the parent's responsibility:
// duplicate (proposal_id, voting_public_key) returns success with
// already_voted=true so the vault can drop a queued retry.
func (sh *SealerHandler) submitSignedVote(req SealerRequest) SealerResponse {
	sh.connMu.Lock()
	defer sh.connMu.Unlock()

	if sh.parentConn == nil {
		return SealerResponse{Success: false, Error: "no parent connection available"}
	}
	if len(req.VoteSubmitPayload) == 0 {
		return SealerResponse{Success: false, Error: "empty vote submit payload"}
	}

	msg := &Message{
		Type:    MessageTypeVoteSubmit,
		Payload: req.VoteSubmitPayload,
	}
	if err := sh.parentConn.WriteMessage(msg); err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to send vote submit: %v", err)}
	}
	resp, err := sh.parentConn.ReadMessage()
	if err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to read vote submit response: %v", err)}
	}
	if resp.Type != MessageTypeVoteSubmitResponse {
		return SealerResponse{Success: false, Error: fmt.Sprintf("unexpected response type: %s", resp.Type)}
	}
	return SealerResponse{Success: true, VoteSubmitResult: resp.Payload}
}

// getVoteProof fetches a Merkle inclusion proof from the parent (which reads
// from the published-votes S3 bucket). The vault verifies the proof locally.
func (sh *SealerHandler) getVoteProof(req SealerRequest) SealerResponse {
	sh.connMu.Lock()
	defer sh.connMu.Unlock()

	if sh.parentConn == nil {
		return SealerResponse{Success: false, Error: "no parent connection available"}
	}
	if req.ProposalID == "" || req.VotingPublicKey == "" {
		return SealerResponse{Success: false, Error: "proposal_id and voting_public_key required"}
	}

	body, err := json.Marshal(map[string]string{
		"proposal_id":       req.ProposalID,
		"voting_public_key": req.VotingPublicKey,
	})
	if err != nil {
		return SealerResponse{Success: false, Error: err.Error()}
	}
	msg := &Message{
		Type:    MessageTypeVoteProofRequest,
		Payload: body,
	}
	if err := sh.parentConn.WriteMessage(msg); err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to send vote proof request: %v", err)}
	}
	resp, err := sh.parentConn.ReadMessage()
	if err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to read vote proof response: %v", err)}
	}
	if resp.Type != MessageTypeVoteProofResponse {
		return SealerResponse{Success: false, Error: fmt.Sprintf("unexpected response type: %s", resp.Type)}
	}
	// Parent encodes errors inside the JSON body (no MessageTypeError here).
	var errCheck struct {
		Error string `json:"error,omitempty"`
	}
	if json.Unmarshal(resp.Payload, &errCheck) == nil && errCheck.Error != "" {
		return SealerResponse{Success: false, Error: errCheck.Error}
	}
	return SealerResponse{Success: true, VoteProofData: resp.Payload}
}

// listProposals fetches proposals from DynamoDB via the parent process.
func (sh *SealerHandler) listProposals(req SealerRequest) SealerResponse {
	sh.connMu.Lock()
	defer sh.connMu.Unlock()

	if sh.parentConn == nil {
		return SealerResponse{Success: false, Error: "no parent connection available"}
	}

	log.Info().Msg("Listing proposals via parent")

	msg := &Message{Type: MessageTypeProposalsList}

	if err := sh.parentConn.WriteMessage(msg); err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to send proposals list request: %v", err)}
	}

	response, err := sh.parentConn.ReadMessage()
	if err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to read proposals list response: %v", err)}
	}

	if response.Type == MessageTypeError {
		return SealerResponse{Success: false, Error: fmt.Sprintf("parent error: %s", response.Error)}
	}

	if response.Type != MessageTypeProposalsResponse {
		return SealerResponse{Success: false, Error: fmt.Sprintf("unexpected response type: %s", response.Type)}
	}

	return SealerResponse{Success: true, ProposalsData: response.Payload}
}

// ForwardHTTPRequest forwards an HTTP proxy request from vault-manager to the parent process.
// The parent makes the actual HTTP call and returns the response.
// This uses the same parentConn as other parent-proxied operations (account seed, invite resolve, etc).
func (sh *SealerHandler) ForwardHTTPRequest(msg *Message) *Message {
	sh.connMu.Lock()
	defer sh.connMu.Unlock()

	if sh.parentConn == nil {
		log.Warn().Msg("No parent connection for HTTP proxy - dev mode")
		return &Message{
			RequestID: msg.RequestID,
			Type:      MessageTypeHTTPResponse,
			Payload:   []byte(`{"error":"no parent connection available"}`),
		}
	}

	log.Debug().
		Str("request_id", msg.RequestID).
		Int("payload_len", len(msg.Payload)).
		Msg("Forwarding HTTP request to parent")

	// Forward the request to parent as-is (parent will parse the HTTP request payload)
	fwdMsg := &Message{
		Type:      MessageTypeHTTPRequest,
		RequestID: msg.RequestID,
		Payload:   msg.Payload,
	}

	if err := sh.parentConn.WriteMessage(fwdMsg); err != nil {
		log.Error().Err(err).Msg("Failed to forward HTTP request to parent")
		return &Message{
			RequestID: msg.RequestID,
			Type:      MessageTypeHTTPResponse,
			Payload:   []byte(`{"error":"failed to send HTTP request to parent"}`),
		}
	}

	// Wait for response from parent
	response, err := sh.parentConn.ReadMessage()
	if err != nil {
		log.Error().Err(err).Msg("Failed to read HTTP response from parent")
		return &Message{
			RequestID: msg.RequestID,
			Type:      MessageTypeHTTPResponse,
			Payload:   []byte(`{"error":"failed to read HTTP response from parent"}`),
		}
	}

	if response.Type == MessageTypeError {
		return &Message{
			RequestID: msg.RequestID,
			Type:      MessageTypeHTTPResponse,
			Payload:   []byte(fmt.Sprintf(`{"error":"parent error: %s"}`, response.Error)),
		}
	}

	if response.Type != MessageTypeHTTPResponse {
		log.Warn().
			Str("expected", string(MessageTypeHTTPResponse)).
			Str("got", string(response.Type)).
			Msg("Unexpected response type for HTTP proxy")
		return &Message{
			RequestID: msg.RequestID,
			Type:      MessageTypeHTTPResponse,
			Payload:   []byte(fmt.Sprintf(`{"error":"unexpected response type: %s"}`, response.Type)),
		}
	}

	// Relay response back to vault-manager with correct request ID
	response.RequestID = msg.RequestID
	return response
}

// fetchMigrationConfig loads the signed migration config from S3.
// The config is published by deploy-with-migration.sh to _migration/config.json.
func (sh *SealerHandler) fetchMigrationConfig(req SealerRequest) SealerResponse {
	key := "_migration/config.json"
	log.Info().Str("key", key).Msg("Fetching migration config from S3")

	data, err := sh.s3Get(key)
	if err != nil {
		// No migration config is a normal case (no migration in progress)
		log.Debug().Err(err).Msg("No migration config found in S3")
		return SealerResponse{Success: true, MigrationConfig: nil}
	}

	log.Info().Int("config_len", len(data)).Msg("Migration config loaded from S3")
	return SealerResponse{Success: true, MigrationConfig: data}
}

// getTurnCredentials asks the parent for fresh Cloudflare TURN credentials.
// The parent fetches the shared secret from Secrets Manager and computes
// HMAC-signed REST API credentials scoped to the requesting vault's user_guid.
// Returns the response body as opaque JSON in TurnCredentials.
func (sh *SealerHandler) getTurnCredentials(req SealerRequest) SealerResponse {
	sh.connMu.Lock()
	defer sh.connMu.Unlock()

	if sh.parentConn == nil {
		return SealerResponse{Success: false, Error: "no parent connection available"}
	}

	msg := &Message{
		Type:       MessageTypeTurnCredentialsGet,
		OwnerSpace: req.OwnerSpace,
	}
	if err := sh.parentConn.WriteMessage(msg); err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to send turn request: %v", err)}
	}

	response, err := sh.parentConn.ReadMessage()
	if err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to read turn response: %v", err)}
	}
	if response.Type == MessageTypeError {
		return SealerResponse{Success: false, Error: fmt.Sprintf("parent error: %s", response.Error)}
	}
	if response.Type != MessageTypeTurnCredentialsResponse {
		return SealerResponse{Success: false, Error: fmt.Sprintf("unexpected response type: %s", response.Type)}
	}

	// Surface inline {"error": "..."} payloads as failure rather than success.
	var errPeek struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(response.Payload, &errPeek) == nil && errPeek.Error != "" {
		return SealerResponse{Success: false, Error: errPeek.Error}
	}

	return SealerResponse{Success: true, TurnCredentials: response.Payload}
}

// fetchPCRSigningPublicKey forwards the request to the parent which
// returns the DER-encoded SPKI bytes of the PCR signing key.
func (sh *SealerHandler) fetchPCRSigningPublicKey(req SealerRequest) SealerResponse {
	sh.connMu.Lock()
	defer sh.connMu.Unlock()

	if sh.parentConn == nil {
		return SealerResponse{Success: false, Error: "no parent connection available"}
	}

	msg := &Message{
		Type:       MessageTypePCRSigningKeyGet,
		OwnerSpace: req.OwnerSpace,
	}
	if err := sh.parentConn.WriteMessage(msg); err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to send pcr signing key request: %v", err)}
	}

	response, err := sh.parentConn.ReadMessage()
	if err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("failed to read pcr signing key response: %v", err)}
	}
	if response.Type == MessageTypeError {
		return SealerResponse{Success: false, Error: fmt.Sprintf("parent error: %s", response.Error)}
	}
	if response.Type != MessageTypePCRSigningKeyResponse {
		return SealerResponse{Success: false, Error: fmt.Sprintf("unexpected response type: %s", response.Type)}
	}

	// Inline error payload?
	var errPeek struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(response.Payload, &errPeek) == nil && errPeek.Error != "" {
		return SealerResponse{Success: false, Error: errPeek.Error}
	}

	// Extract the DER bytes from the JSON envelope.
	var keyEnv struct {
		PublicKeyDER []byte `json:"public_key_der"`
	}
	if err := json.Unmarshal(response.Payload, &keyEnv); err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("invalid pcr signing key envelope: %v", err)}
	}
	if len(keyEnv.PublicKeyDER) == 0 {
		return SealerResponse{Success: false, Error: "empty pcr signing public key"}
	}
	return SealerResponse{Success: true, PCRSigningPublicKey: keyEnv.PublicKeyDER}
}

// writeMigrationMarker publishes a "user migrated" signal to S3,
// signed by the enclave's PCR signing KMS key. Lambda auto-finalize
// reads these markers to decide when every enrolled user has migrated
// (instead of relying on the broken "no active users" heuristic), and
// verifies the signature so a misconfigured S3 writer can't forge them.
// Key: _migration/completed/{version}/{ownerSpace}.json
//
// SECURITY (attestation-F3): the marker JSON now contains a `signature`
// field — base64 ECDSA-SHA-256 over the canonical (sorted-key) form
// of {version, owner_space, completed_at}. Lambda calls KMS Verify on
// the same key and rejects any marker with a missing or bad signature.
func (sh *SealerHandler) writeMigrationMarker(req SealerRequest) SealerResponse {
	if req.MigrationVersion == "" {
		return SealerResponse{Success: false, Error: "migration_version is required"}
	}
	if req.OwnerSpace == "" {
		return SealerResponse{Success: false, Error: "owner_space is required"}
	}
	completedAt := time.Now().UTC().Format(time.RFC3339)

	// Canonical form: keys are alphabetically sorted, no whitespace.
	// Lambda must reproduce this exact byte sequence to verify.
	canonical := fmt.Sprintf(`{"completed_at":%q,"owner_space":%q,"version":%q}`,
		completedAt, req.OwnerSpace, req.MigrationVersion)
	digest := sha256.Sum256([]byte(canonical))

	sigResp := sh.signWithPCRSigningKey(req.OwnerSpace, digest[:])
	if !sigResp.Success {
		log.Error().Str("error", sigResp.Error).Msg("Failed to sign migration marker")
		return sigResp
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigResp.Signature)

	body := fmt.Sprintf(`{"completed_at":%q,"owner_space":%q,"signature":%q,"version":%q}`,
		completedAt, req.OwnerSpace, sigB64, req.MigrationVersion)
	key := fmt.Sprintf("_migration/completed/%s/%s.json", req.MigrationVersion, req.OwnerSpace)
	if err := sh.s3Put(key, []byte(body)); err != nil {
		log.Error().Err(err).Str("key", key).Msg("Failed to write migration marker")
		return SealerResponse{Success: false, Error: err.Error()}
	}
	log.Info().Str("key", key).Msg("Migration marker written + signed")
	return SealerResponse{Success: true}
}

// signWithPCRSigningKey forwards a digest to the parent for KMS Sign
// using the PCR signing key. Caller is expected to have hashed the
// payload with SHA-256.
func (sh *SealerHandler) signWithPCRSigningKey(ownerSpace string, digest []byte) SealerResponse {
	sh.connMu.Lock()
	defer sh.connMu.Unlock()

	if sh.parentConn == nil {
		return SealerResponse{Success: false, Error: "no parent connection available"}
	}

	payload, err := json.Marshal(map[string][]byte{"digest": digest})
	if err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("marshal digest: %v", err)}
	}
	msg := &Message{
		Type:       MessageTypePCRSigningKeySign,
		OwnerSpace: ownerSpace,
		Payload:    payload,
	}
	if err := sh.parentConn.WriteMessage(msg); err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("send sign request: %v", err)}
	}
	response, err := sh.parentConn.ReadMessage()
	if err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("read sign response: %v", err)}
	}
	if response.Type == MessageTypeError {
		return SealerResponse{Success: false, Error: response.Error}
	}
	if response.Type != MessageTypePCRSigningKeySignResponse {
		return SealerResponse{Success: false, Error: fmt.Sprintf("unexpected response type: %s", response.Type)}
	}
	var errPeek struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(response.Payload, &errPeek) == nil && errPeek.Error != "" {
		return SealerResponse{Success: false, Error: errPeek.Error}
	}
	var sigEnv struct {
		Signature []byte `json:"signature"`
	}
	if err := json.Unmarshal(response.Payload, &sigEnv); err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("invalid sign envelope: %v", err)}
	}
	if len(sigEnv.Signature) == 0 {
		return SealerResponse{Success: false, Error: "empty signature"}
	}
	return SealerResponse{Success: true, Signature: sigEnv.Signature}
}
