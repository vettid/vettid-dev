package main

import (
	"context"
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
	sealer *NitroSealer
	mux    *MuxConn     // Multiplexed transport to parent for S3/KMS/etc.
	muxMu  sync.RWMutex // Guards the mux pointer (swapped on connect/drop)
	// devMode, when true, allows S3/HTTP/SSM operations to no-op
	// successfully when the parent transport is nil. SECURITY (#74):
	// in production devMode is false, so a missing parent connection
	// fails-closed instead of silently pretending the write
	// succeeded — which used to leave callers thinking durable
	// state was persisted when it wasn't, opening a "ghost write"
	// data-loss window during a restart or split-brain.
	devMode bool
}

// NewSealerHandler creates a new sealer handler
func NewSealerHandler(sealer *NitroSealer) *SealerHandler {
	return &SealerHandler{
		sealer: sealer,
	}
}

// SetDevMode wires the supervisor's parsed dev-mode flag into the
// sealer handler. Production callers should never invoke this (default
// false). When true, parent-not-connected paths log warnings and
// return synthetic success; when false they return errors.
func (sh *SealerHandler) SetDevMode(devMode bool) {
	sh.devMode = devMode
}

// SetMux wires (or clears, on nil) the multiplexed parent transport.
// handleConnection calls this each time the parent connects or drops.
func (sh *SealerHandler) SetMux(mux *MuxConn) {
	sh.muxMu.Lock()
	sh.mux = mux
	sh.muxMu.Unlock()
}

// getMux returns the current parent transport, or nil if not connected.
func (sh *SealerHandler) getMux() *MuxConn {
	sh.muxMu.RLock()
	defer sh.muxMu.RUnlock()
	return sh.mux
}

// muxRoundTrip issues a supervisor→parent request through the mux and
// returns the response, rejecting a transport failure, a
// MessageTypeError response, or (when want != "") an unexpected
// response type. op labels error strings; the timeout matches
// s3OperationTimeout. SECURITY (#74): a nil mux in production is a
// fail-closed error, never a silent pass.
func (sh *SealerHandler) muxRoundTrip(op string, req *Message, want MessageType) (*Message, error) {
	mux := sh.getMux()
	if mux == nil {
		log.Error().Str("op", op).Msg("SECURITY: parent connection missing — failing closed")
		return nil, fmt.Errorf("%s: supervisor not connected to parent", op)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s3OperationTimeout)
	defer cancel()
	resp, err := mux.SendRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if resp.Type == MessageTypeError {
		return nil, fmt.Errorf("%s: parent error: %s", op, resp.Error)
	}
	if want != "" && resp.Type != want {
		return nil, fmt.Errorf("%s: unexpected response type %s", op, resp.Type)
	}
	return resp, nil
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
	// Running PCR0 hex of the executing enclave. Cached at first
	// read. Used by the migration handler (M3) to stamp
	// `sealed_to_pcr0` into the SealedMaterialData wrapper after
	// re-seal so future readers can identify the bound PCR0
	// without a KMS round-trip.
	SealerOpGetRunningPCR0 SealerOperation = "get_running_pcr0"
	// LEASH publish ops — vault pushes the public attestation pubkey
	// and per-jti issuance log to DynamoDB so the public verifier
	// Lambda can answer without touching the enclave.
	SealerOpPublishLeashAttestKey SealerOperation = "publish_leash_attest_key"
	SealerOpPublishLeashIssued    SealerOperation = "publish_leash_issued"
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

	// D3 conditional-storage fields (vault_state.enc split-brain guard).
	// For store_vault_state: ExpectedETag is the ETag from the previous
	// load_vault_state; IfNoneMatchAny=true requests first-write semantics
	// (the object must not exist). load_vault_state has no inputs here.
	ExpectedETag    string `json:"expected_etag,omitempty"`
	IfNoneMatchAny  bool   `json:"if_none_match_any,omitempty"`
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

	// For get_running_pcr0 (hex-encoded running PCR0)
	RunningPCR0 string `json:"running_pcr0,omitempty"`

	// For internal sign-with-PCR-signing-key calls (used by the
	// migration-marker writer). Caller embeds the bytes in the
	// outbound JSON; not surfaced to vault-manager.
	Signature []byte `json:"-"`

	// D3 conditional-storage fields (vault_state.enc).
	// For load_vault_state: ETag is the S3 object's ETag, ready to be
	// echoed back as ExpectedETag on the next store_vault_state.
	// For store_vault_state: ETag is the new object's ETag; ConditionFailed
	// is true if S3 rejected the conditional put (412 PreconditionFailed)
	// — the caller MUST NOT retry; another writer is touching the object.
	ETag            string `json:"etag,omitempty"`
	ConditionFailed bool   `json:"condition_failed,omitempty"`
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
	case SealerOpPublishLeashAttestKey:
		resp = sh.publishLeashAttestKey(req)
	case SealerOpPublishLeashIssued:
		resp = sh.publishLeashIssued(req)
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
	case SealerOpGetRunningPCR0:
		resp = sh.getRunningPCR0(req)
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

// s3Put stores data to S3 via the parent (multiplexed request/response)
func (sh *SealerHandler) s3Put(key string, data []byte) error {
	mux := sh.getMux()
	if mux == nil {
		if sh.devMode {
			log.Warn().Str("key", key).Msg("No parent connection for S3 PUT - dev mode (silent pass)")
			return nil
		}
		log.Error().Str("key", key).Msg("SECURITY: parent connection missing for S3 PUT — failing closed")
		return fmt.Errorf("s3Put: supervisor not connected to parent (key=%s)", key)
	}

	ctx, cancel := context.WithTimeout(context.Background(), s3OperationTimeout)
	defer cancel()
	resp, err := mux.SendRequest(ctx, &Message{
		Type:         MessageTypeStoragePut,
		StorageKey:   key,
		StorageValue: data, // []byte for binary data, not Payload (json.RawMessage)
	})
	if err != nil {
		return fmt.Errorf("S3 PUT request failed: %w", err)
	}
	if resp.Type == MessageTypeError {
		return fmt.Errorf("S3 PUT error: %s", resp.Error)
	}
	if resp.Type != MessageTypeStorageResponse && resp.Type != MessageTypeOK {
		return fmt.Errorf("unexpected response type for S3 PUT: %s", resp.Type)
	}
	return nil
}

// s3PutConditional performs a conditional S3 PUT through the parent.
// Exactly one of (expectedETag, ifNoneMatchAny) is meaningful: pass
// expectedETag for an update-in-place that must match the prior load,
// or ifNoneMatchAny=true for first-write semantics (object must not
// exist). Returns the new ETag on success. conflict=true means the
// parent's S3 PUT got 412 PreconditionFailed and the caller MUST NOT
// retry; another writer is racing this object (D3 split-brain guard).
func (sh *SealerHandler) s3PutConditional(key string, data []byte, expectedETag string, ifNoneMatchAny bool) (newETag string, conflict bool, err error) {
	mux := sh.getMux()
	if mux == nil {
		if sh.devMode {
			log.Warn().Str("key", key).Msg("No parent connection for conditional S3 PUT - dev mode (silent pass)")
			return "", false, nil
		}
		log.Error().Str("key", key).Msg("SECURITY: parent connection missing for conditional S3 PUT — failing closed")
		return "", false, fmt.Errorf("s3PutConditional: supervisor not connected to parent (key=%s)", key)
	}

	req := &Message{
		Type:         MessageTypeStoragePut,
		StorageKey:   key,
		StorageValue: data,
	}
	if expectedETag != "" {
		req.IfMatch = expectedETag
	}
	if ifNoneMatchAny {
		req.IfNoneMatch = "*"
	}

	ctx, cancel := context.WithTimeout(context.Background(), s3OperationTimeout)
	defer cancel()
	resp, err := mux.SendRequest(ctx, req)
	if err != nil {
		return "", false, fmt.Errorf("S3 PUT request failed: %w", err)
	}
	if resp.Type == MessageTypeError {
		return "", false, fmt.Errorf("S3 PUT error: %s", resp.Error)
	}
	if resp.Type != MessageTypeStorageResponse && resp.Type != MessageTypeOK {
		return "", false, fmt.Errorf("unexpected response type for S3 PUT: %s", resp.Type)
	}

	return resp.ReturnedETag, resp.ConditionFailed, nil
}

// s3Get retrieves data from S3 via the parent (multiplexed request/response)
func (sh *SealerHandler) s3Get(key string) ([]byte, error) {
	resp, err := sh.muxRoundTrip("s3Get:"+key, &Message{
		Type:       MessageTypeStorageGet,
		StorageKey: key,
	}, MessageTypeStorageResponse)
	if err != nil {
		return nil, err
	}
	// Data is in Payload or StorageValue
	if len(resp.Payload) > 0 {
		return resp.Payload, nil
	}
	return resp.StorageValue, nil
}

// s3GetWithETag is s3Get plus the object's ETag. Callers that intend to
// follow up with a conditional put on the same key (vault_state.enc D3
// path) keep the ETag and pass it back as ExpectedETag on the store.
func (sh *SealerHandler) s3GetWithETag(key string) ([]byte, string, error) {
	resp, err := sh.muxRoundTrip("s3GetWithETag:"+key, &Message{
		Type:       MessageTypeStorageGet,
		StorageKey: key,
	}, MessageTypeStorageResponse)
	if err != nil {
		return nil, "", err
	}
	data := resp.StorageValue
	if len(resp.Payload) > 0 {
		data = resp.Payload
	}
	return data, resp.ReturnedETag, nil
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

// storeVaultState stores encrypted vault state to S3 via parent using
// the D3 conditional-put path. The caller (vault-manager SealerProxy)
// supplies either ExpectedETag (update of an object loaded earlier in
// this process) or IfNoneMatchAny (first-write at fresh enrollment).
// Returns the new ETag on success. ConditionFailed=true means S3 got a
// 412 PreconditionFailed: another writer is racing this object; the
// caller MUST NOT retry blindly and should treat it as a split-brain
// signal (the existing ownershipRevoked plumbing fences subsequent writes).
func (sh *SealerHandler) storeVaultState(req SealerRequest) SealerResponse {
	key := s3KeyVaultState(req.OwnerSpace)
	log.Info().
		Str("owner_space", req.OwnerSpace).
		Str("key", key).
		Bool("has_expected_etag", req.ExpectedETag != "").
		Bool("if_none_match_any", req.IfNoneMatchAny).
		Msg("Storing vault state to S3")

	newETag, conflict, err := sh.s3PutConditional(key, req.Data, req.ExpectedETag, req.IfNoneMatchAny)
	if err != nil {
		log.Error().Err(err).Msg("Failed to store vault state to S3")
		return SealerResponse{Success: false, Error: err.Error()}
	}
	if conflict {
		log.Error().
			Str("owner_space", req.OwnerSpace).
			Str("expected_etag", req.ExpectedETag).
			Bool("if_none_match_any", req.IfNoneMatchAny).
			Msg("SECURITY: S3 conditional store rejected — D3 split-brain guard tripped")
		return SealerResponse{Success: false, ConditionFailed: true, Error: "s3 precondition failed"}
	}

	log.Info().
		Str("owner_space", req.OwnerSpace).
		Str("new_etag", newETag).
		Msg("Vault state stored to S3 successfully")
	return SealerResponse{Success: true, ETag: newETag}
}

// loadVaultState loads encrypted vault state from S3 via parent and
// returns the object's ETag so the next store_vault_state can use it
// as ExpectedETag (D3 compare-and-swap).
func (sh *SealerHandler) loadVaultState(req SealerRequest) SealerResponse {
	key := s3KeyVaultState(req.OwnerSpace)
	log.Info().Str("owner_space", req.OwnerSpace).Str("key", key).Msg("Loading vault state from S3")

	data, etag, err := sh.s3GetWithETag(key)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load vault state from S3")
		return SealerResponse{Success: false, Error: err.Error()}
	}

	log.Info().
		Str("owner_space", req.OwnerSpace).
		Int("data_len", len(data)).
		Str("etag", etag).
		Msg("Vault state loaded from S3 successfully")
	return SealerResponse{Success: true, UnsealedData: data, ETag: etag}
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
	log.Info().Str("owner_space", req.OwnerSpace).Msg("Requesting NATS account seed from parent")

	response, err := sh.muxRoundTrip("loadAccountSeed", &Message{
		Type:       MessageTypeNATSAccountSeedGet,
		OwnerSpace: req.OwnerSpace,
	}, MessageTypeNATSAccountSeedResponse)
	if err != nil {
		return SealerResponse{Success: false, Error: err.Error()}
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
	log.Info().Str("invite_code", req.InviteCode).Msg("Resolving invitation via parent")

	response, err := sh.muxRoundTrip("resolveInvite", &Message{
		Type:    MessageTypeInviteResolve,
		Subject: req.InviteCode,
	}, MessageTypeInviteResponse)
	if err != nil {
		return SealerResponse{Success: false, Error: err.Error()}
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
	if len(req.VoteSubmitPayload) == 0 {
		return SealerResponse{Success: false, Error: "empty vote submit payload"}
	}
	resp, err := sh.muxRoundTrip("submitSignedVote", &Message{
		Type:    MessageTypeVoteSubmit,
		Payload: req.VoteSubmitPayload,
	}, MessageTypeVoteSubmitResponse)
	if err != nil {
		return SealerResponse{Success: false, Error: err.Error()}
	}
	return SealerResponse{Success: true, VoteSubmitResult: resp.Payload}
}

// publishLeashAttestKey forwards the vault's published Ed25519
// attestation pubkey to the parent for DynamoDB write. Pure pass-
// through: payload is the marshalled key row, parent does the put.
func (sh *SealerHandler) publishLeashAttestKey(req SealerRequest) SealerResponse {
	if len(req.Data) == 0 {
		return SealerResponse{Success: false, Error: "empty leash attest key payload"}
	}
	resp, err := sh.muxRoundTrip("publishLeashAttestKey", &Message{
		Type:       MessageTypeLeashAttestKeyPublish,
		OwnerSpace: req.OwnerSpace,
		Payload:    req.Data,
	}, MessageTypeLeashAttestKeyPublishResponse)
	if err != nil {
		return SealerResponse{Success: false, Error: err.Error()}
	}
	// Parent embeds {success, error?} in the response payload.
	var inner struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(resp.Payload, &inner); err != nil {
		return SealerResponse{Success: false, Error: "decode publish response: " + err.Error()}
	}
	if !inner.Success {
		return SealerResponse{Success: false, Error: inner.Error}
	}
	return SealerResponse{Success: true}
}

// publishLeashIssued forwards a leash issuance record to the parent
// for DynamoDB write. Same pass-through shape as the attest-key publish.
func (sh *SealerHandler) publishLeashIssued(req SealerRequest) SealerResponse {
	if len(req.Data) == 0 {
		return SealerResponse{Success: false, Error: "empty leash issued payload"}
	}
	resp, err := sh.muxRoundTrip("publishLeashIssued", &Message{
		Type:       MessageTypeLeashIssuedPublish,
		OwnerSpace: req.OwnerSpace,
		Payload:    req.Data,
	}, MessageTypeLeashIssuedPublishResponse)
	if err != nil {
		return SealerResponse{Success: false, Error: err.Error()}
	}
	var inner struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(resp.Payload, &inner); err != nil {
		return SealerResponse{Success: false, Error: "decode publish response: " + err.Error()}
	}
	if !inner.Success {
		return SealerResponse{Success: false, Error: inner.Error}
	}
	return SealerResponse{Success: true}
}

// getVoteProof fetches a Merkle inclusion proof from the parent (which reads
// from the published-votes S3 bucket). The vault verifies the proof locally.
func (sh *SealerHandler) getVoteProof(req SealerRequest) SealerResponse {
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
	resp, err := sh.muxRoundTrip("getVoteProof", &Message{
		Type:    MessageTypeVoteProofRequest,
		Payload: body,
	}, MessageTypeVoteProofResponse)
	if err != nil {
		return SealerResponse{Success: false, Error: err.Error()}
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
	log.Info().Msg("Listing proposals via parent")

	response, err := sh.muxRoundTrip("listProposals",
		&Message{Type: MessageTypeProposalsList}, MessageTypeProposalsResponse)
	if err != nil {
		return SealerResponse{Success: false, Error: err.Error()}
	}

	return SealerResponse{Success: true, ProposalsData: response.Payload}
}

// ForwardHTTPRequest forwards an HTTP proxy request from vault-manager to the parent process.
// The parent makes the actual HTTP call and returns the response.
// This uses the same parentConn as other parent-proxied operations (account seed, invite resolve, etc).
func (sh *SealerHandler) ForwardHTTPRequest(msg *Message) *Message {
	httpErr := func(format string, a ...interface{}) *Message {
		return &Message{
			RequestID: msg.RequestID,
			Type:      MessageTypeHTTPResponse,
			Payload:   []byte(fmt.Sprintf(format, a...)),
		}
	}

	mux := sh.getMux()
	if mux == nil {
		log.Warn().Msg("No parent connection for HTTP proxy")
		return httpErr(`{"error":"no parent connection available"}`)
	}

	log.Debug().
		Str("request_id", msg.RequestID).
		Int("payload_len", len(msg.Payload)).
		Msg("Forwarding HTTP request to parent")

	ctx, cancel := context.WithTimeout(context.Background(), s3OperationTimeout)
	defer cancel()
	response, err := mux.SendRequest(ctx, &Message{
		Type:      MessageTypeHTTPRequest,
		RequestID: msg.RequestID,
		Payload:   msg.Payload,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed HTTP request round-trip to parent")
		return httpErr(`{"error":"failed to forward HTTP request to parent"}`)
	}

	if response.Type == MessageTypeError {
		return httpErr(`{"error":"parent error: %s"}`, response.Error)
	}
	if response.Type != MessageTypeHTTPResponse {
		log.Warn().
			Str("expected", string(MessageTypeHTTPResponse)).
			Str("got", string(response.Type)).
			Msg("Unexpected response type for HTTP proxy")
		return httpErr(`{"error":"unexpected response type: %s"}`, response.Type)
	}

	// Relay response back to vault-manager with the request ID it
	// expects; the transport MuxID is meaningless on the subprocess pipe.
	response.RequestID = msg.RequestID
	response.MuxID = ""
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
	response, err := sh.muxRoundTrip("getTurnCredentials", &Message{
		Type:       MessageTypeTurnCredentialsGet,
		OwnerSpace: req.OwnerSpace,
	}, MessageTypeTurnCredentialsResponse)
	if err != nil {
		return SealerResponse{Success: false, Error: err.Error()}
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
	response, err := sh.muxRoundTrip("fetchPCRSigningPublicKey", &Message{
		Type:       MessageTypePCRSigningKeyGet,
		OwnerSpace: req.OwnerSpace,
	}, MessageTypePCRSigningKeyResponse)
	if err != nil {
		return SealerResponse{Success: false, Error: err.Error()}
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

// getRunningPCR0 returns the hex-encoded PCR0 of the running
// enclave so the migration handler can stamp `sealed_to_pcr0` into
// the SealedMaterialData wrapper after a re-seal. The result is
// cached inside the supervisor; PCR0 is immutable per instance.
func (sh *SealerHandler) getRunningPCR0(_ SealerRequest) SealerResponse {
	pcr0, err := GetRunningPCR0Hex()
	if err != nil {
		return SealerResponse{Success: false, Error: err.Error()}
	}
	return SealerResponse{Success: true, RunningPCR0: pcr0}
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
	payload, err := json.Marshal(map[string][]byte{"digest": digest})
	if err != nil {
		return SealerResponse{Success: false, Error: fmt.Sprintf("marshal digest: %v", err)}
	}
	response, err := sh.muxRoundTrip("signWithPCRSigningKey", &Message{
		Type:       MessageTypePCRSigningKeySign,
		OwnerSpace: ownerSpace,
		Payload:    payload,
	}, MessageTypePCRSigningKeySignResponse)
	if err != nil {
		return SealerResponse{Success: false, Error: err.Error()}
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
