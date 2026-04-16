package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// SECURITY: Timeout for sealer proxy responses
// Prevents indefinite hangs if supervisor becomes unresponsive
const sealerProxyTimeout = 30 * time.Second

// SealerProxy handles communication with the supervisor for KMS-dependent operations.
// The vault-manager cannot directly access KMS - it must proxy through the supervisor
// which has access to the NitroSealer.
type SealerProxy struct {
	ownerSpace string
	sendFn     func(msg *OutgoingMessage) error
	// responseCh is set by the caller to receive responses
	responseCh chan *IncomingMessage
}

// NewSealerProxy creates a new sealer proxy
func NewSealerProxy(ownerSpace string, sendFn func(msg *OutgoingMessage) error) *SealerProxy {
	return &SealerProxy{
		ownerSpace: ownerSpace,
		sendFn:     sendFn,
	}
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
	// Migration config (fetched from S3 via parent)
	SealerOpFetchMigrationConfig SealerOperation = "fetch_migration_config"
	// Migration marker (written to unencrypted S3 path after user completes migration)
	SealerOpWriteMigrationMarker SealerOperation = "write_migration_marker"
	// Migration: unseal the inner sealed material from the full blob (no DEK derivation)
	SealerOpUnsealMaterial SealerOperation = "unseal_material"
)

// SealerRequest is sent from vault-manager to supervisor
type SealerRequest struct {
	Operation  SealerOperation `json:"operation"`
	OwnerSpace string          `json:"owner_space"`

	// For derive_dek_from_pin
	SealedMaterial []byte  `json:"sealed_material,omitempty"`
	PIN            []byte  `json:"pin,omitempty"` // SECURITY: Only sent over internal pipe, zeroed after use

	// For seal_credential / unseal_credential
	Data []byte `json:"data,omitempty"`

	// For resolve_invite
	InviteCode string `json:"invite_code,omitempty"`

	// For write_migration_marker
	MigrationVersion string `json:"migration_version,omitempty"`
}

// SealerResponse is returned from supervisor to vault-manager
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

	// For fetch_migration_config
	MigrationConfig []byte `json:"migration_config,omitempty"`
}

// GenerateSealedMaterial requests the supervisor to generate PCR-bound sealed material
// This material is used to derive the DEK from the user's PIN
func (p *SealerProxy) GenerateSealedMaterial() ([]byte, error) {
	req := SealerRequest{
		Operation:  SealerOpGenerateSealedMaterial,
		OwnerSpace: p.ownerSpace,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("sealer error: %s", resp.Error)
	}

	return resp.SealedMaterial, nil
}

// DeriveDEKFromPIN requests the supervisor to derive the DEK from PIN + sealed material
// SECURITY: The PIN is sent over the internal pipe (not exposed externally)
// SECURITY: PIN is passed as []byte so it can be zeroed by the caller after use
func (p *SealerProxy) DeriveDEKFromPIN(sealedMaterial []byte, pin []byte) ([]byte, error) {
	// Make a copy of the PIN for the request so we can zero it after sending
	pinCopy := make([]byte, len(pin))
	copy(pinCopy, pin)

	req := SealerRequest{
		Operation:      SealerOpDeriveDEKFromPIN,
		OwnerSpace:     p.ownerSpace,
		SealedMaterial: sealedMaterial,
		PIN:            pinCopy,
	}
	// SECURITY: Zero the PIN copy in the request after marshaling
	defer zeroBytes(pinCopy)

	resp, err := p.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("sealer error: %s", resp.Error)
	}

	return resp.DEK, nil
}

// SealCredential requests the supervisor to seal data using Nitro KMS
func (p *SealerProxy) SealCredential(data []byte) ([]byte, error) {
	req := SealerRequest{
		Operation:  SealerOpSealCredential,
		OwnerSpace: p.ownerSpace,
		Data:       data,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("sealer error: %s", resp.Error)
	}

	return resp.SealedData, nil
}

// UnsealMaterial unseals the inner sealed material from a full SealedMaterialData blob.
// Unlike UnsealCredential, this passes the blob via the SealedMaterial field (same path
// as DeriveDEKFromPIN) to avoid base64-encoding issues with the Data field.
func (p *SealerProxy) UnsealMaterial(sealedMaterialBlob []byte) ([]byte, error) {
	req := SealerRequest{
		Operation:      SealerOpUnsealMaterial,
		OwnerSpace:     p.ownerSpace,
		SealedMaterial: sealedMaterialBlob,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("sealer error: %s", resp.Error)
	}

	return resp.UnsealedData, nil
}

// UnsealCredential requests the supervisor to unseal data using Nitro KMS
func (p *SealerProxy) UnsealCredential(sealedData []byte) ([]byte, error) {
	req := SealerRequest{
		Operation:  SealerOpUnsealCredential,
		OwnerSpace: p.ownerSpace,
		Data:       sealedData,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("sealer error: %s", resp.Error)
	}

	return resp.UnsealedData, nil
}

// sendRequest sends a sealer request to the supervisor and waits for response
// NOTE: This is a synchronous call - the vault-manager message loop must handle
// routing sealer responses back to this channel
// SECURITY: Uses a timeout to prevent indefinite hangs
// SECURITY: Matches request ID to prevent processing stale responses
func (p *SealerProxy) sendRequest(req SealerRequest) (*SealerResponse, error) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sealer request: %w", err)
	}

	requestID := generateMessageID()
	msg := &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeSealerRequest,
		Payload:   reqBytes,
	}

	log.Debug().
		Str("operation", string(req.Operation)).
		Str("owner_space", req.OwnerSpace).
		Str("request_id", requestID).
		Msg("Sending sealer request to supervisor")

	if err := p.sendFn(msg); err != nil {
		return nil, fmt.Errorf("failed to send sealer request: %w", err)
	}

	// Wait for response on the response channel with timeout
	// The main message loop routes sealer responses here
	if p.responseCh == nil {
		return nil, fmt.Errorf("response channel not set")
	}

	// SECURITY: Use timeout to prevent indefinite hangs
	// SECURITY: Match request ID to prevent processing stale responses from timed-out requests
	deadline := time.Now().Add(sealerProxyTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			log.Error().
				Str("operation", string(req.Operation)).
				Str("owner_space", req.OwnerSpace).
				Str("request_id", requestID).
				Dur("timeout", sealerProxyTimeout).
				Msg("SECURITY: Sealer proxy timeout waiting for supervisor response")
			return nil, fmt.Errorf("sealer proxy timeout after %v", sealerProxyTimeout)
		}

		select {
		case respMsg := <-p.responseCh:
			if respMsg == nil {
				return nil, fmt.Errorf("no response received (channel closed)")
			}

			// SECURITY: Check if this response matches our request ID
			// If not, it's a stale response from a previous timed-out request - discard it
			if respMsg.RequestID != "" && respMsg.RequestID != requestID {
				log.Warn().
					Str("expected_id", requestID).
					Str("received_id", respMsg.RequestID).
					Str("operation", string(req.Operation)).
					Msg("Discarding stale sealer response (request ID mismatch)")
				continue // Keep waiting for our response
			}

			var resp SealerResponse
			if err := json.Unmarshal(respMsg.Payload, &resp); err != nil {
				return nil, fmt.Errorf("failed to unmarshal sealer response: %w", err)
			}

			log.Debug().
				Str("operation", string(req.Operation)).
				Str("request_id", requestID).
				Bool("success", resp.Success).
				Msg("Received matching sealer response")

			return &resp, nil

		case <-time.After(remaining):
			log.Error().
				Str("operation", string(req.Operation)).
				Str("owner_space", req.OwnerSpace).
				Str("request_id", requestID).
				Dur("timeout", sealerProxyTimeout).
				Msg("SECURITY: Sealer proxy timeout waiting for supervisor response")
			return nil, fmt.Errorf("sealer proxy timeout after %v", sealerProxyTimeout)
		}
	}
}

// SetResponseChannel sets the channel for receiving responses
func (p *SealerProxy) SetResponseChannel(ch chan *IncomingMessage) {
	p.responseCh = ch
}

// StoreSealedMaterial stores sealed material to S3 for cold vault recovery
func (p *SealerProxy) StoreSealedMaterial(sealedMaterial []byte) error {
	req := SealerRequest{
		Operation:  SealerOpStoreSealedMaterial,
		OwnerSpace: p.ownerSpace,
		Data:       sealedMaterial,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("storage error: %s", resp.Error)
	}

	return nil
}

// LoadSealedMaterial loads sealed material from S3 for cold vault recovery
func (p *SealerProxy) LoadSealedMaterial() ([]byte, error) {
	req := SealerRequest{
		Operation:  SealerOpLoadSealedMaterial,
		OwnerSpace: p.ownerSpace,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("storage error: %s", resp.Error)
	}

	return resp.SealedMaterial, nil
}

// StoreSealedECIES stores KMS-sealed ECIES keys to S3 for cold vault recovery
func (p *SealerProxy) StoreSealedECIES(sealedECIES []byte) error {
	req := SealerRequest{
		Operation:  SealerOpStoreSealedECIES,
		OwnerSpace: p.ownerSpace,
		Data:       sealedECIES,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("storage error: %s", resp.Error)
	}

	return nil
}

// LoadSealedECIES loads KMS-sealed ECIES keys from S3 for cold vault recovery
func (p *SealerProxy) LoadSealedECIES() ([]byte, error) {
	req := SealerRequest{
		Operation:  SealerOpLoadSealedECIES,
		OwnerSpace: p.ownerSpace,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("storage error: %s", resp.Error)
	}

	return resp.SealedData, nil
}

// StoreVaultState stores DEK-encrypted vault state to S3 for cold vault recovery
func (p *SealerProxy) StoreVaultState(encryptedState []byte) error {
	req := SealerRequest{
		Operation:  SealerOpStoreVaultState,
		OwnerSpace: p.ownerSpace,
		Data:       encryptedState,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("storage error: %s", resp.Error)
	}

	return nil
}

// LoadAccountSeed fetches the NATS account seed via the parent process.
// The parent reads the encrypted seed from DynamoDB and decrypts via KMS.
func (p *SealerProxy) LoadAccountSeed() (string, error) {
	req := SealerRequest{
		Operation:  SealerOpLoadAccountSeed,
		OwnerSpace: p.ownerSpace,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return "", err
	}

	if !resp.Success {
		return "", fmt.Errorf("account seed error: %s", resp.Error)
	}

	if resp.AccountSeed == "" {
		return "", fmt.Errorf("empty account seed returned")
	}

	return resp.AccountSeed, nil
}

// ResolveInvite fetches invitation data from the NATS INVITATIONS stream via the parent.
func (p *SealerProxy) ResolveInvite(inviteCode string) ([]byte, error) {
	req := SealerRequest{
		Operation:  SealerOpResolveInvite,
		OwnerSpace: p.ownerSpace,
		InviteCode: inviteCode,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("invite resolve error: %s", resp.Error)
	}

	if len(resp.InviteData) == 0 {
		return nil, fmt.Errorf("empty invite data returned")
	}

	return resp.InviteData, nil
}

// LoadVaultState loads DEK-encrypted vault state from S3 for cold vault recovery
func (p *SealerProxy) LoadVaultState() ([]byte, error) {
	req := SealerRequest{
		Operation:  SealerOpLoadVaultState,
		OwnerSpace: p.ownerSpace,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("storage error: %s", resp.Error)
	}

	return resp.UnsealedData, nil
}

// ListProposals fetches active/upcoming/published proposals from DynamoDB via the parent.
func (p *SealerProxy) ListProposals() ([]byte, error) {
	req := SealerRequest{
		Operation:  SealerOpListProposals,
		OwnerSpace: p.ownerSpace,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("proposals list error: %s", resp.Error)
	}

	if len(resp.ProposalsData) == 0 {
		return nil, fmt.Errorf("empty proposals data returned")
	}

	return resp.ProposalsData, nil
}

// FetchMigrationConfig loads the signed migration config from S3 via the supervisor.
// Returns nil, nil if no migration config exists (normal case when no migration is in progress).
func (p *SealerProxy) FetchMigrationConfig() ([]byte, error) {
	req := SealerRequest{
		Operation:  SealerOpFetchMigrationConfig,
		OwnerSpace: p.ownerSpace,
	}

	resp, err := p.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("fetch migration config error: %s", resp.Error)
	}

	// nil config means no migration available (normal case)
	return resp.MigrationConfig, nil
}

// WriteMigrationMarker publishes an unencrypted "this user has migrated to
// `version`" marker to S3 (_migration/completed/{version}/{ownerSpace}.json).
// The auto-finalize Lambda reads these to know when every enrolled user is
// done, so it no longer has to guess from "active user" heuristics.
func (p *SealerProxy) WriteMigrationMarker(version string) error {
	req := SealerRequest{
		Operation:        SealerOpWriteMigrationMarker,
		OwnerSpace:       p.ownerSpace,
		MigrationVersion: version,
	}
	resp, err := p.sendRequest(req)
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("write migration marker error: %s", resp.Error)
	}
	return nil
}
