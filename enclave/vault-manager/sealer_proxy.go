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
func (p *SealerProxy) sendRequest(req SealerRequest) (*SealerResponse, error) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sealer request: %w", err)
	}

	msg := &OutgoingMessage{
		RequestID: generateMessageID(),
		Type:      MessageTypeSealerRequest,
		Payload:   reqBytes,
	}

	log.Debug().
		Str("operation", string(req.Operation)).
		Str("owner_space", req.OwnerSpace).
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
	select {
	case respMsg := <-p.responseCh:
		if respMsg == nil {
			return nil, fmt.Errorf("no response received (channel closed)")
		}

		var resp SealerResponse
		if err := json.Unmarshal(respMsg.Payload, &resp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal sealer response: %w", err)
		}

		return &resp, nil

	case <-time.After(sealerProxyTimeout):
		log.Error().
			Str("operation", string(req.Operation)).
			Str("owner_space", req.OwnerSpace).
			Dur("timeout", sealerProxyTimeout).
			Msg("SECURITY: Sealer proxy timeout waiting for supervisor response")
		return nil, fmt.Errorf("sealer proxy timeout after %v", sealerProxyTimeout)
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
