package main

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
)

// SealerHandler handles sealer requests from vault-manager processes.
// The vault-manager cannot directly access KMS - it must proxy through the supervisor.
type SealerHandler struct {
	sealer *NitroSealer
}

// NewSealerHandler creates a new sealer handler
func NewSealerHandler(sealer *NitroSealer) *SealerHandler {
	return &SealerHandler{
		sealer: sealer,
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
)

// SealerRequest is received from vault-manager
type SealerRequest struct {
	Operation  SealerOperation `json:"operation"`
	OwnerSpace string          `json:"owner_space"`

	// For derive_dek_from_pin
	SealedMaterial []byte `json:"sealed_material,omitempty"`
	PIN            string `json:"pin,omitempty"`

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
func (sh *SealerHandler) deriveDEKFromPIN(req SealerRequest) SealerResponse {
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
