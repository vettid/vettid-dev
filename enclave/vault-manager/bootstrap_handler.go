package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/curve25519"
)

// BootstrapHandler handles vault bootstrap operations
type BootstrapHandler struct {
	ownerSpace string
	state      *VaultState
}

// NewBootstrapHandler creates a new bootstrap handler
func NewBootstrapHandler(ownerSpace string, state *VaultState) *BootstrapHandler {
	return &BootstrapHandler{
		ownerSpace: ownerSpace,
		state:      state,
	}
}

// HandleBootstrap processes bootstrap requests
// This implements Phase 2 of the enrollment flow per Architecture v2.0 Section 5.6
// 1. Generate CEK keypair (for credential encryption)
// 2. Generate UTK/LTK pairs (for transport encryption)
// 3. Return UTKs and ECIES public key to app
func (h *BootstrapHandler) HandleBootstrap(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("Bootstrap requested")

	// Parse bootstrap request (optional)
	var req BootstrapRequest
	if len(msg.Payload) > 0 {
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			log.Warn().Err(err).Msg("Failed to parse bootstrap request")
			// Continue anyway - bootstrap token validation is optional
		}
	}

	// NOTE: Bootstrap token validation is NOT required because:
	// 1. NATS authentication already ensures only the legitimate user can publish to their vault topic
	// 2. The mobile app receives temporary NATS credentials from enrollFinalize Lambda
	// 3. These credentials are scoped to the user's OwnerSpace topics only
	// 4. If an attacker could bypass NATS auth, they'd have broader access than bootstrap provides
	// 5. Bootstrap is idempotent - calling it again just returns existing keys
	_ = req.BootstrapToken

	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	// Check if already bootstrapped
	if h.state.cekPair != nil && len(h.state.utkPairs) > 0 {
		log.Info().Str("owner_space", h.ownerSpace).Msg("Vault already bootstrapped, returning existing keys")
		return h.buildBootstrapResponse(msg.GetID(), false)
	}

	// Generate ECIES keypair if not already generated
	if h.state.eciesPrivateKey == nil {
		if err := h.generateECIESKeypair(); err != nil {
			return h.errorResponse(msg.GetID(), "failed to generate ECIES keypair")
		}
	}

	// Generate CEK keypair (X25519)
	cekPrivateKey := make([]byte, 32)
	if _, err := rand.Read(cekPrivateKey); err != nil {
		log.Error().Err(err).Msg("Failed to generate CEK private key")
		return h.errorResponse(msg.GetID(), "failed to generate CEK")
	}

	cekPublicKey, err := curve25519.X25519(cekPrivateKey, curve25519.Basepoint)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive CEK public key")
		return h.errorResponse(msg.GetID(), "failed to derive CEK public key")
	}

	h.state.cekPair = &CEKPair{
		PublicKey:  cekPublicKey,
		PrivateKey: cekPrivateKey,
		Version:    1,
		CreatedAt:  time.Now().Unix(),
	}

	// Generate initial batch of UTK/LTK pairs (5 pairs)
	const initialUTKCount = 5
	h.state.utkPairs = make([]*UTKPair, 0, initialUTKCount)
	for i := 0; i < initialUTKCount; i++ {
		pair, err := h.generateUTKPair()
		if err != nil {
			log.Error().Err(err).Int("index", i).Msg("Failed to generate UTK pair")
			continue
		}
		h.state.utkPairs = append(h.state.utkPairs, pair)
	}

	if len(h.state.utkPairs) == 0 {
		return h.errorResponse(msg.GetID(), "failed to generate UTK pairs")
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Int("utk_count", len(h.state.utkPairs)).
		Int("cek_version", h.state.cekPair.Version).
		Msg("Bootstrap completed - keys generated")

	// Credential not yet created - app needs to set password
	return h.buildBootstrapResponse(msg.GetID(), true)
}

// generateECIESKeypair generates the ECIES keypair for encrypting PIN/password
func (h *BootstrapHandler) generateECIESKeypair() error {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return fmt.Errorf("failed to generate ECIES private key: %w", err)
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("failed to derive ECIES public key: %w", err)
	}

	h.state.eciesPrivateKey = privateKey
	h.state.eciesPublicKey = publicKey
	return nil
}

// generateUTKPair creates a new UTK/LTK pair
func (h *BootstrapHandler) generateUTKPair() (*UTKPair, error) {
	// Generate X25519 private key (LTK)
	ltk := make([]byte, 32)
	if _, err := rand.Read(ltk); err != nil {
		return nil, fmt.Errorf("failed to generate LTK: %w", err)
	}

	// Derive public key (UTK)
	utk, err := curve25519.X25519(ltk, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive UTK: %w", err)
	}

	// Generate unique ID
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("failed to generate UTK ID: %w", err)
	}

	return &UTKPair{
		UTK:       utk,
		LTK:       ltk,
		ID:        fmt.Sprintf("utk-%x", idBytes),
		CreatedAt: time.Now().Unix(),
	}, nil
}

// buildBootstrapResponse creates the response for bootstrap
func (h *BootstrapHandler) buildBootstrapResponse(requestID string, requiresPassword bool) (*OutgoingMessage, error) {
	// Encode UTKs as base64
	utks := make([]string, 0, len(h.state.utkPairs))
	for _, pair := range h.state.utkPairs {
		if pair.UsedAt == 0 { // Only include unused UTKs
			// Encode as: id:base64(utk)
			encoded := pair.ID + ":" + base64.StdEncoding.EncodeToString(pair.UTK)
			utks = append(utks, encoded)
		}
	}

	response := BootstrapResponse{
		Status:           "bootstrapped",
		UTKs:             utks,
		ECIESPublicKey:   base64.StdEncoding.EncodeToString(h.state.eciesPublicKey),
		EnclavePublicKey: "", // Will be set after credential creation
		Capabilities:     []string{"call", "sign", "store", "connect"},
		RequiresPassword: requiresPassword && h.state.credential == nil,
		RequiresPIN:      true, // Always require PIN for DEK derivation
	}

	// If credential exists, include the enclave public key
	if h.state.credential != nil {
		response.EnclavePublicKey = base64.StdEncoding.EncodeToString(h.state.credential.IdentityPublicKey)
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal bootstrap response")
		return h.errorResponse(requestID, "failed to create response")
	}

	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   responseBytes,
	}, nil
}

// GenerateMoreUTKs generates additional UTK pairs (called when running low)
func (h *BootstrapHandler) GenerateMoreUTKs(count int) error {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	for i := 0; i < count; i++ {
		pair, err := h.generateUTKPair()
		if err != nil {
			return err
		}
		h.state.utkPairs = append(h.state.utkPairs, pair)
	}
	return nil
}

// GetUnusedUTKs returns the list of unused UTKs
func (h *BootstrapHandler) GetUnusedUTKs() []string {
	h.state.mu.RLock()
	defer h.state.mu.RUnlock()

	utks := make([]string, 0)
	for _, pair := range h.state.utkPairs {
		if pair.UsedAt == 0 {
			encoded := pair.ID + ":" + base64.StdEncoding.EncodeToString(pair.UTK)
			utks = append(utks, encoded)
		}
	}
	return utks
}

// MarkUTKUsed marks a UTK as used
func (h *BootstrapHandler) MarkUTKUsed(utkID string) bool {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	for _, pair := range h.state.utkPairs {
		if pair.ID == utkID && pair.UsedAt == 0 {
			pair.UsedAt = time.Now().Unix()
			return true
		}
	}
	return false
}

// GetLTKForUTK retrieves the LTK (private key) for a given UTK ID
func (h *BootstrapHandler) GetLTKForUTK(utkID string) ([]byte, bool) {
	h.state.mu.RLock()
	defer h.state.mu.RUnlock()

	for _, pair := range h.state.utkPairs {
		if pair.ID == utkID {
			return pair.LTK, true
		}
	}
	return nil, false
}

func (h *BootstrapHandler) errorResponse(requestID string, errMsg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeError,
		Error:     errMsg,
	}, nil
}
