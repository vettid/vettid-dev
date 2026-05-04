package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/curve25519"
)

// SECURITY: Secret for verifying attestation binding tokens
// Must match the secret used by verifyNitroAttestation Lambda
var attestationBindingSecret = getAttestationBindingSecret()

func getAttestationBindingSecret() string {
	if secret := os.Getenv("ATTESTATION_BINDING_SECRET"); secret != "" {
		return secret
	}
	return "default-dev-secret-replace-in-production"
}

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

// verifyBindingToken verifies the HMAC token from attestation verification
// SECURITY: This prevents MITM attacks on the key exchange by binding it to attestation
//
// Token = HMAC-SHA256(session_id || app_public_key_hash || pcr_hash, secret)
func verifyBindingToken(sessionID, appPublicKey, pcrHash, token string) bool {
	if sessionID == "" || appPublicKey == "" || pcrHash == "" || token == "" {
		return false
	}

	// Compute hash of app's public key
	appKeyBytes, err := base64.StdEncoding.DecodeString(appPublicKey)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decode app public key for binding verification")
		return false
	}
	appKeyHash := sha256.Sum256(appKeyBytes)
	appKeyHashHex := hex.EncodeToString(appKeyHash[:])

	// Compute expected token
	data := fmt.Sprintf("%s:%s:%s", sessionID, strings.ToLower(appKeyHashHex), strings.ToLower(pcrHash))
	mac := hmac.New(sha256.New, []byte(attestationBindingSecret))
	mac.Write([]byte(data))
	expectedToken := hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison to prevent timing attacks
	return hmac.Equal([]byte(token), []byte(expectedToken))
}

// HandleBootstrap processes bootstrap requests
// This implements Phase 2 of the enrollment flow per Architecture v2.0 Section 5.6
// 1. Generate CEK keypair (for credential encryption)
// 2. Generate UTK/LTK pairs (for transport encryption)
// 3. Return UTKs and ECIES public key to app
//
// SECURITY: If attestation binding fields are provided, they are verified to prevent MITM attacks
func (h *BootstrapHandler) HandleBootstrap(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("Bootstrap requested")

	// Parse bootstrap request (optional)
	var req BootstrapRequest
	if len(msg.Payload) > 0 {
		if err := unmarshalRequest(msg.Payload, &req, "HandleBootstrap"); err != nil {
			log.Warn().Err(err).Msg("Failed to parse bootstrap request")
			// Continue anyway - bootstrap token validation is optional
		}
	}

	// SECURITY: Verify attestation binding if provided
	// This prevents MITM attacks on the key exchange by binding it to attestation verification
	bindingVerified := false
	if req.SessionID != "" && req.AppPublicKey != "" && req.BindingToken != "" && req.PCRHash != "" {
		if verifyBindingToken(req.SessionID, req.AppPublicKey, req.PCRHash, req.BindingToken) {
			bindingVerified = true
			log.Info().
				Str("session_id", req.SessionID).
				Msg("Attestation binding verified - key exchange is MITM-protected")
		} else {
			log.Warn().
				Str("session_id", req.SessionID).
				Msg("SECURITY: Attestation binding verification FAILED - possible MITM attempt")
			// Don't fail the request - app may be using legacy flow without binding
			// But log prominently for security monitoring
		}
	} else if req.SessionID != "" {
		log.Debug().Str("session_id", req.SessionID).Msg("Bootstrap request missing binding fields (legacy flow)")
	}

	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	// Check if already bootstrapped
	if h.state.cekPair != nil && len(h.state.utkPairs) > 0 {
		log.Info().Str("owner_space", h.ownerSpace).Msg("Vault already bootstrapped, returning existing keys")
		return h.buildBootstrapResponse(msg.GetID(), false, bindingVerified)
	}

	// Generate ECIES keypair if not already generated
	if h.state.eciesPrivateKey == nil {
		log.Debug().Str("owner_space", h.ownerSpace).Msg("Generating ECIES keypair for cold vault recovery")
		if err := h.generateECIESKeypair(); err != nil {
			return h.errorResponse(msg.GetID(), "failed to generate ECIES keypair")
		}
		log.Info().
			Str("owner_space", h.ownerSpace).
			Int("ecies_public_len", len(h.state.eciesPublicKey)).
			Int("ecies_private_len", len(h.state.eciesPrivateKey)).
			Msg("ECIES keypair generated")
	} else {
		log.Debug().Str("owner_space", h.ownerSpace).Msg("ECIES keypair already exists")
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
		Bool("binding_verified", bindingVerified).
		Msg("Bootstrap completed - keys generated")

	// Credential not yet created - app needs to set password
	return h.buildBootstrapResponse(msg.GetID(), true, bindingVerified)
}

// GenerateECIESKeypairIfNeeded generates the ECIES keypair if not already present
// Returns true if keys were generated, false if they already existed
func (h *BootstrapHandler) GenerateECIESKeypairIfNeeded() (bool, error) {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	if h.state.eciesPrivateKey != nil {
		log.Debug().Str("owner_space", h.ownerSpace).Msg("ECIES keypair already exists")
		return false, nil
	}

	if err := h.generateECIESKeypairLocked(); err != nil {
		return false, err
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Int("ecies_public_len", len(h.state.eciesPublicKey)).
		Int("ecies_private_len", len(h.state.eciesPrivateKey)).
		Msg("ECIES keypair generated")

	return true, nil
}

// GetECIESKeys returns the ECIES keys for storage (copies to prevent race conditions)
func (h *BootstrapHandler) GetECIESKeys() (privateKey, publicKey []byte) {
	h.state.mu.RLock()
	defer h.state.mu.RUnlock()

	if h.state.eciesPrivateKey == nil || h.state.eciesPublicKey == nil {
		return nil, nil
	}

	// Return copies to prevent race conditions
	privateKey = make([]byte, len(h.state.eciesPrivateKey))
	publicKey = make([]byte, len(h.state.eciesPublicKey))
	copy(privateKey, h.state.eciesPrivateKey)
	copy(publicKey, h.state.eciesPublicKey)
	return privateKey, publicKey
}

// generateECIESKeypairLocked generates the ECIES keypair (caller must hold lock)
func (h *BootstrapHandler) generateECIESKeypairLocked() error {
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
func (h *BootstrapHandler) buildBootstrapResponse(requestID string, requiresPassword bool, bindingVerified bool) (*OutgoingMessage, error) {
	// Encode UTKs as base64
	utks := make([]string, 0, len(h.state.utkPairs))
	for _, pair := range h.state.utkPairs {
		if pair.UsedAt == 0 { // Only include unused UTKs
			// Encode as: id:base64(utk)
			encoded := pair.ID + ":" + base64.StdEncoding.EncodeToString(pair.UTK)
			utks = append(utks, encoded)
		}
	}

	// Phase D: surface readiness via the identity-public-key carve-
	// out so we can drop the full credential cache. A populated
	// identityPublicKey means PIN unlock has run and the credential
	// has been bound in this session.
	hasIdentity := len(h.state.identityPublicKey) > 0
	response := BootstrapResponse{
		Status:           "bootstrapped",
		UTKs:             utks,
		ECIESPublicKey:   base64.StdEncoding.EncodeToString(h.state.eciesPublicKey),
		EnclavePublicKey: "", // Will be set after credential creation
		Capabilities:     []string{"call", "sign", "store", "connect"},
		RequiresPassword: requiresPassword && !hasIdentity,
		RequiresPIN:      true, // Always require PIN for DEK derivation
		BindingVerified:  bindingVerified,
	}

	if hasIdentity {
		response.EnclavePublicKey = base64.StdEncoding.EncodeToString(h.state.identityPublicKey)
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

// MaxUnusedUTKs caps the number of unused UTK/LTK pairs kept in vault state.
// Oldest unused pairs are pruned when the pool exceeds this. Must stay ≥ the
// app-side cap (CredentialStore.UTK_POOL_MAX = 100) so the app's oldest pick
// still has a matching LTK in the vault. 200 leaves headroom for in-flight
// generation rounds.
const MaxUnusedUTKs = 200

// GenerateMoreUTKs generates additional UTK pairs (called when running low)
// and returns ONLY the freshly-generated ones so callers can send just the
// new ones to the app — not the entire vault pool.
//
// Historical bug: the pin-unlock + authenticate handlers used to generate N
// UTKs and then return GetUnusedUTKs(), which is the entire unused pool.
// The app appended everything, duplicates accumulated, and after many
// unlocks the app's UTK pool ballooned to tens of thousands (~14k observed),
// blowing up encrypted-prefs decrypt time on every unlock.
//
// Callers encode either as a "id:base64(utk)" string (see EncodeUTKs) or as
// UTKPublic objects (see EncodeUTKPublics) depending on the response shape.
func (h *BootstrapHandler) GenerateMoreUTKs(count int) ([]*UTKPair, error) {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	newPairs := make([]*UTKPair, 0, count)
	for i := 0; i < count; i++ {
		pair, err := h.generateUTKPair()
		if err != nil {
			return newPairs, err
		}
		h.state.utkPairs = append(h.state.utkPairs, pair)
		newPairs = append(newPairs, pair)
	}
	h.pruneUnusedUTKsLocked()
	return newPairs, nil
}

// pruneUnusedUTKsLocked drops the oldest unused pairs (FIFO) when the unused
// count exceeds MaxUnusedUTKs. Caller must hold h.state.mu.
func (h *BootstrapHandler) pruneUnusedUTKsLocked() {
	unused := 0
	for _, pair := range h.state.utkPairs {
		if pair.UsedAt == 0 {
			unused++
		}
	}
	excess := unused - MaxUnusedUTKs
	if excess <= 0 {
		return
	}
	kept := h.state.utkPairs[:0]
	pruned := 0
	for _, pair := range h.state.utkPairs {
		if pair.UsedAt == 0 && pruned < excess {
			zeroBytes(pair.LTK)
			pruned++
			continue
		}
		kept = append(kept, pair)
	}
	h.state.utkPairs = kept
	log.Debug().
		Str("owner_space", h.ownerSpace).
		Int("pruned", pruned).
		Int("remaining", len(h.state.utkPairs)).
		Msg("UTK pool pruned (oldest unused dropped)")
}

// EncodeUTKs encodes UTK pairs as "id:base64(utk)" strings (legacy wire format).
func EncodeUTKs(pairs []*UTKPair) []string {
	out := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, pair.ID+":"+base64.StdEncoding.EncodeToString(pair.UTK))
	}
	return out
}

// EncodeUTKPublics encodes UTK pairs as structured UTKPublic objects.
func EncodeUTKPublics(pairs []*UTKPair) []UTKPublic {
	out := make([]UTKPublic, len(pairs))
	for i, pair := range pairs {
		out[i] = UTKPublic{
			ID:        pair.ID,
			PublicKey: base64.StdEncoding.EncodeToString(pair.UTK),
		}
	}
	return out
}

// GetUnusedUTKs returns the list of unused UTKs as encoded strings
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

// GetUnusedUTKPairs returns the list of unused UTK pairs
func (h *BootstrapHandler) GetUnusedUTKPairs() []*UTKPair {
	h.state.mu.RLock()
	defer h.state.mu.RUnlock()

	pairs := make([]*UTKPair, 0)
	for _, pair := range h.state.utkPairs {
		if pair.UsedAt == 0 {
			pairs = append(pairs, pair)
		}
	}
	return pairs
}

// GenerateCEKPair generates a new CEK keypair for credential encryption
func (h *BootstrapHandler) GenerateCEKPair() error {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	// Generate X25519 keypair
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return fmt.Errorf("failed to generate CEK private key: %w", err)
	}

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	h.state.cekPair = &CEKPair{
		PublicKey:  publicKey[:],
		PrivateKey: privateKey[:],
		Version:    1,
		CreatedAt:  time.Now().Unix(),
	}

	log.Debug().
		Str("owner_space", h.ownerSpace).
		Msg("Generated CEK keypair")

	return nil
}

// MarkUTKUsed consumes a UTK. The pair is removed from the pool entirely —
// callers always do GetLTKForUTK → decrypt → MarkUTKUsed, so the LTK has no
// further use once marked. Keeping tombstones in place caused the pool to
// grow unbounded, slowing every GetLTKForUTK scan and every S3 state
// persist (each round-trip serializes the full slice).
func (h *BootstrapHandler) MarkUTKUsed(utkID string) bool {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	for i, pair := range h.state.utkPairs {
		if pair.ID == utkID && pair.UsedAt == 0 {
			zeroBytes(pair.LTK)
			h.state.utkPairs = append(h.state.utkPairs[:i], h.state.utkPairs[i+1:]...)
			return true
		}
	}
	return false
}

// GetLTKForUTK retrieves the LTK (private key) for a given UTK ID
func (h *BootstrapHandler) GetLTKForUTK(utkID string) ([]byte, bool) {
	h.state.mu.RLock()
	defer h.state.mu.RUnlock()

	log.Debug().
		Str("requested_utk_id", utkID).
		Int("total_utk_pairs", len(h.state.utkPairs)).
		Msg("DEBUG: Looking up LTK for UTK")

	for i, pair := range h.state.utkPairs {
		log.Debug().
			Int("index", i).
			Str("pair_id", pair.ID).
			Bool("is_used", pair.UsedAt != 0).
			Int("ltk_len", len(pair.LTK)).
			Msg("DEBUG: Checking UTK pair")
		if pair.ID == utkID {
			log.Info().
				Str("utk_id", utkID).
				Int("ltk_len", len(pair.LTK)).
				Msg("DEBUG: Found LTK for UTK")
			return pair.LTK, true
		}
	}
	log.Warn().Str("utk_id", utkID).Msg("DEBUG: UTK not found")
	return nil, false
}

func (h *BootstrapHandler) errorResponse(requestID string, errMsg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeError,
		Error:     errMsg,
	}, nil
}
