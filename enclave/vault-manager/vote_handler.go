package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/hkdf"
)

// VotingKeyDerivationInfo is the HKDF info for deriving voting keypairs
// This ensures derived keys are domain-separated from other uses
const VotingKeyDerivationInfo = "vettid-vote-v1"

// VoteHandler handles voting operations
// Voting requires the vault to be unlocked (credential loaded in memory)
type VoteHandler struct {
	ownerSpace string
	state      *VaultState
	bootstrap  *BootstrapHandler
}

// NewVoteHandler creates a new vote handler
func NewVoteHandler(ownerSpace string, state *VaultState, bootstrap *BootstrapHandler) *VoteHandler {
	return &VoteHandler{
		ownerSpace: ownerSpace,
		state:      state,
		bootstrap:  bootstrap,
	}
}

// CastVoteRequest is the request from the mobile app to cast a vote
type CastVoteRequest struct {
	ProposalID        string `json:"proposal_id"`
	ProposalTitle     string `json:"proposal_title,omitempty"`
	Vote              string `json:"vote"` // choice ID (e.g., "yes", "no", "option_a")
	ProposalSignature string `json:"proposal_signature"` // VettID's KMS signature (base64)
	OpensAt           string `json:"opens_at"`
	ClosesAt          string `json:"closes_at"`
	// Password authorization (encrypted with UTK)
	EncryptedPasswordHash string   `json:"encrypted_password_hash"`
	EphemeralPublicKey    string   `json:"ephemeral_public_key"`
	Nonce                 string   `json:"nonce"`
	KeyID                 string   `json:"password_key_id"`
	// Dynamic choices — if provided, vote must be in this list
	ValidChoices []string `json:"valid_choices,omitempty"`
}

// CastVoteResponse is returned after successful vote signing
type CastVoteResponse struct {
	Status          string   `json:"status"`
	ProposalID      string   `json:"proposal_id"`
	Vote            string   `json:"vote"`
	VotingPublicKey string   `json:"voting_public_key"` // Base64-encoded derived public key
	VoteSignature   string   `json:"vote_signature"`    // Base64-encoded Ed25519 signature
	SignedPayload   string   `json:"signed_payload"`    // The canonical payload that was signed
	VotedAt         string   `json:"voted_at"`
	NewUTKs         []string `json:"new_utks,omitempty"` // Replacement UTKs after consumption
}

// HandleCastVote processes a vote request
// Flow:
// 1. Verify vault is unlocked (credential exists)
// 2. Derive voting keypair from identity key + proposal_id
// 3. Create canonical signed payload
// 4. Sign with Ed25519 using derived private key
// 5. Return voting_public_key and signature
func (h *VoteHandler) HandleCastVote(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("Cast vote requested")

	// Parse request
	var req CastVoteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		log.Error().Err(err).Msg("Failed to parse vote request")
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	// Validate required fields
	if req.ProposalID == "" {
		return h.errorResponse(msg.GetID(), "proposal_id is required")
	}
	if req.Vote == "" {
		return h.errorResponse(msg.GetID(), "vote is required")
	}

	// Validate vote against valid choices (dynamic or default)
	if len(req.ValidChoices) > 0 {
		valid := false
		for _, c := range req.ValidChoices {
			if c == req.Vote {
				valid = true
				break
			}
		}
		if !valid {
			return h.errorResponse(msg.GetID(), fmt.Sprintf("vote must be one of: %v", req.ValidChoices))
		}
	}
	// If no valid choices provided, accept any non-empty vote string (validated on backend Lambda)

	// Verify vault is unlocked
	h.state.mu.RLock()
	credential := h.state.credential
	h.state.mu.RUnlock()

	if credential == nil {
		return h.errorResponse(msg.GetID(), "vault is locked - unlock with PIN first")
	}
	if credential.IdentityPrivateKey == nil || len(credential.IdentityPrivateKey) == 0 {
		return h.errorResponse(msg.GetID(), "identity key not available")
	}

	// SECURITY: Verify password before allowing vote
	if req.EncryptedPasswordHash == "" || req.EphemeralPublicKey == "" || req.Nonce == "" || req.KeyID == "" {
		return h.errorResponse(msg.GetID(), "password authorization required")
	}
	if err := h.verifyPassword(req.EncryptedPasswordHash, req.EphemeralPublicKey, req.Nonce, req.KeyID); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Vote password verification failed")
		return h.errorResponse(msg.GetID(), err.Error())
	}

	// Derive voting keypair using HKDF
	// Derivation: HKDF-SHA256(identity_private_key, proposal_id, "vettid-vote-v1")
	votingPrivateKey, votingPublicKey, err := h.deriveVotingKeypair(credential.IdentityPrivateKey, req.ProposalID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive voting keypair")
		return h.errorResponse(msg.GetID(), "key derivation failed")
	}
	// SECURITY: Zero voting private key after use
	defer zeroBytes(votingPrivateKey)

	// Create canonical signed payload: proposal_id|vote|timestamp
	votedAt := time.Now().UTC().Format(time.RFC3339)
	signedPayload := fmt.Sprintf("%s|%s|%s", req.ProposalID, req.Vote, votedAt)

	// Sign with Ed25519
	signature := ed25519.Sign(votingPrivateKey, []byte(signedPayload))

	// Encode results as base64
	votingPublicKeyB64 := base64.StdEncoding.EncodeToString(votingPublicKey)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("proposal_id", req.ProposalID).
		Str("vote", req.Vote).
		Str("voting_key_prefix", votingPublicKeyB64[:16]+"...").
		Msg("Vote signed successfully")

	// Generate replacement UTKs
	newUTKs := h.bootstrap.GetUnusedUTKs()

	// Build response
	response := CastVoteResponse{
		Status:          "success",
		ProposalID:      req.ProposalID,
		Vote:            req.Vote,
		VotingPublicKey: votingPublicKeyB64,
		VoteSignature:   signatureB64,
		SignedPayload:   signedPayload,
		VotedAt:         votedAt,
		NewUTKs:         newUTKs,
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal response")
		return h.errorResponse(msg.GetID(), "response serialization failed")
	}

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   responseBytes,
	}, nil
}

// verifyPassword verifies the encrypted password hash against the stored credential
// Uses the same pattern as CredentialSecretHandler.verifyPassword
func (h *VoteHandler) verifyPassword(encryptedPasswordHash, ephemeralPublicKey, nonce, keyID string) error {
	// Get the LTK for the provided UTK ID
	ltk, found := h.bootstrap.GetLTKForUTK(keyID)
	if !found {
		return fmt.Errorf("invalid or expired UTK")
	}

	// Decode the three separate base64-encoded components
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedPasswordHash)
	if err != nil {
		return fmt.Errorf("invalid encrypted_password_hash encoding")
	}

	ephPubKey, err := base64.StdEncoding.DecodeString(ephemeralPublicKey)
	if err != nil {
		return fmt.Errorf("invalid ephemeral_public_key encoding")
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("invalid nonce encoding")
	}

	// Combine into format expected by decryptWithUTK: pubkey(32) || nonce(24) || ciphertext
	combinedPayload := make([]byte, 0, len(ephPubKey)+len(nonceBytes)+len(ciphertext))
	combinedPayload = append(combinedPayload, ephPubKey...)
	combinedPayload = append(combinedPayload, nonceBytes...)
	combinedPayload = append(combinedPayload, ciphertext...)

	// Decrypt using the LTK
	passwordHashBytes, err := decryptWithUTK(ltk, combinedPayload)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	defer zeroBytes(passwordHashBytes)

	// Parse decrypted payload - the app sends a PHC string (may be raw or JSON-wrapped)
	passwordHash := string(passwordHashBytes)
	var payload struct {
		PasswordHash string `json:"password_hash"`
	}
	if err := json.Unmarshal(passwordHashBytes, &payload); err == nil && payload.PasswordHash != "" {
		passwordHash = payload.PasswordHash
	}

	// Get the stored credential's password hash
	h.state.mu.RLock()
	credential := h.state.credential
	h.state.mu.RUnlock()

	if credential == nil {
		return fmt.Errorf("no credential available")
	}

	// Compare PHC strings directly (constant-time comparison)
	if !timingSafeEqualStrings(passwordHash, credential.PasswordHash) {
		return fmt.Errorf("incorrect password")
	}

	// Mark UTK as used (single-use for security)
	h.bootstrap.MarkUTKUsed(keyID)

	return nil
}

// deriveVotingKeypair derives a unique Ed25519 keypair for voting on a specific proposal
// This ensures that:
// 1. Each proposal gets a different voting key (unlinkable votes across proposals)
// 2. The same user always derives the same key for the same proposal (deterministic)
// 3. The voting key cannot be linked back to the identity key without the proposal_id
func (h *VoteHandler) deriveVotingKeypair(identityPrivateKey []byte, proposalID string) (privateKey, publicKey []byte, err error) {
	// Use the seed portion of the Ed25519 private key (first 32 bytes)
	// Ed25519 private keys are 64 bytes: 32-byte seed + 32-byte public key
	if len(identityPrivateKey) < ed25519.SeedSize {
		return nil, nil, fmt.Errorf("invalid identity private key length")
	}
	identitySeed := identityPrivateKey[:ed25519.SeedSize]

	// Derive voting seed using HKDF
	// Salt: SHA256(proposal_id) - ensures unique derivation per proposal
	// Info: "vettid-vote-v1" - domain separation
	saltBytes := sha256.Sum256([]byte(proposalID))

	hkdfReader := hkdf.New(sha256.New, identitySeed, saltBytes[:], []byte(VotingKeyDerivationInfo))

	// Read 32 bytes for the voting seed
	votingSeed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(hkdfReader, votingSeed); err != nil {
		return nil, nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	defer zeroBytes(votingSeed) // SECURITY: Zero intermediate key material

	// Generate Ed25519 keypair from the derived seed
	votingPrivateKey := ed25519.NewKeyFromSeed(votingSeed)
	votingPublicKey := votingPrivateKey.Public().(ed25519.PublicKey)

	return votingPrivateKey, votingPublicKey, nil
}

// errorResponse creates an error response
func (h *VoteHandler) errorResponse(id string, errMsg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeError,
		Error:     errMsg,
	}, nil
}
