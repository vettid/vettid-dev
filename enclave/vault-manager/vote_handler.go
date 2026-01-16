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
}

// NewVoteHandler creates a new vote handler
func NewVoteHandler(ownerSpace string, state *VaultState) *VoteHandler {
	return &VoteHandler{
		ownerSpace: ownerSpace,
		state:      state,
	}
}

// CastVoteRequest is the request from the mobile app to cast a vote
type CastVoteRequest struct {
	ProposalID        string `json:"proposal_id"`
	ProposalTitle     string `json:"proposal_title,omitempty"`
	Vote              string `json:"vote"` // "yes", "no", "abstain"
	ProposalSignature string `json:"proposal_signature"` // VettID's KMS signature (base64)
	OpensAt           string `json:"opens_at"`
	ClosesAt          string `json:"closes_at"`
}

// CastVoteResponse is returned after successful vote signing
type CastVoteResponse struct {
	Status          string `json:"status"`
	ProposalID      string `json:"proposal_id"`
	Vote            string `json:"vote"`
	VotingPublicKey string `json:"voting_public_key"` // Base64-encoded derived public key
	VoteSignature   string `json:"vote_signature"`    // Base64-encoded Ed25519 signature
	SignedPayload   string `json:"signed_payload"`    // The canonical payload that was signed
	VotedAt         string `json:"voted_at"`
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
	if req.Vote != "yes" && req.Vote != "no" && req.Vote != "abstain" {
		return h.errorResponse(msg.GetID(), "vote must be 'yes', 'no', or 'abstain'")
	}

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

	// Build response
	response := CastVoteResponse{
		Status:          "success",
		ProposalID:      req.ProposalID,
		Vote:            req.Vote,
		VotingPublicKey: votingPublicKeyB64,
		VoteSignature:   signatureB64,
		SignedPayload:   signedPayload,
		VotedAt:         votedAt,
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
