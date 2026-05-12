package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
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
	ownerSpace  string
	state       *VaultState
	storage     *EncryptedStorage
	bootstrap   *BootstrapHandler
	sealerProxy *SealerProxy
	auditLog    *AuditLog

	// pendingVotes holds receipts that the vault signed but couldn't ship
	// to the parent (network blip, parent not yet ready, etc). Drained on
	// the next successful submit or via vote.resubmit-pending.
	pendingMu    sync.Mutex
	pendingVotes []pendingVote
}

// pendingVote is a vault-signed receipt awaiting submission to DynamoDB.
type pendingVote struct {
	ProposalID      string `json:"proposal_id"`
	Vote            string `json:"vote"`
	VotedAt         string `json:"voted_at"`
	VotingPublicKey string `json:"voting_public_key"`
	VoteSignature   string `json:"vote_signature"`
	SignedPayload   string `json:"signed_payload"`
}

// SetAuditLog wires the per-connection audit trail so vote proposals
// and tallies land on the VettID system connection.
func (h *VoteHandler) SetAuditLog(a *AuditLog) { h.auditLog = a }

// NewVoteHandler creates a new vote handler
func NewVoteHandler(ownerSpace string, state *VaultState, storage *EncryptedStorage, bootstrap *BootstrapHandler) *VoteHandler {
	return &VoteHandler{
		ownerSpace: ownerSpace,
		state:      state,
		storage:    storage,
		bootstrap:  bootstrap,
	}
}

// consumeIdentityKey is the VoteHandler shim around the shared TTL gate.
func (h *VoteHandler) consumeIdentityKey() ([]byte, error) {
	return consumeIdentityKeyFromState(h.state, h.storage)
}

// auditIdentityKey records identity-key use for voting operations.
// Mirrors MessageHandler.auditIdentityKey so the same event type
// (AuditTypeIdentityKeyUsed) shows up regardless of which subsystem
// signed. VoteHandler stays self-contained — it doesn't borrow the
// MessageHandler reference just for audit.
func (h *VoteHandler) auditIdentityKey(purpose string, refs map[string]string) {
	if h.auditLog == nil {
		return
	}
	h.auditLog.AppendSystem(AuditEntry{
		EventType: AuditTypeIdentityKeyUsed,
		Direction: AuditDirectionInternal,
		Title:     "Identity key used: " + purpose,
		Refs:      refs,
		Metadata:  map[string]string{"purpose": purpose},
	})
}

// SetSealerProxy sets the sealer proxy for proposals list access
func (h *VoteHandler) SetSealerProxy(sp *SealerProxy) {
	h.sealerProxy = sp
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
	EncryptedPasswordHash string `json:"encrypted_password_hash"`
	EphemeralPublicKey    string `json:"ephemeral_public_key"`
	Nonce                 string `json:"nonce"`
	KeyID                 string `json:"password_key_id"`
	// Phase D: caller supplies the encrypted credential blob so the
	// vault can verify the password against it without holding the
	// credential plaintext in memory.
	EncryptedCredential string `json:"encrypted_credential,omitempty"`
	// Dynamic choices — if provided, vote must be in this list
	ValidChoices []string `json:"valid_choices,omitempty"`
}

// CastVoteResponse is returned after successful vote signing
//
// Status values:
//   - "submitted": vault signed AND backend accepted the vote
//   - "queued": vault signed but submission failed; vault will retry
//     automatically on the next vote.resubmit-pending call. The receipt is
//     still valid and the user has voted from a privacy standpoint — the
//     row just hasn't landed in DynamoDB yet.
//   - "duplicate": this voting public key already submitted on this proposal
//     (idempotent re-cast — UI should treat as success)
type CastVoteResponse struct {
	Status          string   `json:"status"`
	ProposalID      string   `json:"proposal_id"`
	Vote            string   `json:"vote"`
	VotingPublicKey string   `json:"voting_public_key"` // Base64-encoded derived public key
	VoteSignature   string   `json:"vote_signature"`    // Base64-encoded Ed25519 signature
	SignedPayload   string   `json:"signed_payload"`    // The canonical payload that was signed
	VotedAt         string   `json:"voted_at"`
	SubmitError     string   `json:"submit_error,omitempty"` // populated when status="queued"
	NewUTKs         []string `json:"new_utks,omitempty"`     // Replacement UTKs after consumption
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
	if err := unmarshalRequest(msg.Payload, &req, "HandleCastVote"); err != nil {
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

	// Phase E: voting is high-stakes — always require fresh password
	// authorization in addition to the TTL gate. The password verify
	// decrypts the request-supplied credential blob and pulls the
	// identity key directly from it, so we never rely on the in-memory
	// carve-out for vote signing.
	if req.EncryptedPasswordHash == "" || req.EphemeralPublicKey == "" || req.Nonce == "" || req.KeyID == "" {
		return h.errorResponse(msg.GetID(), "password authorization required")
	}
	if req.EncryptedCredential == "" {
		return h.errorResponse(msg.GetID(), "encrypted_credential required for vote authorization")
	}
	idKey, err := h.revealIdentityViaPasswordedBlob(
		req.EncryptedCredential,
		req.EncryptedPasswordHash,
		req.EphemeralPublicKey,
		req.Nonce,
		req.KeyID,
	)
	if err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Vote password verification failed")
		return h.errorResponse(msg.GetID(), err.Error())
	}
	defer zeroBytes(idKey)

	// Derive voting keypair using HKDF
	// Derivation: HKDF-SHA256(identity_private_key, proposal_id, "vettid-vote-v1")
	votingPrivateKey, votingPublicKey, err := h.deriveVotingKeypair(idKey, req.ProposalID)
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
	// Identity-key audit: the vote signing uses an HKDF-derived child of
	// the user's identity key, but the act of voting still pivots on
	// the identity key being unlocked. Audit the act so the user sees
	// "vote cast" reflected in their identity-key usage trail.
	h.auditIdentityKey("vote_cast", map[string]string{
		"proposal_id": req.ProposalID,
	})

	// Encode results as base64
	votingPublicKeyB64 := base64.StdEncoding.EncodeToString(votingPublicKey)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("proposal_id", req.ProposalID).
		Str("vote", req.Vote).
		Str("voting_key_prefix", votingPublicKeyB64[:16]+"...").
		Msg("Vote signed successfully")

	// Build the receipt the parent expects (mirrors SignedVoteSubmission in
	// enclave/parent/vote_validator.go). The vault submits it directly via
	// the sealer proxy — the app never sees the signature.
	pv := pendingVote{
		ProposalID:      req.ProposalID,
		Vote:            req.Vote,
		VotedAt:         votedAt,
		VotingPublicKey: votingPublicKeyB64,
		VoteSignature:   signatureB64,
		SignedPayload:   signedPayload,
	}
	status, submitErr := h.submitVote(pv, false)

	// Generate fresh replacement UTKs and return ONLY the new ones
	// (not GetUnusedUTKs which returns the full vault pool).
	newPairs, err := h.bootstrap.GenerateMoreUTKs(3)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate replacement UTKs")
	}
	newUTKs := EncodeUTKs(newPairs)

	response := CastVoteResponse{
		Status:          status,
		ProposalID:      req.ProposalID,
		Vote:            req.Vote,
		VotingPublicKey: votingPublicKeyB64,
		VoteSignature:   signatureB64,
		SignedPayload:   signedPayload,
		VotedAt:         votedAt,
		NewUTKs:         newUTKs,
	}
	if submitErr != nil {
		response.SubmitError = submitErr.Error()
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

// submitVote ships a signed receipt to the parent for DynamoDB write. On
// network/parent failure the receipt is queued in pendingVotes for retry via
// vote.resubmit-pending. Returns the wire-level status string the app sees
// in CastVoteResponse.
func (h *VoteHandler) submitVote(pv pendingVote, isResubmit bool) (string, error) {
	if h.sealerProxy == nil {
		h.queuePendingVote(pv)
		return "queued", fmt.Errorf("sealer proxy not available")
	}

	envelope := struct {
		Resubmit bool        `json:"resubmit,omitempty"`
		Vote     pendingVote `json:"vote"`
	}{Resubmit: isResubmit, Vote: pv}
	body, err := json.Marshal(envelope)
	if err != nil {
		return "queued", fmt.Errorf("marshal vote envelope: %w", err)
	}

	result, err := h.sealerProxy.SubmitSignedVote(body)
	if err != nil {
		log.Warn().Err(err).
			Str("proposal_id", pv.ProposalID).
			Str("voting_pk_prefix", pv.VotingPublicKey[:min(16, len(pv.VotingPublicKey))]+"...").
			Msg("Vote submission failed; queueing for retry")
		h.queuePendingVote(pv)
		return "queued", err
	}
	if result.AlreadyVoted {
		log.Info().Str("proposal_id", pv.ProposalID).Msg("Vote already recorded (idempotent)")
		return "duplicate", nil
	}
	log.Info().Str("proposal_id", pv.ProposalID).Msg("Vote submitted to backend")
	return "submitted", nil
}

func (h *VoteHandler) queuePendingVote(pv pendingVote) {
	h.pendingMu.Lock()
	defer h.pendingMu.Unlock()
	// Skip if we already have this exact (proposal_id, voting_public_key)
	for _, existing := range h.pendingVotes {
		if existing.ProposalID == pv.ProposalID && existing.VotingPublicKey == pv.VotingPublicKey {
			return
		}
	}
	h.pendingVotes = append(h.pendingVotes, pv)
}

// HandleResubmitPendingVotes drains the in-memory pending queue. Called by
// the app (vote.resubmit-pending) when connectivity is restored, or by the
// recovery script for one-off rescues. Each pending receipt is submitted
// with the resubmit flag so the parent skips its 5-minute timestamp window.
func (h *VoteHandler) HandleResubmitPendingVotes(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	h.pendingMu.Lock()
	queued := append([]pendingVote(nil), h.pendingVotes...)
	h.pendingVotes = h.pendingVotes[:0]
	h.pendingMu.Unlock()

	type itemResult struct {
		ProposalID      string `json:"proposal_id"`
		VotingPublicKey string `json:"voting_public_key"`
		Status          string `json:"status"`
		Error           string `json:"error,omitempty"`
	}
	results := make([]itemResult, 0, len(queued))
	requeued := 0
	for _, pv := range queued {
		status, err := h.submitVote(pv, true)
		ir := itemResult{ProposalID: pv.ProposalID, VotingPublicKey: pv.VotingPublicKey, Status: status}
		if err != nil {
			ir.Error = err.Error()
			requeued++
		}
		results = append(results, ir)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"status":         "ok",
		"processed":      len(queued),
		"still_queued":   requeued,
		"items":          results,
	})
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   body,
	}, nil
}

// VerifyVoteRequest asks the vault to fetch a Merkle inclusion proof for a
// previously cast vote and verify it locally. Used by the app's "Verify my
// vote" UX on closed proposals.
type VerifyVoteRequest struct {
	ProposalID string `json:"proposal_id"`
	// Optional: when present, override the derivation. Normally the vault
	// re-derives the voting key from identity + proposal_id.
	VotingPublicKey string `json:"voting_public_key,omitempty"`
}

// VerifyVoteResponse is the result returned to the app.
type VerifyVoteResponse struct {
	Verified        bool   `json:"verified"`
	ProposalID      string `json:"proposal_id"`
	VotingPublicKey string `json:"voting_public_key,omitempty"`
	LeafIndex       int    `json:"leaf_index,omitempty"`
	Total           int    `json:"total,omitempty"`
	MerkleRoot      string `json:"merkle_root,omitempty"`
	Vote            string `json:"vote,omitempty"`
	Error           string `json:"error,omitempty"`
}

// HandleVerifyVote re-derives the user's voting public key for the given
// proposal, asks the parent for the published Merkle proof, and verifies it
// locally inside the enclave. The vault is the source of truth on whether a
// vote was counted — the app only renders the boolean.
func (h *VoteHandler) HandleVerifyVote(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req VerifyVoteRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleVerifyVote"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}
	if req.ProposalID == "" {
		return h.errorResponse(msg.GetID(), "proposal_id is required")
	}

	// Re-derive the voting public key if not explicitly provided.
	// Phase E: verify-vote is read-only — uses the same TTL gate as
	// other signing ops via mh.consumeIdentityKey, but the value
	// returned is only used as HKDF input for public-key derivation.
	vk := req.VotingPublicKey
	if vk == "" {
		idKey, err := h.consumeIdentityKey()
		if err != nil {
			return h.errorResponse(msg.GetID(), "identity_locked")
		}
		defer zeroBytes(idKey)
		_, pubKey, err := h.deriveVotingKeypair(idKey, req.ProposalID)
		if err != nil {
			return h.errorResponse(msg.GetID(), "key derivation failed")
		}
		vk = base64.StdEncoding.EncodeToString(pubKey)
	}

	if h.sealerProxy == nil {
		return h.respondJSON(msg.GetID(), VerifyVoteResponse{
			Verified: false, ProposalID: req.ProposalID, VotingPublicKey: vk,
			Error: "sealer proxy not available",
		})
	}

	proofData, err := h.sealerProxy.GetVoteProof(req.ProposalID, vk)
	if err != nil {
		return h.respondJSON(msg.GetID(), VerifyVoteResponse{
			Verified: false, ProposalID: req.ProposalID, VotingPublicKey: vk,
			Error: err.Error(),
		})
	}

	var proof struct {
		MerkleRoot string                   `json:"merkle_root"`
		LeafHash   string                   `json:"leaf_hash"`
		LeafIndex  int                      `json:"leaf_index"`
		Total      int                      `json:"total"`
		ProofPath  []map[string]interface{} `json:"proof_path"`
		Vote       map[string]interface{}   `json:"vote"`
	}
	if err := json.Unmarshal(proofData, &proof); err != nil {
		return h.respondJSON(msg.GetID(), VerifyVoteResponse{
			Verified: false, ProposalID: req.ProposalID, VotingPublicKey: vk,
			Error: "decode proof: " + err.Error(),
		})
	}

	// Recompute leaf hash inside the enclave so we never trust the parent's
	// claim about which choice the user voted for.
	choice, _ := proof.Vote["vote"].(string)
	sig, _ := proof.Vote["vote_signature"].(string)
	leaf := fmt.Sprintf("%s|%s|%s", vk, choice, sig)
	if hashHex(leaf) != proof.LeafHash {
		return h.respondJSON(msg.GetID(), VerifyVoteResponse{
			Verified: false, ProposalID: req.ProposalID, VotingPublicKey: vk,
			Error: "leaf hash mismatch (vote tampered)",
		})
	}

	// Walk the path and compare against the published root.
	cur := proof.LeafHash
	for _, step := range proof.ProofPath {
		hStr, _ := step["hash"].(string)
		dir, _ := step["direction"].(string)
		if dir == "left" {
			cur = hashHex(hStr + cur)
		} else {
			cur = hashHex(cur + hStr)
		}
	}
	verified := cur == proof.MerkleRoot && strings.TrimSpace(proof.MerkleRoot) != ""

	return h.respondJSON(msg.GetID(), VerifyVoteResponse{
		Verified:        verified,
		ProposalID:      req.ProposalID,
		VotingPublicKey: vk,
		LeafIndex:       proof.LeafIndex,
		Total:           proof.Total,
		MerkleRoot:      proof.MerkleRoot,
		Vote:            choice,
	})
}

func (h *VoteHandler) respondJSON(reqID string, payload interface{}) (*OutgoingMessage, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return h.errorResponse(reqID, "response serialization failed")
	}
	return &OutgoingMessage{
		RequestID: reqID,
		Type:      MessageTypeResponse,
		Payload:   body,
	}, nil
}

func hashHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// revealIdentityViaPasswordedBlob (Phase E) decrypts the request-supplied
// encrypted credential blob, verifies the encrypted password hash against
// THAT decrypted credential, and on success returns a fresh copy of the
// user's Ed25519 identity private key. The decrypted credential is
// securely erased before this function returns; the caller owns the
// returned key and must zero it out (defer zeroBytes(idKey)).
//
// Vote signing always uses this path — the in-memory carve-out is never
// consulted, so casting a vote always requires fresh password
// authorization.
func (h *VoteHandler) revealIdentityViaPasswordedBlob(encryptedCredential, encryptedPasswordHash, ephemeralPublicKey, nonce, keyID string) ([]byte, error) {
	// Decrypt the credential blob in-flight via the CEK still cached
	// on vaultState.
	encBytes, err := base64.StdEncoding.DecodeString(encryptedCredential)
	if err != nil {
		return nil, fmt.Errorf("invalid credential encoding: %w", err)
	}
	h.state.mu.RLock()
	cekPair := h.state.cekPair
	h.state.mu.RUnlock()
	if cekPair == nil {
		return nil, fmt.Errorf("CEK not available")
	}
	plaintext, err := decryptWithCEK(cekPair.PrivateKey, encBytes)
	if err != nil {
		return nil, fmt.Errorf("CEK decryption failed: %w", err)
	}
	defer zeroBytes(plaintext)
	var cred ProteanCredentialV2
	if err := json.Unmarshal(plaintext, &cred); err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}
	defer cred.SecureErase()

	// Get the LTK for the provided UTK ID and decrypt the
	// password-hash envelope.
	ltk, found := h.bootstrap.GetLTKForUTK(keyID)
	if !found {
		return nil, fmt.Errorf("invalid or expired UTK")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedPasswordHash)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted_password_hash encoding")
	}
	ephPubKey, err := base64.StdEncoding.DecodeString(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral_public_key encoding")
	}
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce encoding")
	}
	combinedPayload := make([]byte, 0, len(ephPubKey)+len(nonceBytes)+len(ciphertext))
	combinedPayload = append(combinedPayload, ephPubKey...)
	combinedPayload = append(combinedPayload, nonceBytes...)
	combinedPayload = append(combinedPayload, ciphertext...)
	passwordHashBytes, err := decryptWithUTK(ltk, combinedPayload)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	defer zeroBytes(passwordHashBytes)

	// SECURITY (crypto-H2): UTK is single-use on AEAD success — burn
	// it before evaluating the password match so a leaked UTK can't
	// be replayed against an online password-guessing oracle.
	h.bootstrap.MarkUTKUsed(keyID)

	passwordHash := string(passwordHashBytes)
	var payload struct {
		PasswordHash string `json:"password_hash"`
	}
	if err := json.Unmarshal(passwordHashBytes, &payload); err == nil && payload.PasswordHash != "" {
		passwordHash = payload.PasswordHash
	}

	if !timingSafeEqualStrings(passwordHash, cred.Auth.Hash) {
		return nil, fmt.Errorf("incorrect password")
	}

	if len(cred.Identity.PrivateKey) == 0 {
		return nil, fmt.Errorf("identity key not present in credential")
	}
	idKey := make([]byte, len(cred.Identity.PrivateKey))
	copy(idKey, cred.Identity.PrivateKey)

	return idKey, nil
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

// HandleListProposals fetches active/upcoming/published proposals from DynamoDB via the parent.
func (h *VoteHandler) HandleListProposals(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("List proposals requested")

	if h.state == nil {
		return h.errorResponse(msg.GetID(), "vault not initialized")
	}

	if h.sealerProxy == nil {
		return h.errorResponse(msg.GetID(), "sealer proxy not available")
	}

	data, err := h.sealerProxy.ListProposals()
	if err != nil {
		log.Error().Err(err).Msg("Failed to list proposals")
		return h.errorResponse(msg.GetID(), fmt.Sprintf("failed to list proposals: %v", err))
	}

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   data,
	}, nil
}

// errorResponse creates an error response
func (h *VoteHandler) errorResponse(id string, errMsg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeError,
		Error:     errMsg,
	}, nil
}
