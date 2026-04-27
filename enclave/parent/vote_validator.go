package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SignedVoteSubmission is the payload the vault sends to the parent for
// submission to DynamoDB. The vault signs `signed_payload` with the
// per-proposal voting Ed25519 private key derived from the user's identity
// key. The parent re-verifies the signature before any write.
type SignedVoteSubmission struct {
	ProposalID      string `json:"proposal_id"`
	Vote            string `json:"vote"`
	VotedAt         string `json:"voted_at"`
	VotingPublicKey string `json:"voting_public_key"` // base64
	VoteSignature   string `json:"vote_signature"`    // base64
	SignedPayload   string `json:"signed_payload"`    // canonical: proposal_id|vote|voted_at
}

// ValidateSignedVote performs the same checks the previous Lambda
// (`receiveSignedVote.ts`) did, in Go, before any DynamoDB write:
//   - All required fields present
//   - signed_payload structurally matches `proposal_id|vote|voted_at`
//   - signed_payload fields agree with the top-level submission fields
//   - voting_public_key is a 32-byte Ed25519 key (base64-decoded)
//   - voted_at parses as RFC3339 and is within the maxAge window
//   - Ed25519 signature is valid
//
// maxAge of 0 disables the timestamp window check (used by resubmit path
// for receipts cached locally on a phone that may have been offline for
// hours/days).
func ValidateSignedVote(payload []byte, maxAge time.Duration) (*SignedVoteSubmission, error) {
	var sub SignedVoteSubmission
	if err := json.Unmarshal(payload, &sub); err != nil {
		return nil, fmt.Errorf("invalid submission JSON: %w", err)
	}

	if sub.ProposalID == "" {
		return nil, fmt.Errorf("proposal_id is required")
	}
	if sub.Vote == "" {
		return nil, fmt.Errorf("vote is required")
	}
	if sub.VotedAt == "" {
		return nil, fmt.Errorf("voted_at is required")
	}
	if sub.VotingPublicKey == "" {
		return nil, fmt.Errorf("voting_public_key is required")
	}
	if sub.VoteSignature == "" {
		return nil, fmt.Errorf("vote_signature is required")
	}
	if sub.SignedPayload == "" {
		return nil, fmt.Errorf("signed_payload is required")
	}

	parts := strings.Split(sub.SignedPayload, "|")
	if len(parts) != 3 {
		return nil, fmt.Errorf("signed_payload must be proposal_id|vote|voted_at")
	}
	if parts[0] != sub.ProposalID {
		return nil, fmt.Errorf("signed_payload proposal_id mismatch")
	}
	if parts[1] != sub.Vote {
		return nil, fmt.Errorf("signed_payload vote mismatch")
	}
	if parts[2] != sub.VotedAt {
		return nil, fmt.Errorf("signed_payload voted_at mismatch")
	}

	pubKey, err := base64.StdEncoding.DecodeString(sub.VotingPublicKey)
	if err != nil {
		return nil, fmt.Errorf("voting_public_key not valid base64: %w", err)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("voting_public_key must be %d bytes", ed25519.PublicKeySize)
	}

	sig, err := base64.StdEncoding.DecodeString(sub.VoteSignature)
	if err != nil {
		return nil, fmt.Errorf("vote_signature not valid base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("vote_signature must be %d bytes", ed25519.SignatureSize)
	}

	votedAt, err := time.Parse(time.RFC3339, sub.VotedAt)
	if err != nil {
		return nil, fmt.Errorf("voted_at not RFC3339: %w", err)
	}
	if maxAge > 0 {
		age := time.Since(votedAt)
		if age < -maxAge || age > maxAge {
			return nil, fmt.Errorf("voted_at outside acceptance window (age=%s, max=%s)", age, maxAge)
		}
	}

	if !ed25519.Verify(pubKey, []byte(sub.SignedPayload), sig) {
		return nil, fmt.Errorf("ed25519 signature verification failed")
	}

	return &sub, nil
}
