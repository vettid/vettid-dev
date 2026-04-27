package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// makeSignedVote builds a well-formed signed vote for testing. Returns the
// payload bytes plus the keypair so callers can re-sign tampered variants.
func makeSignedVote(t *testing.T, proposalID, vote string, votedAt time.Time) ([]byte, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	votedAtStr := votedAt.UTC().Format(time.RFC3339)
	payload := fmt.Sprintf("%s|%s|%s", proposalID, vote, votedAtStr)
	sig := ed25519.Sign(priv, []byte(payload))

	sub := SignedVoteSubmission{
		ProposalID:      proposalID,
		Vote:            vote,
		VotedAt:         votedAtStr,
		VotingPublicKey: base64.StdEncoding.EncodeToString(pub),
		VoteSignature:   base64.StdEncoding.EncodeToString(sig),
		SignedPayload:   payload,
	}
	data, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data, pub, priv
}

func TestValidateSignedVote_HappyPath(t *testing.T) {
	data, _, _ := makeSignedVote(t, "prop-1", "yes", time.Now())
	sub, err := ValidateSignedVote(data, 5*time.Minute)
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if sub.ProposalID != "prop-1" || sub.Vote != "yes" {
		t.Fatalf("submission fields wrong: %+v", sub)
	}
}

func TestValidateSignedVote_TamperedSignature(t *testing.T) {
	data, _, _ := makeSignedVote(t, "prop-1", "yes", time.Now())
	var sub SignedVoteSubmission
	_ = json.Unmarshal(data, &sub)
	// Flip a bit in the signature
	rawSig, _ := base64.StdEncoding.DecodeString(sub.VoteSignature)
	rawSig[0] ^= 0x01
	sub.VoteSignature = base64.StdEncoding.EncodeToString(rawSig)
	tampered, _ := json.Marshal(sub)

	if _, err := ValidateSignedVote(tampered, 5*time.Minute); err == nil {
		t.Fatalf("expected signature failure")
	}
}

func TestValidateSignedVote_MismatchedPayload(t *testing.T) {
	data, _, _ := makeSignedVote(t, "prop-1", "yes", time.Now())
	var sub SignedVoteSubmission
	_ = json.Unmarshal(data, &sub)
	sub.Vote = "no" // mismatch with signed_payload
	tampered, _ := json.Marshal(sub)

	if _, err := ValidateSignedVote(tampered, 5*time.Minute); err == nil {
		t.Fatalf("expected vote-mismatch failure")
	} else if !strings.Contains(err.Error(), "vote mismatch") {
		t.Fatalf("expected vote-mismatch error, got %v", err)
	}
}

func TestValidateSignedVote_OldTimestamp(t *testing.T) {
	old := time.Now().Add(-1 * time.Hour)
	data, _, _ := makeSignedVote(t, "prop-1", "yes", old)
	if _, err := ValidateSignedVote(data, 5*time.Minute); err == nil {
		t.Fatalf("expected old-timestamp failure")
	}
}

func TestValidateSignedVote_MaxAgeZeroAcceptsOld(t *testing.T) {
	old := time.Now().Add(-1 * time.Hour)
	data, _, _ := makeSignedVote(t, "prop-1", "yes", old)
	if _, err := ValidateSignedVote(data, 0); err != nil {
		t.Fatalf("expected ok with maxAge=0 (resubmit path), got %v", err)
	}
}

func TestValidateSignedVote_BadPayloadFormat(t *testing.T) {
	data, _, _ := makeSignedVote(t, "prop-1", "yes", time.Now())
	var sub SignedVoteSubmission
	_ = json.Unmarshal(data, &sub)
	sub.SignedPayload = "missing-pipes"
	tampered, _ := json.Marshal(sub)

	if _, err := ValidateSignedVote(tampered, 5*time.Minute); err == nil {
		t.Fatalf("expected payload-format failure")
	}
}

func TestValidateSignedVote_WrongKeyLength(t *testing.T) {
	data, _, _ := makeSignedVote(t, "prop-1", "yes", time.Now())
	var sub SignedVoteSubmission
	_ = json.Unmarshal(data, &sub)
	// Truncate the key to invalid length
	sub.VotingPublicKey = base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	tampered, _ := json.Marshal(sub)

	if _, err := ValidateSignedVote(tampered, 5*time.Minute); err == nil {
		t.Fatalf("expected key-length failure")
	}
}
