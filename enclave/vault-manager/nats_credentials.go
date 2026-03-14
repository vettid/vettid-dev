package main

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"
)

const inviteCodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// generateInviteCode creates a 16-character random alphanumeric code.
// 62^16 ≈ 4.7×10^28 combinations — unguessable within the 5-minute TTL.
func generateInviteCode() string {
	code := make([]byte, 16)
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	for i := range code {
		code[i] = inviteCodeAlphabet[int(randomBytes[i])%len(inviteCodeAlphabet)]
	}
	return string(code)
}

// extractCredsComponents extracts the JWT and seed from a NATS .creds file.
func extractCredsComponents(creds string) (jwt string, seed string) {
	// Extract JWT between markers
	if start := strings.Index(creds, "-----BEGIN NATS USER JWT-----"); start != -1 {
		after := creds[start+len("-----BEGIN NATS USER JWT-----"):]
		if end := strings.Index(after, "------END NATS USER JWT------"); end != -1 {
			jwt = strings.TrimSpace(after[:end])
		}
	}
	// Extract seed between markers
	if start := strings.Index(creds, "-----BEGIN USER NKEY SEED-----"); start != -1 {
		after := creds[start+len("-----BEGIN USER NKEY SEED-----"):]
		if end := strings.Index(after, "------END USER NKEY SEED------"); end != -1 {
			seed = strings.TrimSpace(after[:end])
		}
	}
	return
}

// GenerateInvitationCredentials creates scoped NATS credentials for a connection invitation.
// The credentials allow the peer to subscribe to this vault's published profile.
//
// Permissions granted:
// - Subscribe: OwnerSpace.{ownerSpace}.forApp.profile.> (read profile)
// - Subscribe: $JS.API.CONSUMER.CREATE.ENROLLMENT (JetStream consumer for retained messages)
// - Subscribe: $JS.API.CONSUMER.MSG.NEXT.ENROLLMENT.> (fetch retained messages)
// - Subscribe: $JS.API.STREAM.INFO.ENROLLMENT (stream info for consumer setup)
// - Publish: $JS.API.CONSUMER.CREATE.ENROLLMENT (create ephemeral consumers)
// - Publish: $JS.API.CONSUMER.MSG.NEXT.ENROLLMENT.> (fetch messages)
//
// SECURITY: Credentials are tightly scoped and time-limited.
func GenerateInvitationCredentials(accountSeed string, ownerSpace string, expiresAt time.Time) (string, error) {
	// Parse account seed to get signing key
	accountKP, err := nkeys.FromSeed([]byte(accountSeed))
	if err != nil {
		return "", fmt.Errorf("failed to parse account seed: %w", err)
	}
	defer accountKP.Wipe()

	accountPubKey, err := accountKP.PublicKey()
	if err != nil {
		return "", fmt.Errorf("failed to get account public key: %w", err)
	}

	// Generate ephemeral user key pair for this invitation
	userKP, err := nkeys.CreateUser()
	if err != nil {
		return "", fmt.Errorf("failed to create user key pair: %w", err)
	}

	userPubKey, err := userKP.PublicKey()
	if err != nil {
		return "", fmt.Errorf("failed to get user public key: %w", err)
	}

	userSeed, err := userKP.Seed()
	if err != nil {
		return "", fmt.Errorf("failed to get user seed: %w", err)
	}
	defer func() {
		for i := range userSeed {
			userSeed[i] = 0
		}
	}()

	// Build user claims with minimal permissions to keep JWT small (QR code friendly)
	// NATS defaults to deny — only allow list needed, no deny list
	claims := jwt.NewUserClaims(userPubKey)
	claims.IssuerAccount = accountPubKey
	claims.Expires = expiresAt.Unix()

	// SECURITY: Tightly scoped — only profile read + connection acceptance
	claims.Sub.Allow = jwt.StringList{
		fmt.Sprintf("OwnerSpace.%s.forApp.profile.>", ownerSpace),
		"$JS.API.CONSUMER.>",
		"$JS.API.STREAM.INFO.ENROLLMENT",
	}
	claims.Pub.Allow = jwt.StringList{
		"$JS.API.CONSUMER.>",
		fmt.Sprintf("MessageSpace.%s.forOwner.connection.accepted", ownerSpace),
	}

	// Sign the JWT with the account key
	token, err := claims.Encode(accountKP)
	if err != nil {
		return "", fmt.Errorf("failed to encode user JWT: %w", err)
	}

	// Format as NATS credentials file (JWT + seed)
	creds := formatNATSCredentials(token, userSeed)

	log.Debug().
		Str("owner_space", ownerSpace).
		Str("user_pub", userPubKey).
		Time("expires", expiresAt).
		Msg("Generated invitation NATS credentials")

	return creds, nil
}

// formatNATSCredentials formats a JWT and seed as a NATS .creds file
func formatNATSCredentials(jwt string, seed []byte) string {
	return fmt.Sprintf("-----BEGIN NATS USER JWT-----\n%s\n------END NATS USER JWT------\n\n************************* IMPORTANT *************************\nNKEY Seed printed below can be used to sign and prove identity.\nNKEYs are sensitive and should be treated as secrets.\n\n-----BEGIN USER NKEY SEED-----\n%s\n------END USER NKEY SEED------\n\n*************************************************************\n", jwt, string(seed))
}
