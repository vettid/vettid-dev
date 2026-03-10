package main

import (
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"
)

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

	// Build user claims with scoped permissions
	claims := jwt.NewUserClaims(userPubKey)
	claims.IssuerAccount = accountPubKey
	claims.Name = fmt.Sprintf("invite-%s", ownerSpace[:min(8, len(ownerSpace))])
	claims.Expires = expiresAt.Unix()

	// SECURITY: Tightly scoped subscription permissions
	// Only allow reading this vault's profile from JetStream
	claims.Sub.Allow = jwt.StringList{
		fmt.Sprintf("OwnerSpace.%s.forApp.profile.>", ownerSpace),
		"$JS.API.CONSUMER.CREATE.ENROLLMENT",
		"$JS.API.CONSUMER.MSG.NEXT.ENROLLMENT.>",
		"$JS.API.STREAM.INFO.ENROLLMENT",
	}

	// SECURITY: Minimal publish permissions (JetStream consumer ops + connection acceptance)
	claims.Pub.Allow = jwt.StringList{
		"$JS.API.CONSUMER.CREATE.ENROLLMENT",
		"$JS.API.CONSUMER.MSG.NEXT.ENROLLMENT.>",
		// Allow accepter to notify this vault when they accept the connection
		fmt.Sprintf("MessageSpace.%s.forOwner.connection.accepted", ownerSpace),
	}

	// SECURITY: Explicit denies to prevent abuse
	claims.Sub.Deny = jwt.StringList{
		"$SYS.>",
		"_INBOX.>",
	}
	claims.Pub.Deny = jwt.StringList{
		"$SYS.>",
		"_INBOX.>",
		"$JS.API.STREAM.CREATE.>",
		"$JS.API.STREAM.DELETE.>",
		"$JS.API.STREAM.UPDATE.>",
		"$JS.API.STREAM.PURGE.>",
		"$JS.API.CONSUMER.DELETE.>",
	}

	// SECURITY: Rate limits
	claims.Limits.Subs = 10        // Max 10 subscriptions
	claims.Limits.Data = 1_000_000 // 1 MB/sec
	claims.Limits.Payload = 65536  // 64 KB max payload

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
