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

// shortCodeAlphabet excludes ambiguous glyphs (0/O, 1/I/L, and lowercase) so
// the same code is safe to display on a QR AND hand-type. Used for every
// short-lived pairing/invitation code: peer invitations, device pairing,
// agent registration. Standardising on one alphabet means a user can't
// fail by entering the wrong shape from the wrong flow.
const shortCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// generateShortCode produces a 12-character ambiguity-safe code, displayed
// to the user as three 4-character blocks (`ABCD-EFGH-JKLM`). 32^12 ≈
// 1.15×10^18 combinations — comfortably brute-resistant within the
// minutes-scale TTLs these codes live for, especially once paired with
// broker-side rate limiting.
func generateShortCode() string {
	code := make([]byte, 12)
	randomBytes := make([]byte, 12)
	rand.Read(randomBytes)
	for i := range code {
		code[i] = shortCodeAlphabet[int(randomBytes[i])%len(shortCodeAlphabet)]
	}
	return string(code)
}

// generateInviteCode produces a peer-invitation code. Aliased to
// generateShortCode so peer + device + agent flows all share the same
// shape and validation rules.
func generateInviteCode() string { return generateShortCode() }

// generateDeviceInviteCode produces a device-pairing code. Same shape
// as peer invitations; alias kept for callsite readability.
func generateDeviceInviteCode() string { return generateShortCode() }

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

// GenerateDeviceCredentials creates scoped NATS credentials for a paired
// desktop device. Permissions are narrow enough that a compromised JWT
// cannot read any other user's data or impersonate the user's app, while
// still allowing the device to exchange pairing messages and session
// payloads within this specific connection.
//
// Permissions granted:
//   - Publish to MessageSpace.<owner>.forOwner.device.<conn-id>.> — all outbound
//     device messages for this one connection (request-session, extend, revoke, ops)
//   - Subscribe to MessageSpace.<owner>.forApp.device.<conn-id>.> — activation,
//     revocation events, operation responses for this connection
//   - JetStream consumer ops (so the device can create ephemeral consumers
//     for reading its own invite and any persistent feed deliveries)
//
// SECURITY: scoped to a single connection_id. The device cannot publish
// or subscribe on behalf of any other connection.
func GenerateDeviceCredentials(accountSeed, ownerSpace, connectionID string, expiresAt time.Time) (string, error) {
	accountKP, err := nkeys.FromSeed([]byte(accountSeed))
	if err != nil {
		return "", fmt.Errorf("failed to parse account seed: %w", err)
	}
	defer accountKP.Wipe()

	accountPubKey, err := accountKP.PublicKey()
	if err != nil {
		return "", fmt.Errorf("failed to get account public key: %w", err)
	}

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

	claims := jwt.NewUserClaims(userPubKey)
	claims.IssuerAccount = accountPubKey
	claims.Expires = expiresAt.Unix()

	// SECURITY: scoped to this connection_id only.
	claims.Pub.Allow = jwt.StringList{
		fmt.Sprintf("MessageSpace.%s.forOwner.device.%s.>", ownerSpace, connectionID),
		"$JS.API.CONSUMER.>",
	}
	claims.Sub.Allow = jwt.StringList{
		fmt.Sprintf("MessageSpace.%s.forApp.device.%s.>", ownerSpace, connectionID),
		"$JS.API.CONSUMER.>",
		"$JS.API.STREAM.INFO.>",
	}

	token, err := claims.Encode(accountKP)
	if err != nil {
		return "", fmt.Errorf("failed to encode user JWT: %w", err)
	}

	creds := formatNATSCredentials(token, userSeed)

	log.Debug().
		Str("owner_space", ownerSpace).
		Str("connection_id", connectionID).
		Str("user_pub", userPubKey).
		Time("expires", expiresAt).
		Msg("Generated device NATS credentials")

	return creds, nil
}

// GenerateFullAppCredentials creates NATS credentials with full app permissions.
// These are the "real" credentials issued by the vault after PIN verification.
// The vault is the sole authority for full OwnerSpace/MessageSpace access.
//
// Permissions match the Lambda's generateUserCredentials(clientType='app') exactly:
// - Publish to vault handlers, JetStream consumer ops
// - Subscribe to vault responses, event types, directory, JetStream
// - Deny system topics, JetStream admin ops
//
// SECURITY: Only the vault can issue these credentials. Lambda can only issue
// bootstrap credentials with narrow pin-unlock scope.
func GenerateFullAppCredentials(accountSeed, ownerSpace, messageSpace string, expiresAt time.Time) (string, error) {
	accountKP, err := nkeys.FromSeed([]byte(accountSeed))
	if err != nil {
		return "", fmt.Errorf("failed to parse account seed: %w", err)
	}
	defer accountKP.Wipe()

	accountPubKey, err := accountKP.PublicKey()
	if err != nil {
		return "", fmt.Errorf("failed to get account public key: %w", err)
	}

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

	claims := jwt.NewUserClaims(userPubKey)
	claims.IssuerAccount = accountPubKey
	claims.Expires = expiresAt.Unix()

	// Publish allow: vault handlers + JetStream consumer ops
	claims.Pub.Allow = jwt.StringList{
		fmt.Sprintf("%s.forVault.>", ownerSpace),
		"$JS.API.CONSUMER.CREATE.ENROLLMENT",
		"$JS.API.CONSUMER.MSG.NEXT.ENROLLMENT.>",
	}

	// Publish deny: system topics + JetStream admin ops
	claims.Pub.Deny = jwt.StringList{
		"$SYS.>",
		"_INBOX.>",
		"Broadcast.>",
		"$JS.API.STREAM.CREATE.>",
		"$JS.API.STREAM.DELETE.>",
		"$JS.API.STREAM.UPDATE.>",
		"$JS.API.STREAM.PURGE.>",
		"$JS.API.CONSUMER.DELETE.>",
	}

	// Subscribe allow: vault responses + event types + directory + JetStream
	claims.Sub.Allow = jwt.StringList{
		fmt.Sprintf("%s.forApp.>", ownerSpace),
		fmt.Sprintf("%s.eventTypes", ownerSpace),
		"Directory.>",
		"$JS.API.CONSUMER.CREATE.ENROLLMENT",
		"$JS.API.CONSUMER.MSG.NEXT.ENROLLMENT.>",
		"$JS.API.STREAM.INFO.ENROLLMENT",
	}

	// Subscribe deny: system topics + JetStream admin ops (no Broadcast deny for subscribe)
	claims.Sub.Deny = jwt.StringList{
		"$SYS.>",
		"_INBOX.>",
		"$JS.API.STREAM.CREATE.>",
		"$JS.API.STREAM.DELETE.>",
		"$JS.API.STREAM.UPDATE.>",
		"$JS.API.STREAM.PURGE.>",
		"$JS.API.CONSUMER.DELETE.>",
	}

	// Resource limits matching Lambda-issued credentials
	claims.Limits.Subs = 50
	claims.Limits.Payload = 1048576  // 1 MB
	claims.Limits.Data = 5000000     // 5 MB/sec

	token, err := claims.Encode(accountKP)
	if err != nil {
		return "", fmt.Errorf("failed to encode user JWT: %w", err)
	}

	creds := formatNATSCredentials(token, userSeed)

	log.Debug().
		Str("owner_space", ownerSpace).
		Str("message_space", messageSpace).
		Str("user_pub", userPubKey).
		Time("expires", expiresAt).
		Msg("Generated full app NATS credentials")

	return creds, nil
}

// formatNATSCredentials formats a JWT and seed as a NATS .creds file
func formatNATSCredentials(jwt string, seed []byte) string {
	return fmt.Sprintf("-----BEGIN NATS USER JWT-----\n%s\n------END NATS USER JWT------\n\n************************* IMPORTANT *************************\nNKEY Seed printed below can be used to sign and prove identity.\nNKEYs are sensitive and should be treated as secrets.\n\n-----BEGIN USER NKEY SEED-----\n%s\n------END USER NKEY SEED------\n\n*************************************************************\n", jwt, string(seed))
}
