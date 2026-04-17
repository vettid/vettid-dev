package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/rs/zerolog/log"
)

const (
	// turnSecretName is the Secrets Manager id for the HMAC shared secret
	// that our coturn relay trusts. Defined in cdk/lib/turn-stack.ts.
	turnSecretName = "vettid/turn-shared-secret"
	// turnTTLSeconds: short-lived creds, re-minted per call. 1 hour is
	// enough to cover ICE restarts and longish conversations without
	// keeping long-lived tokens floating around.
	turnTTLSeconds = 3600
	// turnSecretCacheTTL keeps Secrets Manager calls cheap.
	turnSecretCacheTTL = 30 * time.Minute
	// turnHostname and turnRealm are fixed by the TurnStack deployment.
	turnHostname = "turn.vettid.dev"
)

var (
	turnSecretMu     sync.Mutex
	turnSecretCache  string
	turnSecretExpiry time.Time
	turnSMClient     *secretsmanager.Client
)

// getTurnSecret returns the HMAC secret used to sign coturn credentials.
// Fetched from Secrets Manager on first use and cached for 30 min.
func getTurnSecret(ctx context.Context) (string, error) {
	turnSecretMu.Lock()
	defer turnSecretMu.Unlock()

	if turnSecretCache != "" && time.Now().Before(turnSecretExpiry) {
		return turnSecretCache, nil
	}

	if turnSMClient == nil {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return "", fmt.Errorf("aws config: %w", err)
		}
		turnSMClient = secretsmanager.NewFromConfig(cfg)
	}

	out, err := turnSMClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: ptrString(turnSecretName),
	})
	if err != nil {
		return "", fmt.Errorf("secretsmanager get: %w", err)
	}
	if out.SecretString == nil || *out.SecretString == "" {
		return "", fmt.Errorf("turn secret empty")
	}
	turnSecretCache = *out.SecretString
	turnSecretExpiry = time.Now().Add(turnSecretCacheTTL)
	return turnSecretCache, nil
}

// turnCredentialsResponseJSON is the wire format returned to the vault, which
// in turn relays it to the app. Shape matches what the Android client parses.
type turnCredentialsResponseJSON struct {
	IceServers []turnIceServerJSON `json:"ice_servers"`
	ExpiresAt  string              `json:"expires_at"`
}

type turnIceServerJSON struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// generateTurnCredentials builds coturn long-term credentials.
//
// Format (matches coturn `use-auth-secret` mode):
//   username   = "<unix-expiry>:<per-call-nonce>"
//   credential = base64(HMAC-SHA1(shared_secret, username))
//
// PRIVACY: we use a random per-call nonce rather than user_guid so that a
// passive observer of TURN traffic can't correlate allocations to users.
func generateTurnCredentials(ctx context.Context, _userGUID string) ([]byte, error) {
	secret, err := getTurnSecret(ctx)
	if err != nil {
		return nil, err
	}

	// Per-call opaque nonce — 96 bits of randomness is plenty for uniqueness
	// within the TTL.
	var nonceBytes [12]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes[:])

	expiry := time.Now().Add(time.Duration(turnTTLSeconds) * time.Second).Unix()
	username := fmt.Sprintf("%d:%s", expiry, nonce)
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(username))
	credential := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	resp := turnCredentialsResponseJSON{
		IceServers: []turnIceServerJSON{
			// TURNS (TLS) preferred — keeps allocation creds off the wire.
			// 443 fallback is for networks that only allow HTTPS egress.
			{
				URLs: []string{
					fmt.Sprintf("turns:%s:5349?transport=tcp", turnHostname),
					fmt.Sprintf("turns:%s:443?transport=tcp", turnHostname),
					// Plain TURN is kept as a fallback only. Clients are
					// configured to force relay-only over TURNS where
					// possible; if the TLS ports are blocked we degrade
					// rather than fail.
					fmt.Sprintf("turn:%s:3478?transport=udp", turnHostname),
					fmt.Sprintf("turn:%s:3478?transport=tcp", turnHostname),
				},
				Username:   username,
				Credential: credential,
			},
		},
		ExpiresAt: time.Unix(expiry, 0).UTC().Format(time.RFC3339),
	}
	return json.Marshal(resp)
}

// handleTurnCredentialsGet handles a TURN-credential request from the enclave.
func (p *ParentProcess) handleTurnCredentialsGet(ctx context.Context, msg *EnclaveMessage) *EnclaveMessage {
	body, err := generateTurnCredentials(ctx, msg.OwnerSpace)
	if err != nil {
		log.Error().Err(err).Str("owner_space", msg.OwnerSpace).Msg("Failed to generate TURN credentials")
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return &EnclaveMessage{
			Type:    EnclaveMessageTypeTurnCredentialsResponse,
			Payload: errResp,
		}
	}
	return &EnclaveMessage{
		Type:    EnclaveMessageTypeTurnCredentialsResponse,
		Payload: body,
	}
}

func ptrString(s string) *string { return &s }
