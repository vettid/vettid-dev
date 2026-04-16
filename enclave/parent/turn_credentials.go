package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/rs/zerolog/log"
)

const (
	// turnSecretName is the Secrets Manager id for the Cloudflare TURN
	// shared secret (matches cdk/lambda/handlers/calls/getTurnCredentials.ts).
	turnSecretName = "vettid/cloudflare-turn"
	// turnTTLSeconds matches the Lambda's 24h credential lifetime.
	turnTTLSeconds = 86400
	// turnSecretCacheTTL keeps Secrets Manager calls cheap.
	turnSecretCacheTTL = 30 * time.Minute
)

type turnSecret struct {
	TokenID     string `json:"token_id"`
	TokenSecret string `json:"token_secret"`
}

var (
	turnSecretMu     sync.Mutex
	turnSecretCache  *turnSecret
	turnSecretExpiry time.Time
	turnSMClient     *secretsmanager.Client
)

// getTurnSecret returns the Cloudflare TURN shared secret, fetching from
// Secrets Manager and caching the result.
func getTurnSecret(ctx context.Context) (*turnSecret, error) {
	turnSecretMu.Lock()
	defer turnSecretMu.Unlock()

	if turnSecretCache != nil && time.Now().Before(turnSecretExpiry) {
		return turnSecretCache, nil
	}

	if turnSMClient == nil {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("aws config: %w", err)
		}
		turnSMClient = secretsmanager.NewFromConfig(cfg)
	}

	out, err := turnSMClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: ptrString(turnSecretName),
	})
	if err != nil {
		return nil, fmt.Errorf("secretsmanager get: %w", err)
	}
	if out.SecretString == nil || *out.SecretString == "" {
		return nil, fmt.Errorf("turn secret empty")
	}
	var s turnSecret
	if err := json.Unmarshal([]byte(*out.SecretString), &s); err != nil {
		return nil, fmt.Errorf("turn secret malformed: %w", err)
	}
	if s.TokenSecret == "" {
		return nil, fmt.Errorf("turn secret missing token_secret")
	}
	turnSecretCache = &s
	turnSecretExpiry = time.Now().Add(turnSecretCacheTTL)
	return turnSecretCache, nil
}

// turnCredentialsResponseJSON is the wire format returned to the vault, which
// in turn relays it to the app. Field shape mirrors what the prior HTTP API
// returned so the Android client doesn't have to re-shape it.
type turnCredentialsResponseJSON struct {
	IceServers []turnIceServerJSON `json:"ice_servers"`
	ExpiresAt  string              `json:"expires_at"`
}

type turnIceServerJSON struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// generateTurnCredentials builds a time-limited Cloudflare TURN credential
// for the given user_guid using the standard "expiry:user_guid" + HMAC-SHA1
// REST API format.
func generateTurnCredentials(ctx context.Context, userGUID string) ([]byte, error) {
	if userGUID == "" {
		return nil, fmt.Errorf("user_guid required")
	}
	secret, err := getTurnSecret(ctx)
	if err != nil {
		return nil, err
	}
	expiry := time.Now().Add(time.Duration(turnTTLSeconds) * time.Second).Unix()
	username := fmt.Sprintf("%d:%s", expiry, userGUID)
	mac := hmac.New(sha1.New, []byte(secret.TokenSecret))
	mac.Write([]byte(username))
	credential := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	resp := turnCredentialsResponseJSON{
		IceServers: []turnIceServerJSON{
			{URLs: []string{"stun:stun.cloudflare.com:3478"}},
			{
				URLs: []string{
					"turn:turn.cloudflare.com:3478?transport=udp",
					"turn:turn.cloudflare.com:3478?transport=tcp",
					"turns:turn.cloudflare.com:5349?transport=tcp",
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
