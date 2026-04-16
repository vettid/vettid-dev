package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// cfTurnAPIResponse mirrors Cloudflare's
// POST /v1/turn/keys/{KEY_ID}/credentials/generate-ice-servers response.
// `iceServers` is an array — typically one stun-only entry plus one turn entry.
type cfTurnAPIResponse struct {
	IceServers []struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username,omitempty"`
		Credential string   `json:"credential,omitempty"`
	} `json:"iceServers"`
}

// generateTurnCredentials calls Cloudflare's Calls TURN API to mint
// short-lived credentials. Cloudflare's TURN Token Key requires a server-side
// API call (not local HMAC); the previous implementation produced creds the
// TURN server would reject silently, leaving callers with srflx-only ICE.
func generateTurnCredentials(ctx context.Context, userGUID string) ([]byte, error) {
	if userGUID == "" {
		return nil, fmt.Errorf("user_guid required")
	}
	secret, err := getTurnSecret(ctx)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://rtc.live.cloudflare.com/v1/turn/keys/%s/credentials/generate-ice-servers", secret.TokenID)
	body := bytes.NewBufferString(fmt.Sprintf(`{"ttl": %d}`, turnTTLSeconds))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("build cf request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+secret.TokenSecret)
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cf turn api: %w", err)
	}
	defer res.Body.Close()

	respBody, _ := io.ReadAll(res.Body)
	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("cf turn api status %d: %s", res.StatusCode, string(respBody))
	}

	var cfResp cfTurnAPIResponse
	if err := json.Unmarshal(respBody, &cfResp); err != nil {
		return nil, fmt.Errorf("cf turn api parse: %w", err)
	}
	if len(cfResp.IceServers) == 0 {
		return nil, fmt.Errorf("cf turn api returned no ice servers: %s", string(respBody))
	}

	out := turnCredentialsResponseJSON{
		ExpiresAt: time.Now().Add(time.Duration(turnTTLSeconds) * time.Second).UTC().Format(time.RFC3339),
	}
	for _, srv := range cfResp.IceServers {
		out.IceServers = append(out.IceServers, turnIceServerJSON{
			URLs:       srv.URLs,
			Username:   srv.Username,
			Credential: srv.Credential,
		})
	}
	_ = userGUID // tagging by user_guid is done via Cloudflare's analytics, not in the credential
	return json.Marshal(out)
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
