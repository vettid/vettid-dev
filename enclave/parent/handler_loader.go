package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/rs/zerolog/log"
)

// ManifestEntry represents a handler version in the manifest
type ManifestEntry struct {
	HandlerID       string `json:"handler_id"`
	CurrentVersion  string `json:"current_version"`
	S3Key           string `json:"s3_key"`
	SHA256          string `json:"sha256"`
	Signature       string `json:"signature"`
	RolloutPercent  int    `json:"rollout_percent"`
	FallbackVersion string `json:"fallback_version"`
	UpdatedAt       string `json:"updated_at"`
}

// HandlerLoader manages dynamic loading of WASM handlers
type HandlerLoader struct {
	cfg           HandlerConfig
	ddb           *dynamodb.Client
	s3Client      *s3.Client
	secrets       *secretsmanager.Client
	publicKey     ed25519.PublicKey
	manifestCache map[string]*cachedManifestEntry
	handlerCache  map[string][]byte // keyed by handler_id:version
	mu            sync.RWMutex
}

// cachedManifestEntry wraps ManifestEntry with cache metadata
type cachedManifestEntry struct {
	entry     *ManifestEntry
	fetchedAt time.Time
}

// NewHandlerLoader creates a new handler loader
func NewHandlerLoader(cfg HandlerConfig) (*HandlerLoader, error) {
	// Load AWS configuration
	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	loader := &HandlerLoader{
		cfg:           cfg,
		ddb:           dynamodb.NewFromConfig(awsCfg),
		s3Client:      s3.NewFromConfig(awsCfg),
		secrets:       secretsmanager.NewFromConfig(awsCfg),
		manifestCache: make(map[string]*cachedManifestEntry),
		handlerCache:  make(map[string][]byte),
	}

	// Load the signing public key
	if err := loader.loadPublicKey(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to load signing public key: %w", err)
	}

	log.Info().
		Str("bucket", cfg.Bucket).
		Str("manifest_table", cfg.ManifestTable).
		Int("cache_ttl", cfg.ManifestCacheTTL).
		Msg("Handler loader initialized")

	return loader, nil
}

// loadPublicKey loads the Ed25519 public key from Secrets Manager
func (l *HandlerLoader) loadPublicKey(ctx context.Context) error {
	result, err := l.secrets.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &l.cfg.SigningKeySecretID,
	})
	if err != nil {
		return fmt.Errorf("failed to get signing key secret: %w", err)
	}

	// Parse the secret JSON
	var secret struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
	}
	if err := json.Unmarshal([]byte(*result.SecretString), &secret); err != nil {
		return fmt.Errorf("failed to parse signing key secret: %w", err)
	}

	// Parse the PEM-encoded public key
	pubKey, err := parseEd25519PublicKey(secret.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	l.publicKey = pubKey
	log.Info().Msg("Loaded handler signing public key")
	return nil
}

// parseEd25519PublicKey parses a PEM-encoded Ed25519 public key
func parseEd25519PublicKey(pem string) (ed25519.PublicKey, error) {
	// Ed25519 public keys in PEM format have a fixed structure:
	// -----BEGIN PUBLIC KEY-----
	// MCowBQYDK2VwAyEA<32 bytes base64>
	// -----END PUBLIC KEY-----
	// The last 32 bytes of the decoded base64 are the raw public key

	// Extract the base64 portion
	const prefix = "-----BEGIN PUBLIC KEY-----"
	const suffix = "-----END PUBLIC KEY-----"

	start := len(prefix)
	end := len(pem) - len(suffix)
	if start >= end {
		return nil, fmt.Errorf("invalid PEM format")
	}

	// Find the actual base64 content (skip whitespace)
	b64 := ""
	for i := start; i < end; i++ {
		c := pem[i]
		if c != '\n' && c != '\r' && c != ' ' {
			b64 += string(c)
		}
	}

	// Decode base64
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Ed25519 public key in DER format is 44 bytes:
	// 12 bytes header + 32 bytes raw key
	if len(der) != 44 {
		return nil, fmt.Errorf("unexpected DER length: %d", len(der))
	}

	// Extract the raw 32-byte public key
	return ed25519.PublicKey(der[12:]), nil
}

// GetHandler retrieves a handler WASM module by ID
// Returns the WASM bytes and the version string
func (l *HandlerLoader) GetHandler(ctx context.Context, handlerID string) ([]byte, string, error) {
	// Get the current version from manifest (with caching)
	manifest, err := l.getManifestEntry(ctx, handlerID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get manifest: %w", err)
	}

	if manifest == nil {
		return nil, "", fmt.Errorf("handler not found: %s", handlerID)
	}

	// Check handler cache
	cacheKey := fmt.Sprintf("%s:%s", handlerID, manifest.CurrentVersion)
	l.mu.RLock()
	cached, ok := l.handlerCache[cacheKey]
	l.mu.RUnlock()

	if ok {
		log.Debug().
			Str("handler_id", handlerID).
			Str("version", manifest.CurrentVersion).
			Msg("Handler cache hit")
		return cached, manifest.CurrentVersion, nil
	}

	// Fetch from S3
	log.Debug().
		Str("handler_id", handlerID).
		Str("version", manifest.CurrentVersion).
		Str("s3_key", manifest.S3Key).
		Msg("Fetching handler from S3")

	wasmBytes, err := l.fetchFromS3(ctx, manifest.S3Key)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch handler from S3: %w", err)
	}

	// Verify SHA256 hash
	hash := sha256.Sum256(wasmBytes)
	hashHex := hex.EncodeToString(hash[:])
	if hashHex != manifest.SHA256 {
		return nil, "", fmt.Errorf("handler hash mismatch: expected %s, got %s", manifest.SHA256, hashHex)
	}

	// Verify Ed25519 signature
	signature, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode signature: %w", err)
	}

	if !ed25519.Verify(l.publicKey, wasmBytes, signature) {
		return nil, "", fmt.Errorf("handler signature verification failed")
	}

	log.Info().
		Str("handler_id", handlerID).
		Str("version", manifest.CurrentVersion).
		Int("size", len(wasmBytes)).
		Msg("Handler loaded and verified")

	// Cache the handler
	l.mu.Lock()
	l.handlerCache[cacheKey] = wasmBytes
	l.mu.Unlock()

	return wasmBytes, manifest.CurrentVersion, nil
}

// getManifestEntry retrieves a manifest entry with caching
func (l *HandlerLoader) getManifestEntry(ctx context.Context, handlerID string) (*ManifestEntry, error) {
	ttl := time.Duration(l.cfg.ManifestCacheTTL) * time.Second

	// Check cache
	l.mu.RLock()
	cached, ok := l.manifestCache[handlerID]
	l.mu.RUnlock()

	if ok && time.Since(cached.fetchedAt) < ttl {
		log.Debug().
			Str("handler_id", handlerID).
			Dur("age", time.Since(cached.fetchedAt)).
			Msg("Manifest cache hit")
		return cached.entry, nil
	}

	// Fetch from DynamoDB
	log.Debug().
		Str("handler_id", handlerID).
		Str("table", l.cfg.ManifestTable).
		Msg("Fetching manifest from DynamoDB")

	result, err := l.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &l.cfg.ManifestTable,
		Key: map[string]types.AttributeValue{
			"handler_id": &types.AttributeValueMemberS{Value: handlerID},
		},
	})
	if err != nil {
		// If DynamoDB fails, try to use stale cache
		l.mu.RLock()
		if cached, ok := l.manifestCache[handlerID]; ok {
			l.mu.RUnlock()
			log.Warn().
				Str("handler_id", handlerID).
				Err(err).
				Msg("DynamoDB failed, using stale cache")
			return cached.entry, nil
		}
		l.mu.RUnlock()
		return nil, fmt.Errorf("failed to get manifest from DynamoDB: %w", err)
	}

	if result.Item == nil {
		return nil, nil // Not found
	}

	// Parse the item
	entry := &ManifestEntry{
		HandlerID: handlerID,
	}

	if v, ok := result.Item["current_version"].(*types.AttributeValueMemberS); ok {
		entry.CurrentVersion = v.Value
	}
	if v, ok := result.Item["s3_key"].(*types.AttributeValueMemberS); ok {
		entry.S3Key = v.Value
	}
	if v, ok := result.Item["sha256"].(*types.AttributeValueMemberS); ok {
		entry.SHA256 = v.Value
	}
	if v, ok := result.Item["signature"].(*types.AttributeValueMemberS); ok {
		entry.Signature = v.Value
	}
	if v, ok := result.Item["rollout_percent"].(*types.AttributeValueMemberN); ok {
		fmt.Sscanf(v.Value, "%d", &entry.RolloutPercent)
	}
	if v, ok := result.Item["fallback_version"].(*types.AttributeValueMemberS); ok {
		entry.FallbackVersion = v.Value
	}
	if v, ok := result.Item["updated_at"].(*types.AttributeValueMemberS); ok {
		entry.UpdatedAt = v.Value
	}

	// Update cache
	l.mu.Lock()
	l.manifestCache[handlerID] = &cachedManifestEntry{
		entry:     entry,
		fetchedAt: time.Now(),
	}
	l.mu.Unlock()

	return entry, nil
}

// fetchFromS3 retrieves a handler from S3
func (l *HandlerLoader) fetchFromS3(ctx context.Context, key string) ([]byte, error) {
	result, err := l.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &l.cfg.Bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, err
	}
	defer result.Body.Close()

	// Read the entire body
	var buf []byte
	buf = make([]byte, 0, 1024*1024) // Pre-allocate 1MB
	tmp := make([]byte, 32*1024)     // 32KB read buffer
	for {
		n, err := result.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}

	return buf, nil
}

// InvalidateCache clears the manifest cache for a specific handler
func (l *HandlerLoader) InvalidateCache(handlerID string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.manifestCache, handlerID)
	// Also clear handler cache entries for this handler
	for key := range l.handlerCache {
		if len(key) >= len(handlerID) && key[:len(handlerID)] == handlerID {
			delete(l.handlerCache, key)
		}
	}

	log.Debug().Str("handler_id", handlerID).Msg("Cache invalidated")
}

// InvalidateAllCache clears all caches
func (l *HandlerLoader) InvalidateAllCache() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.manifestCache = make(map[string]*cachedManifestEntry)
	l.handlerCache = make(map[string][]byte)

	log.Debug().Msg("All caches invalidated")
}

// GetCacheStats returns cache statistics
func (l *HandlerLoader) GetCacheStats() (manifestEntries, handlerEntries int) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.manifestCache), len(l.handlerCache)
}
