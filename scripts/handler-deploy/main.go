// Package main implements the handler deployment tool for VettID.
// This tool signs WASM handlers with Ed25519, uploads to S3, and updates the DynamoDB manifest.
//
// Usage:
//
//	handler-deploy -handler-id <id> -version <version> -wasm <path> [-rollout <percent>]
//
// Environment variables:
//   - AWS_REGION: AWS region (default: us-east-1)
//   - HANDLER_BUCKET: S3 bucket for handlers
//   - MANIFEST_TABLE: DynamoDB table for handler manifest
//   - SIGNING_KEY_SECRET: Secrets Manager secret ID for signing key
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func main() {
	// Parse flags
	handlerID := flag.String("handler-id", "", "Handler ID (required)")
	version := flag.String("version", "", "Version string (required)")
	wasmPath := flag.String("wasm", "", "Path to WASM file (required)")
	rolloutPercent := flag.Int("rollout", 100, "Rollout percentage (0-100)")
	dryRun := flag.Bool("dry-run", false, "Print what would be done without executing")
	flag.Parse()

	if *handlerID == "" || *version == "" || *wasmPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: handler-deploy -handler-id <id> -version <version> -wasm <path>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *rolloutPercent < 0 || *rolloutPercent > 100 {
		fmt.Fprintln(os.Stderr, "Error: rollout must be between 0 and 100")
		os.Exit(1)
	}

	// Read environment variables
	region := envOrDefault("AWS_REGION", "us-east-1")
	bucket := envOrDefault("HANDLER_BUCKET", "vettid-infrastructure-handlerpackagesbucket")
	manifestTable := envOrDefault("MANIFEST_TABLE", "VettID-Infrastructure-HandlerManifest")
	signingKeySecret := envOrDefault("SIGNING_KEY_SECRET", "vettid/handler-signing-key")

	// Read WASM file
	wasmBytes, err := os.ReadFile(*wasmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading WASM file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Handler: %s\n", *handlerID)
	fmt.Printf("Version: %s\n", *version)
	fmt.Printf("WASM Size: %d bytes\n", len(wasmBytes))

	// Calculate SHA256
	hash := sha256.Sum256(wasmBytes)
	hashHex := hex.EncodeToString(hash[:])
	fmt.Printf("SHA256: %s\n", hashHex)

	// S3 key
	s3Key := fmt.Sprintf("handlers/%s/%s.wasm", *handlerID, *version)
	fmt.Printf("S3 Key: s3://%s/%s\n", bucket, s3Key)

	if *dryRun {
		fmt.Println("\n[DRY RUN] Would perform the following actions:")
		fmt.Printf("  1. Load signing key from Secrets Manager: %s\n", signingKeySecret)
		fmt.Printf("  2. Sign WASM with Ed25519\n")
		fmt.Printf("  3. Upload to S3: %s/%s\n", bucket, s3Key)
		fmt.Printf("  4. Update DynamoDB manifest: %s\n", manifestTable)
		fmt.Printf("  5. Set rollout to %d%%\n", *rolloutPercent)
		return
	}

	// Load AWS config
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading AWS config: %v\n", err)
		os.Exit(1)
	}

	// Load signing key
	fmt.Println("\nLoading signing key...")
	secretsClient := secretsmanager.NewFromConfig(cfg)
	privateKey, err := loadSigningKey(ctx, secretsClient, signingKeySecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading signing key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Signing key loaded")

	// Sign the WASM
	signature := ed25519.Sign(privateKey, wasmBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	fmt.Printf("Signature: %s...\n", signatureB64[:40])

	// Upload to S3
	fmt.Println("\nUploading to S3...")
	s3Client := s3.NewFromConfig(cfg)
	if err := uploadToS3(ctx, s3Client, bucket, s3Key, wasmBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Error uploading to S3: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Upload complete")

	// Get current version for fallback
	fmt.Println("\nUpdating manifest...")
	ddbClient := dynamodb.NewFromConfig(cfg)
	fallbackVersion, err := getCurrentVersion(ctx, ddbClient, manifestTable, *handlerID)
	if err != nil {
		fmt.Printf("Warning: Could not get current version for fallback: %v\n", err)
		fallbackVersion = ""
	} else if fallbackVersion != "" {
		fmt.Printf("Fallback version: %s\n", fallbackVersion)
	}

	// Update manifest
	if err := updateManifest(ctx, ddbClient, manifestTable, *handlerID, *version, s3Key, hashHex, signatureB64, *rolloutPercent, fallbackVersion); err != nil {
		fmt.Fprintf(os.Stderr, "Error updating manifest: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nDeployment complete!")
	fmt.Printf("  Handler: %s\n", *handlerID)
	fmt.Printf("  Version: %s\n", *version)
	fmt.Printf("  Rollout: %d%%\n", *rolloutPercent)
}

func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func loadSigningKey(ctx context.Context, client *secretsmanager.Client, secretID string) (ed25519.PrivateKey, error) {
	result, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	var secret struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
	}
	if err := json.Unmarshal([]byte(*result.SecretString), &secret); err != nil {
		return nil, fmt.Errorf("failed to parse secret: %w", err)
	}

	// Parse PEM-encoded private key
	privateKey, err := parseEd25519PrivateKey(secret.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

func parseEd25519PrivateKey(pem string) (ed25519.PrivateKey, error) {
	// Ed25519 private keys in PKCS#8 PEM format
	const prefix = "-----BEGIN PRIVATE KEY-----"
	const suffix = "-----END PRIVATE KEY-----"

	start := len(prefix)
	end := len(pem) - len(suffix)
	if start >= end {
		return nil, fmt.Errorf("invalid PEM format")
	}

	// Extract base64 content
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

	// PKCS#8 Ed25519 private key DER format:
	// 48 bytes total: 16 bytes header + 32 bytes raw key
	if len(der) != 48 {
		return nil, fmt.Errorf("unexpected DER length: %d (expected 48)", len(der))
	}

	// Extract the raw 32-byte seed
	seed := der[16:]
	return ed25519.NewKeyFromSeed(seed), nil
}

func uploadToS3(ctx context.Context, client *s3.Client, bucket, key string, data []byte) error {
	contentType := "application/wasm"
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &bucket,
		Key:         &key,
		Body:        bytesReader(data),
		ContentType: &contentType,
	})
	return err
}

func bytesReader(data []byte) *bytesReaderImpl {
	return &bytesReaderImpl{data: data, pos: 0}
}

type bytesReaderImpl struct {
	data []byte
	pos  int
}

func (r *bytesReaderImpl) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func getCurrentVersion(ctx context.Context, client *dynamodb.Client, table, handlerID string) (string, error) {
	result, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &table,
		Key: map[string]types.AttributeValue{
			"handler_id": &types.AttributeValueMemberS{Value: handlerID},
		},
	})
	if err != nil {
		return "", err
	}

	if result.Item == nil {
		return "", nil
	}

	if v, ok := result.Item["current_version"].(*types.AttributeValueMemberS); ok {
		return v.Value, nil
	}
	return "", nil
}

func updateManifest(ctx context.Context, client *dynamodb.Client, table, handlerID, version, s3Key, sha256, signature string, rollout int, fallbackVersion string) error {
	now := time.Now().UTC().Format(time.RFC3339)

	item := map[string]types.AttributeValue{
		"handler_id":       &types.AttributeValueMemberS{Value: handlerID},
		"current_version":  &types.AttributeValueMemberS{Value: version},
		"s3_key":           &types.AttributeValueMemberS{Value: s3Key},
		"sha256":           &types.AttributeValueMemberS{Value: sha256},
		"signature":        &types.AttributeValueMemberS{Value: signature},
		"rollout_percent":  &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", rollout)},
		"updated_at":       &types.AttributeValueMemberS{Value: now},
	}

	if fallbackVersion != "" {
		item["fallback_version"] = &types.AttributeValueMemberS{Value: fallbackVersion}
	}

	_, err := client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &table,
		Item:      item,
	})
	return err
}
