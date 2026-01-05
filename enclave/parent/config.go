package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the parent process configuration
type Config struct {
	// DevMode enables development mode (TCP instead of vsock)
	DevMode bool `yaml:"dev_mode"`

	// NATS configuration
	NATS NATSConfig `yaml:"nats"`

	// S3 configuration
	S3 S3Config `yaml:"s3"`

	// Enclave configuration
	Enclave EnclaveConfig `yaml:"enclave"`

	// Health check configuration
	Health HealthConfig `yaml:"health"`

	// Handler loading configuration
	Handlers HandlerConfig `yaml:"handlers"`

	// KMS configuration for Nitro attestation-based sealing
	KMS KMSConfig `yaml:"kms"`
}

// KMSConfig holds KMS settings for Nitro sealing
type KMSConfig struct {
	// KMS key ARN for sealing (must have attestation-based policy)
	SealingKeyARN string `yaml:"sealing_key_arn"`
	// AWS region
	Region string `yaml:"region"`
}

// NATSConfig holds NATS connection settings
type NATSConfig struct {
	URL            string `yaml:"url"`
	CredentialsFile string `yaml:"credentials_file"`
	ReconnectWait  int    `yaml:"reconnect_wait_ms"`
	MaxReconnects  int    `yaml:"max_reconnects"`
}

// S3Config holds S3 storage settings
type S3Config struct {
	Bucket    string `yaml:"bucket"`
	Region    string `yaml:"region"`
	KeyPrefix string `yaml:"key_prefix"`
}

// EnclaveConfig holds enclave connection settings
type EnclaveConfig struct {
	CID  uint32 `yaml:"cid"`
	Port uint32 `yaml:"port"`
}

// HealthConfig holds health check settings
type HealthConfig struct {
	Port     int `yaml:"port"`
	Interval int `yaml:"interval_seconds"`
}

// HandlerConfig holds handler loading settings
type HandlerConfig struct {
	// S3 bucket for handler WASM files
	Bucket string `yaml:"bucket"`
	// DynamoDB table for handler manifest
	ManifestTable string `yaml:"manifest_table"`
	// AWS region
	Region string `yaml:"region"`
	// Secrets Manager secret ID for signing key
	SigningKeySecretID string `yaml:"signing_key_secret_id"`
	// Manifest cache TTL in seconds
	ManifestCacheTTL int `yaml:"manifest_cache_ttl_seconds"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	// Start with defaults
	cfg := DefaultConfig()

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Use defaults if no config file
		return cfg, nil
	}

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		DevMode: false,
		NATS: NATSConfig{
			URL:            "nats://nats.internal.vettid.dev:4222",
			CredentialsFile: "/etc/vettid/nats.creds",
			ReconnectWait:  2000,
			MaxReconnects:  -1, // Unlimited
		},
		S3: S3Config{
			Bucket:    "vettid-vault-data",
			Region:    "us-east-1",
			KeyPrefix: "vaults/",
		},
		Enclave: EnclaveConfig{
			CID:  16, // Default enclave CID
			Port: 5000,
		},
		Health: HealthConfig{
			Port:     8080,
			Interval: 30,
		},
		Handlers: HandlerConfig{
			Bucket:             "vettid-infrastructure-handlerpackagesbucket5a751b0-nsabvzt77rbc",
			ManifestTable:      "VettID-Infrastructure-HandlerManifestF07B874C-N86QCO9SZTA4",
			Region:             "us-east-1",
			SigningKeySecretID: "vettid/handler-signing-key",
			ManifestCacheTTL:   30, // 30 seconds
		},
		KMS: KMSConfig{
			SealingKeyARN: "", // Must be configured in production
			Region:        "us-east-1",
		},
	}
}
