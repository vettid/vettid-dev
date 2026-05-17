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

	// EnclaveID is a unique identifier for this enclave instance
	// Format: "{region}-{instance_id}-{timestamp}" or custom value
	// Used for Control.enclave.{id}.* topic subscriptions
	EnclaveID string `yaml:"enclave_id"`

	// NATS configuration
	NATS NATSConfig `yaml:"nats"`

	// S3 configuration
	S3 S3Config `yaml:"s3"`

	// Enclave configuration
	Enclave EnclaveConfig `yaml:"enclave"`

	// Health check configuration
	Health HealthConfig `yaml:"health"`

	// KMS configuration for Nitro attestation-based sealing
	KMS KMSConfig `yaml:"kms"`

	// DynamoDB configuration for NATS account seed access
	DynamoDB DynamoDBConfig `yaml:"dynamodb"`
}

// KMSConfig holds KMS settings for Nitro sealing
type KMSConfig struct {
	// KMS key ARN for sealing (must have attestation-based policy)
	SealingKeyARN string `yaml:"sealing_key_arn"`
	// KMS key ARN for NATS seed encryption/decryption
	NatsSeedKeyARN string `yaml:"nats_seed_key_arn"`
	// KMS key ARN for the PCR-manifest / migration-config signing key
	// (ECDSA P-256, alias `vettid-pcr-signing`). Parent calls
	// kms:GetPublicKey on this key at startup and ships the DER bytes
	// to the vault-manager so the migration handler can verify the
	// signature on every fetched migration config. SSM fallback:
	// /vettid/attestation/pcr-signing-key-id.
	PCRSigningKeyARN string `yaml:"pcr_signing_key_arn"`
	// AWS region
	Region string `yaml:"region"`
}

// DynamoDBConfig holds DynamoDB settings
type DynamoDBConfig struct {
	// Table name for NATS accounts
	NatsAccountsTable string `yaml:"nats_accounts_table"`
	// Table name for governance proposals
	ProposalsTable string `yaml:"proposals_table"`
	// Table name for governance votes (vault-mediated submission target)
	VotesTable string `yaml:"votes_table"`
	// Table name for org vault audit events
	OrgAuditTable string `yaml:"org_audit_table"`
	// S3 bucket holding published Merkle trees + anonymized vote lists
	// (written by closeExpiredProposals, read by GetVoteProof)
	PublishedVotesBucket string `yaml:"published_votes_bucket"`
	// AWS region (defaults to KMS region if not set)
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
	// Endpoint, when non-empty, overrides the default AWS S3 endpoint
	// and forces path-style addressing. Used by Tier-2 Docker harness
	// to point at LocalStack (e.g. "http://localstack:4566"); empty in
	// production so the AWS SDK picks the standard regional endpoint.
	Endpoint string `yaml:"endpoint"`
}

// EnclaveConfig holds enclave connection settings
type EnclaveConfig struct {
	CID  uint32 `yaml:"cid"`
	Port uint32 `yaml:"port"`
	// VsockSecretID is the Secrets Manager secret ID for vsock authentication
	// SECURITY: Fetched at startup and written to /etc/vettid/vsock-secret
	VsockSecretID string `yaml:"vsock_secret_id"`
	// ExpectedPCR0 is the hex-encoded PCR0 value for attestation verification
	// SECURITY: If set, parent will verify enclave attestation against this value
	// Can also be loaded from SSM parameter /vettid/enclave/pcr0
	ExpectedPCR0 string `yaml:"expected_pcr0"`
	// PCR0SSMParameter is the SSM parameter path for PCR0. Fleet-shared
	// and load-bearing for legacy bring-up; superseded by EIFPath for
	// boot-time PCR loading on Nitro hosts. See loadExpectedPCRs for
	// the source-resolution order.
	PCR0SSMParameter string `yaml:"pcr0_ssm_parameter"`
	// EIFPath is the path to the local enclave image file. When set and
	// readable, parent extracts PCR0 from it via `nitro-cli describe-eif`
	// and prefers that value over SSM. The EIF is the immutable identity
	// of the enclave code that's actually about to run on this instance,
	// so it can't drift mid-rollout the way a fleet-shared SSM parameter
	// can (#236, the v6→v7 crash-loop pattern from 2026-05-15).
	EIFPath string `yaml:"eif_path"`
}

// HealthConfig holds health check settings
type HealthConfig struct {
	Port     int `yaml:"port"`
	Interval int `yaml:"interval_seconds"`
	// BindAddr controls which interface the health server listens on.
	// Defaults to 127.0.0.1 — the /internal/reclaim-from-pcr0 endpoint
	// is unauthenticated and SSM RunShellScript is the only intended
	// auth boundary, so the server must not be reachable off-host in
	// production. The Tier-2 Docker harness overrides this to 0.0.0.0
	// in parent.yaml.tmpl so the test driver can reach /ready through
	// the container's port mapping; the harness binary is built with
	// `-tags testharness` and never deployed.
	BindAddr string `yaml:"bind_addr"`
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

// DefaultConfig returns the default configuration.
//
// SECURITY (#117): the NATS URL here is a fallback; in production the
// CDK NitroStack renders parent.yaml with the canonical value (see
// cdk/lib/shared/nats-endpoints.ts) and the YAML overrides this
// default. Update both this literal and the CDK constant together when
// the internal zone moves.
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
			KeyPrefix: "",  // Supervisor controls full S3 key path (vaults/{owner_space}/...)
		},
		Enclave: EnclaveConfig{
			CID:              16, // Default enclave CID
			Port:             5000,
			PCR0SSMParameter: "/vettid/enclave/pcr/pcr0",                       // SSM fallback for PCR0
			EIFPath:          "/opt/vettid/enclave/vettid-vault-enclave.eif",   // Primary PCR0 source on Nitro hosts
		},
		Health: HealthConfig{
			Port:     8080,
			Interval: 30,
			BindAddr: "127.0.0.1", // localhost only by default — see HealthConfig docs
		},
		KMS: KMSConfig{
			SealingKeyARN: "", // Must be configured in production
			Region:        "us-east-1",
		},
	}
}
