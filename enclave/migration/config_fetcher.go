package migration

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
)

// ConfigFetcher fetches PCR configuration from a backing store.
// Implementations may fetch from Secrets Manager, local files, etc.
type ConfigFetcher interface {
	// Fetch retrieves the signed PCR configuration.
	// Returns the raw JSON bytes of the configuration.
	Fetch() ([]byte, error)
}

// MigrationConfig holds the configuration for enclave migration.
type MigrationConfig struct {
	// DeploymentPublicKey is the Ed25519 public key used to verify signed PCR configs.
	// This should be embedded at build time.
	DeploymentPublicKey ed25519.PublicKey

	// CurrentPCRs are the PCR values of the currently running enclave.
	// Obtained from the NSM attestation document.
	CurrentPCRs *PCRValues

	// ConfigFetcher retrieves the signed PCR config from storage.
	ConfigFetcher ConfigFetcher
}

// MigrationManager handles fetching and validating PCR configurations for migration.
type MigrationManager struct {
	config   *MigrationConfig
	verifier *PCRConfigVerifier
}

// NewMigrationManager creates a new migration manager.
func NewMigrationManager(config *MigrationConfig) (*MigrationManager, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if config.DeploymentPublicKey == nil {
		return nil, fmt.Errorf("deployment public key is required")
	}

	if config.CurrentPCRs == nil {
		return nil, fmt.Errorf("current PCRs are required")
	}

	if config.ConfigFetcher == nil {
		return nil, fmt.Errorf("config fetcher is required")
	}

	verifier, err := NewPCRConfigVerifier(config.DeploymentPublicKey, config.CurrentPCRs)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	return &MigrationManager{
		config:   config,
		verifier: verifier,
	}, nil
}

// GetNewPCRsForMigration fetches and verifies the PCR configuration,
// returning the new PCR values if migration is needed.
//
// Returns:
// - (*PCRValues, nil) if migration config is valid and migration is needed
// - (nil, nil) if no migration config exists
// - (nil, error) if there's an error fetching or validating the config
func (m *MigrationManager) GetNewPCRsForMigration() (*PCRValues, error) {
	log.Info().Msg("Checking for PCR migration config")

	// Fetch the signed config
	configData, err := m.config.ConfigFetcher.Fetch()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch PCR config: %w", err)
	}

	if configData == nil {
		log.Debug().Msg("No migration config found")
		return nil, nil
	}

	// Parse the config
	var signedConfig SignedPCRConfig
	if err := json.Unmarshal(configData, &signedConfig); err != nil {
		return nil, fmt.Errorf("failed to parse PCR config: %w", err)
	}

	// Verify the config
	if err := m.verifier.Verify(&signedConfig); err != nil {
		return nil, fmt.Errorf("PCR config verification failed: %w", err)
	}

	// Check if new PCRs are different from current
	if signedConfig.NewPCRs.Equals(m.config.CurrentPCRs) {
		log.Info().Msg("Migration config found but new PCRs match current - no migration needed")
		return nil, nil
	}

	log.Info().
		Str("version", signedConfig.Version).
		Str("new_pcr0", signedConfig.NewPCRs.PCR0[:16]+"...").
		Msg("Migration required - new PCR values found")

	return &signedConfig.NewPCRs, nil
}

// MigrationStatus represents the current migration state.
type MigrationStatus string

const (
	MigrationStatusNone       MigrationStatus = "none"        // No migration needed/available
	MigrationStatusPending    MigrationStatus = "pending"     // Migration config found, not started
	MigrationStatusInProgress MigrationStatus = "in_progress" // Migration running
	MigrationStatusCompleted  MigrationStatus = "completed"   // Migration finished successfully
	MigrationStatusFailed     MigrationStatus = "failed"      // Migration failed
)

// MigrationState tracks the state of an enclave migration.
type MigrationState struct {
	Status     MigrationStatus `json:"status"`
	NewPCRs    *PCRValues      `json:"new_pcrs,omitempty"`
	Version    string          `json:"version,omitempty"`
	StartedAt  int64           `json:"started_at,omitempty"`
	FinishedAt int64           `json:"finished_at,omitempty"`
	Error      string          `json:"error,omitempty"`

	// Migration progress
	TotalUsers     int `json:"total_users,omitempty"`
	MigratedUsers  int `json:"migrated_users,omitempty"`
	FailedUsers    int `json:"failed_users,omitempty"`
}
