package main

import (
	"sync"

	"github.com/rs/zerolog/log"
)

// NATSProxy provides NATS account operations for the vault-manager.
// The account seed is loaded via the sealer proxy (which routes through
// the supervisor to the parent for DynamoDB + KMS decryption).
type NATSProxy struct {
	ownerSpace string

	// Cache account seed after first fetch
	accountSeedMu sync.Mutex
	accountSeed   string
}

// NewNATSProxy creates a new NATS proxy
func NewNATSProxy(ownerSpace string) *NATSProxy {
	return &NATSProxy{
		ownerSpace: ownerSpace,
	}
}

// SetAccountSeed stores the account seed (called when loaded via sealer proxy)
func (p *NATSProxy) SetAccountSeed(seed string) {
	p.accountSeedMu.Lock()
	defer p.accountSeedMu.Unlock()
	p.accountSeed = seed
	log.Debug().Str("owner_space", p.ownerSpace).Msg("Account seed cached")
}

// GetAccountSeed returns the cached account seed
func (p *NATSProxy) GetAccountSeed() string {
	p.accountSeedMu.Lock()
	defer p.accountSeedMu.Unlock()
	return p.accountSeed
}

// HasAccountSeed returns whether the account seed is cached
func (p *NATSProxy) HasAccountSeed() bool {
	p.accountSeedMu.Lock()
	defer p.accountSeedMu.Unlock()
	return p.accountSeed != ""
}
