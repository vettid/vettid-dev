package main

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// OrgVaultManager manages the lifecycle of org-vault-manager processes.
// It parallels VaultManager but spawns org-vault-manager binaries instead of
// vault-manager binaries. The VaultProcess struct is shared — its ProcessMessage
// loop handles HTTP proxy, NATS publish, sealer, log, and audit events generically.
type OrgVaultManager struct {
	config         *Config
	memoryManager  *MemoryManager
	parentSender   ParentSender
	sealer         *NitroSealer
	sealerHandler  *SealerHandler
	processManager *ProcessManager

	vaults    map[string]*VaultProcess
	lruOrder  []string
	mu        sync.RWMutex
	startTime time.Time
}

// NewOrgVaultManager creates a new org vault manager.
func NewOrgVaultManager(cfg *Config, memMgr *MemoryManager, parentSender ParentSender, sealer *NitroSealer, logForwarder LogForwarder) *OrgVaultManager {
	sealerHandler := NewSealerHandler(sealer)
	// SECURITY (#74): inherit devMode so production fails-closed on
	// missing parent connection — same rationale as vault_lifecycle.go.
	sealerHandler.SetDevMode(cfg.DevMode)
	procMgr := NewProcessManager(cfg.OrgVaultManagerPath, cfg.DevMode, sealerHandler, logForwarder)

	return &OrgVaultManager{
		config:         cfg,
		memoryManager:  memMgr,
		parentSender:   parentSender,
		sealer:         sealer,
		sealerHandler:  sealerHandler,
		processManager: procMgr,
		vaults:         make(map[string]*VaultProcess),
		lruOrder:       make([]string, 0),
		startTime:      time.Now(),
	}
}

// GetOrCreate gets an existing org vault or creates a new one.
func (om *OrgVaultManager) GetOrCreate(ctx context.Context, ownerSpace string) (*VaultProcess, error) {
	om.mu.Lock()
	defer om.mu.Unlock()

	if vault, exists := om.vaults[ownerSpace]; exists {
		if vault.isAlive() {
			vault.touch()
			om.updateLRU(ownerSpace)
			return vault, nil
		}
		log.Info().
			Str("owner_space", ownerSpace).
			Msg("GetOrCreate: cached org vault subprocess has exited — replacing with a fresh one")
		om.removeVault(ownerSpace)
	}

	// Check if we need to evict
	if len(om.vaults) >= om.config.MaxVaults/4 { // Org vaults get 1/4 of capacity
		om.evictLRU()
	}

	log.Info().
		Str("owner_space", ownerSpace).
		Msg("Spawning new org-vault-manager process")

	process, err := om.processManager.Spawn(ownerSpace)
	if err != nil {
		return nil, err
	}

	// newVaultProcess inits the pending map and starts the pipe reader
	// — both required for ProcessMessage. The old inline struct skipped
	// them, so an org-vault op nil-map-panicked the supervisor.
	vault := newVaultProcess(ownerSpace, process, om.parentSender, om.sealerHandler, 40)

	om.vaults[ownerSpace] = vault
	om.lruOrder = append(om.lruOrder, ownerSpace)

	return vault, nil
}

// removeVault kills an org vault's subprocess by its exact handle and
// drops it from the resident set and the LRU list. Must hold om.mu.
func (om *OrgVaultManager) removeVault(ownerSpace string) {
	vault, exists := om.vaults[ownerSpace]
	if !exists {
		return
	}
	if vault.process != nil {
		vault.process.kill()
	}
	delete(om.vaults, ownerSpace)
	for i, os := range om.lruOrder {
		if os == ownerSpace {
			om.lruOrder = append(om.lruOrder[:i], om.lruOrder[i+1:]...)
			break
		}
	}
}

// SetMux wires the multiplexed parent transport into the org-vault
// SealerHandler so org-vault-manager S3/KMS proxy requests reach the parent.
func (om *OrgVaultManager) SetMux(mux *MuxConn) {
	if om.sealerHandler != nil {
		om.sealerHandler.SetMux(mux)
	}
}

// updateLRU moves an owner space to the end of the LRU list.
func (om *OrgVaultManager) updateLRU(ownerSpace string) {
	for i, os := range om.lruOrder {
		if os == ownerSpace {
			om.lruOrder = append(om.lruOrder[:i], om.lruOrder[i+1:]...)
			om.lruOrder = append(om.lruOrder, ownerSpace)
			return
		}
	}
}

// evictLRU evicts the least recently used org vault.
func (om *OrgVaultManager) evictLRU() {
	if len(om.lruOrder) == 0 {
		return
	}

	evictSpace := om.lruOrder[0]
	log.Info().
		Str("owner_space", evictSpace).
		Msg("Evicting org vault (LRU)")
	// removeVault kills by handle (closing the pipe so the reader
	// exits) and drops the LRU entry.
	om.removeVault(evictSpace)
}
