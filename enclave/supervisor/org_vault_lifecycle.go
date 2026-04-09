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
		vault.touch()
		om.updateLRU(ownerSpace)
		return vault, nil
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

	vault := &VaultProcess{
		OwnerSpace:    ownerSpace,
		StartedAt:     time.Now(),
		LastAccess:    time.Now(),
		MemoryMB:      40,
		parentSender:  om.parentSender,
		process:       process,
		sealerHandler: om.sealerHandler,
	}

	om.vaults[ownerSpace] = vault
	om.lruOrder = append(om.lruOrder, ownerSpace)

	return vault, nil
}

// SetParentConnection updates the parent connection for sealer operations.
func (om *OrgVaultManager) SetParentConnection(conn Connection) {
	if om.sealerHandler != nil {
		om.sealerHandler.SetParentConnection(conn)
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
	om.lruOrder = om.lruOrder[1:]

	if vault, exists := om.vaults[evictSpace]; exists {
		log.Info().
			Str("owner_space", evictSpace).
			Msg("Evicting org vault (LRU)")
		if vault.process != nil && vault.process.Cmd != nil && vault.process.Cmd.Process != nil {
			vault.process.Cmd.Process.Kill()
		}
		delete(om.vaults, evictSpace)
	}
}
