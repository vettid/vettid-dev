package main

import (
	"sync"

	"github.com/rs/zerolog/log"
)

// MemoryManager tracks memory usage within the enclave
type MemoryManager struct {
	totalMB     int
	usedMB      int
	reservedMB  int
	maxVaults   int
	mu          sync.Mutex
}

// MemoryStats holds memory statistics
type MemoryStats struct {
	TotalMB    int
	UsedMB     int
	ReservedMB int
	FreeMB     int
}

// NewMemoryManager creates a new memory manager
func NewMemoryManager(totalMB int, maxVaults int) *MemoryManager {
	return &MemoryManager{
		totalMB:   totalMB,
		maxVaults: maxVaults,
	}
}

// Reserve attempts to reserve memory for a vault
func (m *MemoryManager) Reserve(mb int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.usedMB+mb > m.totalMB {
		log.Warn().
			Int("requested_mb", mb).
			Int("used_mb", m.usedMB).
			Int("total_mb", m.totalMB).
			Msg("Memory reservation failed")
		return false
	}

	m.usedMB += mb
	m.reservedMB += mb

	log.Debug().
		Int("reserved_mb", mb).
		Int("used_mb", m.usedMB).
		Int("total_mb", m.totalMB).
		Msg("Memory reserved")

	return true
}

// Release releases previously reserved memory
func (m *MemoryManager) Release(mb int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.usedMB -= mb
	if m.usedMB < 0 {
		m.usedMB = 0
	}

	m.reservedMB -= mb
	if m.reservedMB < 0 {
		m.reservedMB = 0
	}

	log.Debug().
		Int("released_mb", mb).
		Int("used_mb", m.usedMB).
		Int("total_mb", m.totalMB).
		Msg("Memory released")
}

// GetStats returns memory statistics
func (m *MemoryManager) GetStats() MemoryStats {
	m.mu.Lock()
	defer m.mu.Unlock()

	return MemoryStats{
		TotalMB:    m.totalMB,
		UsedMB:     m.usedMB,
		ReservedMB: m.reservedMB,
		FreeMB:     m.totalMB - m.usedMB,
	}
}

// CanAllocate checks if a given amount of memory can be allocated
func (m *MemoryManager) CanAllocate(mb int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.usedMB+mb <= m.totalMB
}

// UsagePercent returns the percentage of memory used
func (m *MemoryManager) UsagePercent() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.totalMB == 0 {
		return 0
	}
	return float64(m.usedMB) / float64(m.totalMB) * 100
}
