package main

// Config holds the supervisor configuration
type Config struct {
	// DevMode enables development mode (TCP instead of vsock)
	DevMode bool

	// VsockPort is the vsock port to listen on (CID is always 3 inside enclave)
	VsockPort uint32

	// TCPPort is the TCP port for development mode
	TCPPort uint16

	// MaxVaults is the maximum number of concurrent vaults in memory
	MaxVaults int

	// MaxMemoryMB is the maximum memory usage in megabytes
	MaxMemoryMB int

	// VaultManagerPath is the path to the vault-manager binary
	VaultManagerPath string

	// StateDir is the directory for vault state (in-memory tmpfs in enclave)
	StateDir string
}

// DefaultConfig returns the default supervisor configuration
func DefaultConfig() *Config {
	return &Config{
		DevMode:          false,
		VsockPort:        5000,
		TCPPort:          5000,
		MaxVaults:        160,
		MaxMemoryMB:      5632, // 6GB - 512MB overhead
		VaultManagerPath: "/usr/local/bin/vault-manager",
		StateDir:         "/var/lib/enclave",
	}
}
