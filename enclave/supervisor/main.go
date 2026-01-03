// Package main implements the Nitro Enclave Supervisor for VettID.
// The supervisor manages vault-manager processes inside the enclave,
// routing messages from the parent process to the correct vault.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Version is set at build time
var Version = "dev"

func main() {
	// Parse command line flags
	devMode := flag.Bool("dev-mode", false, "Run in development mode (TCP instead of vsock)")
	vsockPort := flag.Uint("vsock-port", 5000, "vsock port to listen on (CID is always 3 in enclave)")
	tcpPort := flag.Uint("tcp-port", 5000, "TCP port for dev mode")
	maxVaults := flag.Int("max-vaults", 160, "Maximum concurrent vaults in memory")
	maxMemoryMB := flag.Int("max-memory", 5632, "Maximum memory usage in MB (6GB - 512MB overhead)")
	flag.Parse()

	// Configure logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if *devMode {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	log.Info().
		Str("version", Version).
		Bool("dev_mode", *devMode).
		Uint("vsock_port", *vsockPort).
		Int("max_vaults", *maxVaults).
		Msg("VettID Enclave Supervisor starting")

	// Create supervisor configuration
	cfg := &Config{
		DevMode:     *devMode,
		VsockPort:   uint32(*vsockPort),
		TCPPort:     uint16(*tcpPort),
		MaxVaults:   *maxVaults,
		MaxMemoryMB: *maxMemoryMB,
	}

	// Create and start supervisor
	supervisor, err := NewSupervisor(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create supervisor")
	}

	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
	}()

	// Run supervisor (blocks until context is cancelled)
	if err := supervisor.Run(ctx); err != nil {
		log.Fatal().Err(err).Msg("Supervisor error")
	}

	log.Info().Msg("Supervisor shutdown complete")
}
