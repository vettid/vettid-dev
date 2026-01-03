// Package main implements the Parent Process for VettID Nitro Enclave.
// The parent process runs on the EC2 host and bridges the enclave
// to external services (NATS, S3) via vsock.
//
// SECURITY: The parent process is in the UNTRUSTED zone.
// It only sees encrypted blobs - never plaintext vault data.
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
	configPath := flag.String("config", "/etc/vettid/parent.yaml", "Path to configuration file")
	devMode := flag.Bool("dev-mode", false, "Run in development mode (no enclave)")
	natsURL := flag.String("nats-url", "", "NATS server URL (overrides config)")
	s3Bucket := flag.String("s3-bucket", "", "S3 bucket for vault data (overrides config)")
	enclaveCID := flag.Uint("enclave-cid", 16, "Enclave CID for vsock connection")
	enclavePort := flag.Uint("enclave-port", 5000, "Enclave vsock port")
	flag.Parse()

	// Configure logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	log.Info().
		Str("version", Version).
		Str("config", *configPath).
		Bool("dev_mode", *devMode).
		Msg("VettID Parent Process starting")

	// Load configuration
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Override with command line flags
	if *natsURL != "" {
		cfg.NATS.URL = *natsURL
	}
	if *s3Bucket != "" {
		cfg.S3.Bucket = *s3Bucket
	}
	cfg.Enclave.CID = uint32(*enclaveCID)
	cfg.Enclave.Port = uint32(*enclavePort)
	cfg.DevMode = *devMode

	// Create parent process
	parent, err := NewParentProcess(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create parent process")
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

	// Run parent process (blocks until context is cancelled)
	if err := parent.Run(ctx); err != nil {
		log.Fatal().Err(err).Msg("Parent process error")
	}

	log.Info().Msg("Parent process shutdown complete")
}
