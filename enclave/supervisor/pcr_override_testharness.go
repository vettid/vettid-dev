//go:build testharness

package main

import (
	"encoding/hex"
	"fmt"
	"os"
)

// This file is the Tier-2 Docker pair migration harness's hook for
// running two parallel "enclave" containers with different PCR0s — the
// architect spec's "two parents with different fake PCR0s baked in"
// needed for migration scenarios where OLD attests to one value and
// NEW attests to another.
//
// SECURITY: this file ONLY compiles when the build tag `testharness`
// is set (`go build -tags testharness`). The production binary
// (`vettid-supervisor`, built without the tag) never includes this
// file, never sees the FAKE_PCR0_HEX env var, and cannot have its
// runningPCR0Reader overridden. The cmd/supervisor-test main package
// is the only production-shape binary that opts into this tag.
//
// Validation is strict: the env var must be 48 raw bytes encoded as
// 96 hex characters (SHA-384 / Nitro PCR width). A missing or
// malformed value falls through to the default reader so a misconfigured
// test container produces an obvious error instead of silently using
// junk PCR0 bytes that would mask the real test failure.

func init() {
	runningPCR0Reader = fakePCR0Reader
}

func fakePCR0Reader() (string, error) {
	raw := os.Getenv("FAKE_PCR0_HEX")
	if raw == "" {
		// No override configured — defer to the default reader so the
		// existing mockPCR fallback still applies for ad-hoc dev runs.
		return readRunningPCR0Hex()
	}
	bytes, err := hex.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("testharness FAKE_PCR0_HEX invalid hex: %w", err)
	}
	if len(bytes) != 48 {
		return "", fmt.Errorf("testharness FAKE_PCR0_HEX wrong length: got %d bytes, want 48 (SHA-384)", len(bytes))
	}
	return hex.EncodeToString(bytes), nil
}
