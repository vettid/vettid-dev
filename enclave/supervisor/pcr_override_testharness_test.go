//go:build testharness

package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestFakePCR0Reader_ValidEnvOverride(t *testing.T) {
	want := strings.Repeat("ab", 48) // 48 bytes hex = SHA-384 width
	t.Setenv("FAKE_PCR0_HEX", want)

	got, err := fakePCR0Reader()
	if err != nil {
		t.Fatalf("fakePCR0Reader: %v", err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFakePCR0Reader_WrongLengthRejected(t *testing.T) {
	// 32 bytes — SHA-256 width, not SHA-384. Must be rejected loudly
	// rather than silently used, otherwise a test container with a
	// malformed env var would produce a junk PCR0 that masks the real
	// test failure.
	t.Setenv("FAKE_PCR0_HEX", strings.Repeat("ab", 32))
	if _, err := fakePCR0Reader(); err == nil {
		t.Fatalf("expected error on 32-byte FAKE_PCR0_HEX, got nil")
	}
}

func TestFakePCR0Reader_NonHexRejected(t *testing.T) {
	t.Setenv("FAKE_PCR0_HEX", "not-actually-hex-content!!!")
	if _, err := fakePCR0Reader(); err == nil {
		t.Fatalf("expected error on non-hex FAKE_PCR0_HEX, got nil")
	}
}

func TestFakePCR0Reader_UnsetFallsThroughToDefault(t *testing.T) {
	// Empty env → defer to readRunningPCR0Hex, which in a non-Nitro
	// test environment returns hex-encoded mockPCR(0).
	t.Setenv("FAKE_PCR0_HEX", "")
	got, err := fakePCR0Reader()
	if err != nil {
		t.Fatalf("fakePCR0Reader: %v", err)
	}
	want := hex.EncodeToString(mockPCR(0))
	if got != want {
		t.Errorf("fallback mismatch: got %q, want %q", got, want)
	}
}

func TestFakePCR0Reader_IsWiredAsDefault(t *testing.T) {
	// Sanity check that the build-tagged init() actually overrode
	// runningPCR0Reader. If a refactor accidentally drops the init,
	// production behavior would silently take over in the harness.
	t.Setenv("FAKE_PCR0_HEX", strings.Repeat("cd", 48))
	got, err := runningPCR0Reader()
	if err != nil {
		t.Fatalf("runningPCR0Reader: %v", err)
	}
	want := strings.Repeat("cd", 48)
	if got != want {
		t.Errorf("runningPCR0Reader not wired to testharness override: got %q, want %q", got, want)
	}
}
