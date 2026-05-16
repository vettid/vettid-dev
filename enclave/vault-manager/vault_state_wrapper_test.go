package main

import (
	"bytes"
	"testing"
)

func TestVaultStateWrapper_RoundTrip(t *testing.T) {
	payload := []byte("encrypted-vault-state-blob")

	wrapped, err := wrapVaultState(payload, 7)
	if err != nil {
		t.Fatalf("wrapVaultState: %v", err)
	}

	got, gen, isLegacy, err := unwrapVaultState(wrapped)
	if err != nil {
		t.Fatalf("unwrapVaultState: %v", err)
	}
	if isLegacy {
		t.Fatalf("round-tripped v1 wrapper should not be isLegacy")
	}
	if gen != 7 {
		t.Errorf("generation = %d, want 7", gen)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %q want %q", got, payload)
	}
}

func TestVaultStateWrapper_LegacyRawBytes(t *testing.T) {
	// Pre-D3 vault_state.enc was raw encrypted bytes — not valid JSON.
	// Cold-load must accept it as a legacy payload with generation 0
	// so existing vaults don't brick on the upgrade.
	raw := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}

	got, gen, isLegacy, err := unwrapVaultState(raw)
	if err != nil {
		t.Fatalf("unwrapVaultState(raw): %v", err)
	}
	if !isLegacy {
		t.Errorf("isLegacy = false, want true for raw non-JSON bytes")
	}
	if gen != 0 {
		t.Errorf("legacy generation = %d, want 0", gen)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("legacy payload mismatch")
	}
}

func TestVaultStateWrapper_EmptyBlob(t *testing.T) {
	got, gen, isLegacy, err := unwrapVaultState(nil)
	if err != nil {
		t.Fatalf("unwrapVaultState(nil): %v", err)
	}
	if !isLegacy {
		t.Errorf("isLegacy = false, want true for empty blob")
	}
	if gen != 0 || got != nil {
		t.Errorf("empty blob should produce zero values, got gen=%d data=%v", gen, got)
	}
}

func TestVaultStateWrapper_UnknownJSONIsLegacy(t *testing.T) {
	// An unrelated JSON object at this key is safer to treat as legacy
	// (next persist re-wraps it) than to interpret as a wrapper with
	// missing fields and zero out the payload.
	got, _, isLegacy, err := unwrapVaultState([]byte(`{"unrelated":"object"}`))
	if err != nil {
		t.Fatalf("unwrapVaultState: %v", err)
	}
	if !isLegacy {
		t.Errorf("unrelated JSON should be treated as legacy")
	}
	if string(got) != `{"unrelated":"object"}` {
		t.Errorf("legacy path should return original bytes")
	}
}

func TestVaultStateWrapper_UnsupportedVersionFails(t *testing.T) {
	// A wrapper that parses but advertises a future version is a real
	// format-drift signal; the load path must fail loudly rather than
	// silently fall through to "legacy".
	_, _, _, err := unwrapVaultState([]byte(`{"v":99,"g":1,"p":"YWJj"}`))
	if err == nil {
		t.Fatalf("expected error on unsupported wrapper version, got nil")
	}
}
