package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// sealedMaterialWrapper is the migration_handler-side mirror of
// supervisor.SealedMaterialData. These tests pin its on-disk JSON
// shape so changes to either side don't silently diverge — the
// supervisor writes the wrapper at fresh enrollment, the migration
// handler rewrites it during re-seal, and any field that one side
// emits but the other can't parse is a data-loss risk.
//
// The backward-compat tests are load-bearing: legacy v1 wrappers
// (no generation / sealed_to_pcr0 / sealed_to_version) must continue
// to parse cleanly — they are what's on disk for any user who
// enrolled before the M3 redesign. A panic or unmarshal error here
// would lock that user out.

func TestSealedMaterialWrapper_RoundTripPreservesAllFields(t *testing.T) {
	original := sealedMaterialWrapper{
		Version:         1,
		SealedMaterial:  []byte("kms-ciphertext-bytes"),
		OwnerID:         "user-abc",
		CreatedAt:       1714000000,
		Generation:      7,
		SealedToPCR0:    "abcdef0123456789",
		SealedToVersion: "2026-05-09-v3",
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed sealedMaterialWrapper
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if parsed.Version != original.Version {
		t.Errorf("Version: got %d, want %d", parsed.Version, original.Version)
	}
	if string(parsed.SealedMaterial) != string(original.SealedMaterial) {
		t.Errorf("SealedMaterial: got %q, want %q", parsed.SealedMaterial, original.SealedMaterial)
	}
	if parsed.OwnerID != original.OwnerID {
		t.Errorf("OwnerID: got %q, want %q", parsed.OwnerID, original.OwnerID)
	}
	if parsed.CreatedAt != original.CreatedAt {
		t.Errorf("CreatedAt: got %d, want %d", parsed.CreatedAt, original.CreatedAt)
	}
	if parsed.Generation != original.Generation {
		t.Errorf("Generation: got %d, want %d", parsed.Generation, original.Generation)
	}
	if parsed.SealedToPCR0 != original.SealedToPCR0 {
		t.Errorf("SealedToPCR0: got %q, want %q", parsed.SealedToPCR0, original.SealedToPCR0)
	}
	if parsed.SealedToVersion != original.SealedToVersion {
		t.Errorf("SealedToVersion: got %q, want %q", parsed.SealedToVersion, original.SealedToVersion)
	}
}

func TestSealedMaterialWrapper_LegacyV1ParsesAsZeroForNewFields(t *testing.T) {
	// A wrapper written before M3 (no generation/sealed_to_pcr0/sealed_to_version).
	// Real data still on disk for any user who enrolled before the redesign.
	legacy := []byte(`{
		"version": 1,
		"sealed_material": "abc=",
		"owner_id": "legacy-user",
		"created_at": 1700000000
	}`)

	var parsed sealedMaterialWrapper
	if err := json.Unmarshal(legacy, &parsed); err != nil {
		t.Fatalf("legacy v1 wrapper failed to parse: %v", err)
	}

	if parsed.OwnerID != "legacy-user" {
		t.Errorf("OwnerID: got %q, want %q", parsed.OwnerID, "legacy-user")
	}
	if parsed.Generation != 0 {
		t.Errorf("Generation should default to 0 for legacy wrappers; got %d", parsed.Generation)
	}
	if parsed.SealedToPCR0 != "" {
		t.Errorf("SealedToPCR0 should default to empty for legacy wrappers; got %q", parsed.SealedToPCR0)
	}
	if parsed.SealedToVersion != "" {
		t.Errorf("SealedToVersion should default to empty for legacy wrappers; got %q", parsed.SealedToVersion)
	}
	if len(parsed.SealedMaterial) == 0 {
		t.Error("SealedMaterial should still parse from legacy wrappers")
	}
}

func TestSealedMaterialWrapper_OmitemptyHidesZeroNewFields(t *testing.T) {
	// On the wire, a freshly-promoted-from-legacy wrapper that hasn't been
	// stamped yet shouldn't emit `"generation": 0`, `"sealed_to_pcr0": ""`,
	// or `"sealed_to_version": ""` — that would conflict with legacy
	// readers that don't expect those keys. omitempty on the struct tags
	// is what enforces this.
	w := sealedMaterialWrapper{
		Version:        1,
		SealedMaterial: []byte("x"),
		OwnerID:        "u",
		CreatedAt:      1,
	}

	raw, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := string(raw)
	for _, key := range []string{`"generation"`, `"sealed_to_pcr0"`, `"sealed_to_version"`} {
		if strings.Contains(got, key) {
			t.Errorf("zero-valued new field leaked into JSON: %s in %s", key, got)
		}
	}
}

// (Removed 2026-05-11) TestSealedMaterialWrapper_GenerationIncrementsFromLegacy
// was a tautology — it asserted `existing.Generation+1 == expected` by
// computing both sides in the test body, never touching production
// code. Real coverage of the increment behavior lives in the Tier-2
// docker-pair harness (enclave/tests/migration/) which exercises
// resealMaterial against fake-KMS and asserts the actual generation
// stamped on the stored sealed_material wrapper.

