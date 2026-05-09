package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// SealedMaterialData is the canonical JSON wrapper around
// KMS-sealed PIN-derivation material (sealed_material.bin in S3).
// These tests pin its on-disk shape so:
//
//   - Legacy v1 wrappers (no generation / sealed_to_pcr0 /
//     sealed_to_version, written before the M3 redesign) still
//     parse cleanly. Anything else is data loss for users who
//     enrolled before the redesign.
//
//   - Newly-stamped fields survive a JSON round-trip. The
//     vault-manager re-seal path mirrors this struct as a local
//     `sealedMaterialWrapper`; field names and JSON tags must
//     stay in sync across the two packages.
//
//   - omitempty hides zero values for the new fields. A wrapper
//     that hasn't been stamped yet (e.g., emitted by a code path
//     before GetRunningPCR0Hex resolved) must not emit
//     `"sealed_to_pcr0": ""` — legacy readers don't expect those
//     keys.

func TestSealedMaterialData_RoundTripPreservesAllFields(t *testing.T) {
	original := SealedMaterialData{
		Version:         1,
		SealedMaterial:  []byte("kms-ciphertext"),
		OwnerID:         "owner-xyz",
		CreatedAt:       1714000000,
		Generation:      3,
		SealedToPCR0:    "deadbeef",
		SealedToVersion: "2026-05-09-v3",
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed SealedMaterialData
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
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
	if parsed.OwnerID != original.OwnerID {
		t.Errorf("OwnerID: got %q, want %q", parsed.OwnerID, original.OwnerID)
	}
	if string(parsed.SealedMaterial) != string(original.SealedMaterial) {
		t.Errorf("SealedMaterial round-trip mismatch")
	}
}

func TestSealedMaterialData_LegacyV1WrapperStillReadable(t *testing.T) {
	// Real shape of a wrapper written by the pre-M3 supervisor.
	legacy := []byte(`{
		"version": 1,
		"sealed_material": "Y2lwaGVydGV4dA==",
		"owner_id": "pre-redesign-user",
		"created_at": 1700000000
	}`)

	var parsed SealedMaterialData
	if err := json.Unmarshal(legacy, &parsed); err != nil {
		t.Fatalf("legacy v1 must parse without error; got: %v", err)
	}

	if parsed.OwnerID != "pre-redesign-user" {
		t.Errorf("OwnerID: got %q", parsed.OwnerID)
	}
	if parsed.Generation != 0 {
		t.Errorf("Generation should be 0 for legacy wrappers; got %d", parsed.Generation)
	}
	if parsed.SealedToPCR0 != "" {
		t.Errorf("SealedToPCR0 should be empty for legacy wrappers; got %q", parsed.SealedToPCR0)
	}
	if parsed.SealedToVersion != "" {
		t.Errorf("SealedToVersion should be empty for legacy wrappers; got %q", parsed.SealedToVersion)
	}
	if len(parsed.SealedMaterial) == 0 {
		t.Error("SealedMaterial must still decode from legacy wrappers")
	}
}

func TestSealedMaterialData_OmitemptyHidesZeroNewFields(t *testing.T) {
	w := SealedMaterialData{
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

// TestSealedMaterialData_TagsMatchVaultManagerWrapper guards against
// silent divergence with the vault-manager-side mirror of this struct.
// If you add a field on this side, the corresponding `sealedMaterialWrapper`
// in enclave/vault-manager/migration_handler.go MUST get the same JSON
// tag, or re-seal will silently drop the value during round-trip.
func TestSealedMaterialData_TagsMatchVaultManagerWrapper(t *testing.T) {
	// Validate that a marshalled struct has exactly the expected key set.
	// If a new field is added, this test forces a corresponding update on
	// the other side (and then this test itself).
	full := SealedMaterialData{
		Version:         1,
		SealedMaterial:  []byte("x"),
		OwnerID:         "u",
		CreatedAt:       1,
		Generation:      1,
		SealedToPCR0:    "ff",
		SealedToVersion: "v",
	}
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	expected := []string{
		`"version"`,
		`"sealed_material"`,
		`"owner_id"`,
		`"created_at"`,
		`"generation"`,
		`"sealed_to_pcr0"`,
		`"sealed_to_version"`,
	}
	got := string(raw)
	for _, key := range expected {
		if !strings.Contains(got, key) {
			t.Errorf("expected JSON key %s missing from: %s", key, got)
		}
	}

	// Decode into a map and assert the exact key count to catch new
	// additions that aren't reflected here.
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatalf("unmarshal-as-map: %v", err)
	}
	if len(asMap) != len(expected) {
		t.Errorf("unexpected key count: got %d, want %d. Update both this test and the vault-manager-side mirror.", len(asMap), len(expected))
	}
}
