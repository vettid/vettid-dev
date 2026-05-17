package main

// Pins buildMigrationConfigCanonical's byte-for-byte output against
// the same fixture vault-manager uses (`enclave/migration/testdata/
// canonical-fixture.canonical`, generated once with
// `jq -cS 'del(.signature)' canonical-fixture.json`).
//
// The fixture is symlinked from this module's testdata/ so a single
// source of truth covers both sides of the signing chain — if the
// vault's signedPayload() ever drifts (key sort, time format, new
// optional field) the fixture regenerates and BOTH tests update or
// BOTH fail together. Drift between sides is what bit us in the
// 2026-05-11 incident: vault verifier and signer canonicals diverged
// silently, every migration was a no-op.

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestBuildMigrationConfigCanonical_MatchesVaultFixture(t *testing.T) {
	expected, err := os.ReadFile("testdata/canonical-fixture.canonical")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	// jq -cS appends a trailing newline; the in-memory canonical we
	// sign and PUT to S3 has none — trim once so the comparison is
	// against the same payload.
	expected = bytes.TrimRight(expected, "\n")

	in := migrationConfigInput{
		NewPCR0:        "410bc38f8fa1e49ee743bf3d14c0e7373c7393af8088e8f5e431955ca5c4bd461baac35f11407c15ba8d7faa61ac5edd",
		NewPCR1:        "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
		NewPCR2:        "2ef7ad05b8884bd4608a9efc4c6f3d94f4a58b18bbb05e3d26ef89e522ed71efaef0d93b3949d82597982462b4aaed32",
		OldPCR0:        "fcb13ce470986d91accf769fc0f801fe0323017d59cde1410e947a337c9d16979b2d636115a0937a3f520ac58ab844ef",
		OldPCR1:        "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
		OldPCR2:        "0fa3b49c2d855efa35a45d790995826146ddf6dbac676096a1eb17da853b16149326d9d3f5fe35d6c13a2afab0d74b5e",
		Version:        "2026-05-11-canon-fixture",
		ValidFrom:      time.Date(2026, 5, 11, 14, 0, 32, 0, time.UTC),
		PublishedAt:    time.Date(2026, 5, 11, 14, 0, 32, 0, time.UTC),
		MandatoryAfter: time.Date(2026, 5, 14, 14, 0, 32, 0, time.UTC),
		Summary:        "Test fixture for canonicalization regression.",
		DetailsURL:     "https://example.test/details.md",
		// ExpiresAt left zero — fixture has no expires_at; omission
		// must round-trip.
	}
	got, err := buildMigrationConfigCanonical(in)
	if err != nil {
		t.Fatalf("buildMigrationConfigCanonical: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("canonical bytes drift from vault fixture\n got: %s\nwant: %s", got, expected)
	}
}

// TestBuildMigrationConfigCanonical_OmitsZeroOptionals guards the
// rule that's most likely to silently break verification: time.Time
// fields with `omitempty` JSON tags don't actually omit zero values
// in Go's encoding/json — they emit `"0001-01-01T00:00:00Z"`. The
// vault's signedPayload() works around this with explicit IsZero()
// guards; the driver MUST do the same. A regression here would emit
// phantom fields that vault's canonical doesn't have → signature
// rejection with no obvious cause.
func TestBuildMigrationConfigCanonical_OmitsZeroOptionals(t *testing.T) {
	in := migrationConfigInput{
		OldPCR0:   "aa",
		NewPCR0:   "bb",
		Version:   "v",
		ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		// All other optional time/string fields are zero.
	}
	got, err := buildMigrationConfigCanonical(in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, banned := range []string{
		`"expires_at"`,
		`"published_at"`,
		`"mandatory_after"`,
		`"summary"`,
		`"details_url"`,
		`"0001-01-01`, // any phantom zero-time leak
	} {
		if bytes.Contains(got, []byte(banned)) {
			t.Errorf("canonical leaked %s when input was zero: %s", banned, got)
		}
	}
}
