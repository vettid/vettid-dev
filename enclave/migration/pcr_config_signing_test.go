package migration

// Regression test for the signed-payload canonical form.
//
// The signer (enclave/scripts/sign-pcr-config.sh) hashes the output
// of `jq -cS 'del(.signature)'` — compact JSON with alphabetically-
// sorted keys at every nesting level. The verifier (signedPayload
// in pcr_config.go) must produce byte-identical output, otherwise
// the SHA-256 hashes diverge and every ECDSA verification fails.
//
// The 2026-05-11 incident: signedPayload used Go's default struct
// marshal which emits fields in declaration order. Every published
// migration config's signature failed verification, dispatchMigrateConsent
// returned "not_requested", and migration silently no-opped.
// fetchAndVerifyMigrationConfig was the chokepoint and it never
// flagged this because the only way the bug surfaced was end-to-end:
// no unit test compared signer vs verifier bytes.

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestSignedPayloadCanonical_AlphabeticalKeys(t *testing.T) {
	cfg := &SignedPCRConfig{
		NewPCRs: PCRValues{
			PCR0: "410bc38f8fa1e49ee743bf3d14c0e7373c7393af8088e8f5e431955ca5c4bd461baac35f11407c15ba8d7faa61ac5edd",
			PCR1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
			PCR2: "2ef7ad05b8884bd4608a9efc4c6f3d94f4a58b18bbb05e3d26ef89e522ed71efaef0d93b3949d82597982462b4aaed32",
		},
		OldPCRs: PCRValues{
			PCR0: "fcb13ce470986d91accf769fc0f801fe0323017d59cde1410e947a337c9d16979b2d636115a0937a3f520ac58ab844ef",
			PCR1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
			PCR2: "0fa3b49c2d855efa35a45d790995826146ddf6dbac676096a1eb17da853b16149326d9d3f5fe35d6c13a2afab0d74b5e",
		},
		ValidFrom:      time.Date(2026, 5, 11, 14, 0, 32, 0, time.UTC),
		Version:        "2026-05-11-v1",
		Summary:        "Your approval is required to apply a security update to your vault.",
		DetailsURL:     "https://example.test/details.md",
		PublishedAt:    time.Date(2026, 5, 11, 14, 0, 32, 0, time.UTC),
		MandatoryAfter: time.Date(2026, 5, 14, 14, 0, 32, 0, time.UTC),
	}

	out, err := cfg.signedPayload()
	if err != nil {
		t.Fatalf("signedPayload: %v", err)
	}

	// 1. Re-parse and verify all expected fields landed.
	var got map[string]interface{}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal output: %v\nbytes: %s", err, string(out))
	}
	wantKeys := []string{
		"details_url", "mandatory_after", "new_pcrs", "old_pcrs",
		"published_at", "summary", "valid_from", "version",
	}
	gotKeys := make([]string, 0, len(got))
	for k := range got {
		gotKeys = append(gotKeys, k)
	}
	sort.Strings(gotKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Errorf("key set mismatch\n got: %v\nwant: %v", gotKeys, wantKeys)
	}

	// 2. Walk the byte stream to assert keys appear in alphabetical
	//    order. json.Marshal of a map[string]json.RawMessage emits
	//    keys sorted; this guard catches any future change that
	//    accidentally reverts to struct-order marshaling.
	s := string(out)
	prev := ""
	for _, k := range []string{`"details_url"`, `"mandatory_after"`, `"new_pcrs"`, `"old_pcrs"`, `"published_at"`, `"summary"`, `"valid_from"`, `"version"`} {
		idx := strings.Index(s, k)
		if idx < 0 {
			t.Errorf("missing key %s in canonical output: %s", k, s)
			continue
		}
		if prev != "" && idx < strings.Index(s, prev) {
			t.Errorf("key %s appears before %s — canonical output not sorted: %s", k, prev, s)
		}
		prev = k
	}

	// 3. ExpiresAt is zero; should NOT appear (matches signer's
	//    `del(.signature)` + the field's omitempty semantics).
	if strings.Contains(s, `"expires_at"`) {
		t.Errorf("expires_at unexpectedly emitted when zero: %s", s)
	}

	// 4. `signature` is by definition not part of signedPayload.
	if strings.Contains(s, `"signature"`) {
		t.Errorf("signature must not be in signed payload: %s", s)
	}
}

// TestSignedPayloadCanonical_MatchesJqOutput exists to document — for
// any future maintainer who adds a field — that the test fixture
// above must stay in lockstep with sign-pcr-config.sh's
// `jq -cS 'del(.signature)'`. A failing TestSignedPayloadCanonical_AlphabeticalKeys
// on a new field means either the struct field needs to be added
// here, or the signer canonicalization has drifted.
func TestSignedPayloadCanonical_MatchesJqOutput(t *testing.T) {
	t.Skip("documentation-only: see comment above")
}
