package main

// Tier-1 tests for MigrationHandler's resealMaterial path + the
// fetchAndVerifyMigrationConfig chokepoint.
//
// What we pin here:
//   - fetchAndVerifyMigrationConfig short-circuits with nil/nil when
//     S3 has no config (the "no migration in flight" case). No KMS
//     fetch happens because there's nothing to verify.
//   - fetchAndVerifyMigrationConfig propagates the signing-key fetch
//     failure as an error (the 2026-05-11 incident shape — vault saw
//     "PCR signing key ARN not configured" because parent.yaml was
//     missing the wiring).
//   - resealMaterial is idempotent: if the stored wrapper's
//     SealedToPCR0 already matches the running PCR0, it returns nil
//     without burning KMS quota on a no-op re-seal.
//
// What we DON'T cover here (and why): the full happy path for
// resealMaterial requires real KMS Encrypt + a valid sealed_material
// wrapper. Those are covered by Tier-2 Docker-pair tests (task #131).
// This file's job is the input-validation + idempotency surface that
// can be exercised without a real KMS.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// stubMigrationSealer is a hand-written mock of MigrationSealer. Each
// field is the response a method returns; nil-valued errors mean
// success. Counters track call counts so tests can assert e.g.
// "WriteMigrationMarker was called exactly once with version X."
type stubMigrationSealer struct {
	fetchConfigData       []byte
	fetchConfigErr        error
	fetchPubKeyData       []byte
	fetchPubKeyErr        error
	runningPCR0           string
	runningPCR0Err        error
	loadMaterialData      []byte
	loadMaterialErr       error
	unsealMaterialData    []byte
	unsealMaterialErr     error
	sealCredentialData    []byte
	sealCredentialErr     error
	storeMaterialErr      error
	loadECIESData         []byte
	loadECIESErr          error
	unsealCredentialData  []byte
	unsealCredentialErr   error
	storeECIESErr         error
	writeMarkerErr        error

	storeMaterialCalls int
	storeECIESCalls    int
	writeMarkerCalls   int
	lastMarkerVersion  string
	lastSealCredArg    []byte
	lastStoreMatArg    []byte
}

func (s *stubMigrationSealer) FetchMigrationConfig() ([]byte, error) {
	return s.fetchConfigData, s.fetchConfigErr
}
func (s *stubMigrationSealer) FetchPCRSigningPublicKey() ([]byte, error) {
	return s.fetchPubKeyData, s.fetchPubKeyErr
}
func (s *stubMigrationSealer) GetRunningPCR0() (string, error) {
	return s.runningPCR0, s.runningPCR0Err
}
func (s *stubMigrationSealer) LoadSealedMaterial() ([]byte, error) {
	return s.loadMaterialData, s.loadMaterialErr
}
func (s *stubMigrationSealer) UnsealMaterial(b []byte) ([]byte, error) {
	return s.unsealMaterialData, s.unsealMaterialErr
}
func (s *stubMigrationSealer) SealCredential(data []byte) ([]byte, error) {
	s.lastSealCredArg = append([]byte(nil), data...)
	return s.sealCredentialData, s.sealCredentialErr
}
func (s *stubMigrationSealer) StoreSealedMaterial(b []byte) error {
	s.storeMaterialCalls++
	s.lastStoreMatArg = append([]byte(nil), b...)
	return s.storeMaterialErr
}
func (s *stubMigrationSealer) LoadSealedECIES() ([]byte, error) {
	return s.loadECIESData, s.loadECIESErr
}
func (s *stubMigrationSealer) UnsealCredential(b []byte) ([]byte, error) {
	return s.unsealCredentialData, s.unsealCredentialErr
}
func (s *stubMigrationSealer) StoreSealedECIES(b []byte) error {
	s.storeECIESCalls++
	return s.storeECIESErr
}
func (s *stubMigrationSealer) WriteMigrationMarker(version string) error {
	s.writeMarkerCalls++
	s.lastMarkerVersion = version
	return s.writeMarkerErr
}

func newTestMigrationHandler(t *testing.T, sealer MigrationSealer) *MigrationHandler {
	t.Helper()
	return &MigrationHandler{
		ownerSpace:  "test-owner-1",
		sealerProxy: sealer,
	}
}

func TestFetchAndVerifyMigrationConfig_NoConfig(t *testing.T) {
	// fetchConfigData=nil + fetchConfigErr=nil mimics S3 returning
	// "no such key". Should short-circuit nil/nil without ever
	// touching the signing-key fetch.
	sealer := &stubMigrationSealer{
		fetchConfigErr: nil,
		fetchConfigData: nil,
		// Wire pub key fetch to FAIL — if it gets called, that's a bug.
		fetchPubKeyErr: errors.New("MUST NOT BE CALLED"),
	}
	h := newTestMigrationHandler(t, sealer)
	cfg, der, err := h.fetchAndVerifyMigrationConfig()
	if err != nil {
		t.Fatalf("expected nil err on empty config, got %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil cfg, got %+v", cfg)
	}
	if der != nil {
		t.Errorf("expected nil DER, got len=%d", len(der))
	}
}

func TestFetchAndVerifyMigrationConfig_FetchPubKeyError(t *testing.T) {
	// This is the 2026-05-11 incident shape: config IS in S3, but the
	// parent's pcr_signing_key_arn config was missing so the supervisor
	// returns "PCR signing key ARN not configured" from
	// FetchPCRSigningPublicKey. Verifier must propagate the error
	// rather than treat as "no config".
	sealer := &stubMigrationSealer{
		fetchConfigData: []byte(`{"version":"test-v1","new_pcrs":{"pcr0":"01","pcr1":"02","pcr2":"03"},"old_pcrs":{"pcr0":"aa","pcr1":"bb","pcr2":"cc"},"valid_from":"2026-05-11T00:00:00Z","signature":""}`),
		fetchPubKeyErr:  errors.New("PCR signing key ARN not configured"),
	}
	h := newTestMigrationHandler(t, sealer)
	cfg, _, err := h.fetchAndVerifyMigrationConfig()
	if err == nil {
		t.Fatal("expected error when pub key fetch fails")
	}
	if cfg != nil {
		t.Errorf("expected nil cfg on verify failure, got %+v", cfg)
	}
}

func TestResealMaterial_Idempotent(t *testing.T) {
	// The architect's F5 self-heal recovery case: a previous unlock
	// completed re-seal but the marker write failed. The next unlock
	// reads the existing sealed_material.bin, sees its SealedToPCR0
	// already equals the running PCR0, and resealMaterial returns nil
	// without doing any KMS Unseal/Seal or storage write. The caller
	// then re-attempts the marker write idempotently.
	//
	// We construct a sealed_material.bin wrapper whose SealedToPCR0
	// matches the (faked) running PCR0 and assert: zero StoreSealed,
	// zero SealCredential calls.
	const newPCR0 = "5a03197e230bca733dee451f"
	wrapper := struct {
		Version          int    `json:"version"`
		SealedMaterial   string `json:"sealed_material"`
		OwnerID          string `json:"owner_id"`
		CreatedAt        int64  `json:"created_at"`
		Generation       int    `json:"generation"`
		SealedToPCR0     string `json:"sealed_to_pcr0"`
		SealedToVersion  string `json:"sealed_to_version"`
	}{
		Version:         1,
		SealedMaterial:  "dGVzdA==", // arbitrary; resealMaterial doesn't decrypt on idempotent branch
		OwnerID:         "test-owner-1",
		CreatedAt:       1700000000,
		Generation:      7,
		SealedToPCR0:    newPCR0,
		SealedToVersion: "2026-05-11-v1",
	}
	wrapperBytes := mustMarshalForTest(t, wrapper)

	sealer := &stubMigrationSealer{
		runningPCR0:     newPCR0,
		loadMaterialData: wrapperBytes,
	}
	h := newTestMigrationHandler(t, sealer)
	if err := h.resealMaterial(context.Background(), "2026-05-11-v2"); err != nil {
		t.Fatalf("expected nil err on idempotent re-seal, got %v", err)
	}
	if sealer.storeMaterialCalls != 0 {
		t.Errorf("expected 0 StoreSealedMaterial calls (idempotent), got %d", sealer.storeMaterialCalls)
	}
	if sealer.lastSealCredArg != nil {
		t.Errorf("expected SealCredential never called (idempotent), but got call with %d bytes", len(sealer.lastSealCredArg))
	}
}

// mustMarshalForTest wraps json.Marshal and fails the test on error.
// Different name from mustMarshalJSON in combined_datastore.go.
func mustMarshalForTest(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// Ensure interface conformance at compile time.
var _ MigrationSealer = (*stubMigrationSealer)(nil)
