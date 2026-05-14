package main

// Regression test for the DEK-divergence migration corruption
// (2026-05-14).
//
// Symptom: after an enclave migration, one user's vault cold-loaded
// with "backup HMAC verification failed" and came up empty. Root
// cause: a "cold" vault (ECIES not in memory) could still carry an
// s.sqlite from an earlier lifecycle of the same subprocess, keyed
// with a now-stale DEK. InitializeWithDEK is idempotent — it kept
// that stale storage — so the cold-load's RestoreBackup HMAC-checked
// against the wrong key and every restored row payload was
// undecryptable.
//
// Fix: the cold-unlock path uses ResetWithDEK, which discards a
// stale-keyed storage and re-creates fresh; the warm path keeps the
// idempotent InitializeWithDEK (which now no-ops only when the DEK
// actually matches).

import (
	"bytes"
	"testing"
)

func dek32(b byte) []byte {
	d := make([]byte, 32)
	for i := range d {
		d[i] = b
	}
	return d
}

func TestInitializeWithDEK_IdempotentOnlyOnMatchingDEK(t *testing.T) {
	es, err := NewEncryptedStorage("user-dektest")
	if err != nil {
		t.Fatalf("NewEncryptedStorage: %v", err)
	}
	dekA := dek32(0xA1)

	if err := es.InitializeWithDEK(dekA); err != nil {
		t.Fatalf("first InitializeWithDEK: %v", err)
	}
	if err := es.Put("k", []byte("v-original")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Same DEK → idempotent no-op, data preserved (the warm-unlock case).
	if err := es.InitializeWithDEK(dekA); err != nil {
		t.Fatalf("second InitializeWithDEK (same dek): %v", err)
	}
	got, err := es.Get("k")
	if err != nil || !bytes.Equal(got, []byte("v-original")) {
		t.Fatalf("data should survive a same-DEK re-init: got %q err %v", got, err)
	}

	// Different DEK → still a no-op (idempotent), and it must NOT
	// silently adopt the new DEK: the existing storage stays keyed to
	// dekA. This is the dangerous case the warn logs, and exactly why
	// cold unlocks must use ResetWithDEK instead.
	dekB := dek32(0xB2)
	if err := es.InitializeWithDEK(dekB); err != nil {
		t.Fatalf("third InitializeWithDEK (different dek): %v", err)
	}
	if !es.sqlite.DEKEquals(dekA) {
		t.Error("InitializeWithDEK must keep the original DEK, not adopt the mismatched one")
	}
	if es.sqlite.DEKEquals(dekB) {
		t.Error("InitializeWithDEK must NOT have re-keyed to the mismatched DEK")
	}
}

func TestResetWithDEK_DiscardsStaleKeyedStorage(t *testing.T) {
	es, err := NewEncryptedStorage("user-resettest")
	if err != nil {
		t.Fatalf("NewEncryptedStorage: %v", err)
	}
	dekA := dek32(0xA1)
	dekB := dek32(0xB2)

	if err := es.InitializeWithDEK(dekA); err != nil {
		t.Fatalf("InitializeWithDEK: %v", err)
	}
	if err := es.Put("k", []byte("stale-keyed")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Cold unlock with a different (freshly-derived) DEK: ResetWithDEK
	// must discard the stale-keyed storage and re-create fresh, keyed
	// to dekB. The stale row is gone (correct — it was unrecoverable
	// under dekB anyway; the cold-load's RestoreBackup rebuilds from
	// the S3 backup).
	if err := es.ResetWithDEK(dekB); err != nil {
		t.Fatalf("ResetWithDEK: %v", err)
	}
	if !es.sqlite.DEKEquals(dekB) {
		t.Fatal("ResetWithDEK must leave storage keyed to the new DEK")
	}
	if got, _ := es.Get("k"); got != nil {
		t.Errorf("ResetWithDEK must discard stale-keyed rows, got %q", got)
	}

	// Fresh storage under dekB works end-to-end.
	if err := es.Put("k2", []byte("fresh")); err != nil {
		t.Fatalf("Put after reset: %v", err)
	}
	if got, err := es.Get("k2"); err != nil || !bytes.Equal(got, []byte("fresh")) {
		t.Fatalf("post-reset round-trip failed: got %q err %v", got, err)
	}
}

func TestSetEntrySigner_SurvivesLazyStorageCreation(t *testing.T) {
	// Regression for the "chain unsigned" bug (2026-05-14): the audit
	// signer is registered at MessageHandler-init time, but on a
	// fresh-spawned subprocess the SQLite doesn't exist yet — it's
	// created lazily by InitializeWithDEK / ResetWithDEK. The signer
	// must be owned by EncryptedStorage and re-applied to every
	// SQLiteStorage it creates, or every audit row writes unsigned.
	es, err := NewEncryptedStorage("user-signertest")
	if err != nil {
		t.Fatalf("NewEncryptedStorage: %v", err)
	}

	called := false
	signer := func(b []byte) []byte { called = true; return []byte("sig") }

	// Register BEFORE any SQLite exists — the realistic ordering.
	es.SetEntrySigner(signer)
	if es.sqlite != nil {
		t.Fatal("precondition: SQLite should not exist yet")
	}

	// InitializeWithDEK creates the SQLite — the signer must be on it.
	if err := es.InitializeWithDEK(dek32(0xC3)); err != nil {
		t.Fatalf("InitializeWithDEK: %v", err)
	}
	if !es.sqlite.HasEntrySigner() {
		t.Fatal("InitializeWithDEK must re-apply the EncryptedStorage entrySigner to the new SQLite")
	}

	// ResetWithDEK re-creates the SQLite — the signer must follow.
	if err := es.ResetWithDEK(dek32(0xD4)); err != nil {
		t.Fatalf("ResetWithDEK: %v", err)
	}
	if !es.sqlite.HasEntrySigner() {
		t.Fatal("ResetWithDEK must re-apply the entrySigner to the fresh SQLite")
	}

	// Registering again after the SQLite already exists also applies
	// straight through (the warm-vault path).
	called = false
	es.SetEntrySigner(signer)
	es.sqlite.InvokeEntrySignerForTest([]byte("hash"))
	if !called {
		t.Error("SetEntrySigner on an already-created SQLite should apply the closure through")
	}
}

func TestResetWithDEK_NoOpWhenAlreadyCorrectlyKeyed(t *testing.T) {
	es, err := NewEncryptedStorage("user-resetnoop")
	if err != nil {
		t.Fatalf("NewEncryptedStorage: %v", err)
	}
	dekA := dek32(0xA1)

	if err := es.ResetWithDEK(dekA); err != nil {
		t.Fatalf("first ResetWithDEK: %v", err)
	}
	if err := es.Put("k", []byte("keep-me")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Re-reset with the SAME dek (e.g. a retried cold unlock) must not
	// blow away storage that's already fresh-and-correct.
	if err := es.ResetWithDEK(dekA); err != nil {
		t.Fatalf("second ResetWithDEK (same dek): %v", err)
	}
	if got, err := es.Get("k"); err != nil || !bytes.Equal(got, []byte("keep-me")) {
		t.Fatalf("same-DEK ResetWithDEK must preserve data: got %q err %v", got, err)
	}
}
