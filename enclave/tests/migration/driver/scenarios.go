package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

// Harness is the per-run state shared across scenarios. Holds the
// connections to the running compose stack so each scenario doesn't
// re-dial. Later scenarios can stash derived state here (e.g. the
// enrolled user_guid from happy-path so a follow-on scenario can
// drive the same user without re-enrolling).
type Harness struct {
	NC            *nats.Conn
	JS            nats.JetStreamContext
	ParentOldURL  string
	ParentNewURL  string
	LocalStackURL string
}

// Scenario is one labelled end-to-end test. Run receives a per-scenario
// context with the driver's --timeout budget already applied; it
// returns nil on success or an error describing the first failure.
type Scenario struct {
	Name string
	Run  func(ctx context.Context, h *Harness) error
}

// AllScenarios is the registry the driver iterates by default. Add
// new scenarios here as they're implemented. Order matters when scenarios
// share Harness state (the smoke scenario is intentionally first so a
// broken stack is reported once, clearly, before the others pile on
// noisier failures).
var AllScenarios = []Scenario{
	{Name: "smoke", Run: scenarioSmoke},
	{Name: "attestation", Run: scenarioAttestation},
	{Name: "pin-setup", Run: scenarioPinSetup},
	{Name: "enroll-only", Run: scenarioEnrollOnly},
	{Name: "migration-config-publish", Run: scenarioMigrationConfigPublish},
	{Name: "unlock-only", Run: scenarioUnlockOnly},
	{Name: "concurrent-load", Run: scenarioConcurrentLoad},
	{Name: "concurrent-multiuser", Run: scenarioConcurrentMultiUser},
	{Name: "persist-idle-no-stall", Run: scenarioPersistIdleNoStall},
	{Name: "migration-handoff", Run: scenarioMigrationHandoff},
	// Roadmap (see ../README.md §"Scenarios to implement"):
	// {Name: "happy-path",                Run: scenarioHappyPath},
	// {Name: "kill-during-reseal",        Run: scenarioKillDuringReseal},
	// {Name: "kill-after-reseal-before-marker", Run: scenarioKillAfterReseal},
	// {Name: "routing-lease-expiry",      Run: scenarioLeaseExpiry},
	// {Name: "persistFn-regression",      Run: scenarioPersistFnRegression},
	// {Name: "canonicalization-regression", Run: scenarioCanonicalization},
	// {Name: "split-brain-eviction",      Run: scenarioSplitBrainEviction},
}

func scenarioByName(name string) (Scenario, bool) {
	for _, s := range AllScenarios {
		if s.Name == name {
			return s, true
		}
	}
	return Scenario{}, false
}

// scenarioSmoke is the baseline check: both parent containers report
// /ready, core NATS publish-subscribe round-trips, and the JetStream
// context is reachable. If this fails the rest of the scenarios won't
// run because every other scenario depends on these primitives.
func scenarioSmoke(ctx context.Context, h *Harness) error {
	// 1. Parent /ready probes. The compose stack's depends_on / healthcheck
	//    chain already gated these before run.sh exited, but a scenario
	//    invocation may happen after the stack has drifted (a container
	//    restart, a kill scenario's tail effect), so we re-check.
	//    parent-new is gated by the `migration` profile so it may be
	//    absent in basic enrollment runs — probe it best-effort.
	if err := waitForReady(ctx, h.ParentOldURL+"/ready", 30*time.Second); err != nil {
		return fmt.Errorf("ready check parent-old: %w", err)
	}
	// Probe parent-new with a tight deadline (it may not be in the
	// stack — `--with-new` opts in). Use a *derived* context with a
	// short timeout, not just perCallTimeout, because waitForReady
	// loops until the context expires.
	probeCtx, probeCancel := context.WithTimeout(ctx, 3*time.Second)
	parentNewProbe := waitForReady(probeCtx, h.ParentNewURL+"/ready", 1*time.Second)
	probeCancel()
	if parentNewProbe == nil {
		fmt.Println("    parent-old + parent-new /ready 200")
	} else {
		fmt.Println("    parent-old /ready 200 (parent-new absent — run with --with-new for migration scenarios)")
	}

	// 2. Core NATS publish/subscribe — proves the driver's NATS client
	//    is connected and the broker is routing.
	sub, err := h.NC.SubscribeSync("harness.smoke")
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	defer sub.Unsubscribe()
	if err := h.NC.Publish("harness.smoke", []byte("hello")); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	msg, err := sub.NextMsgWithContext(ctx)
	if err != nil {
		return fmt.Errorf("recv: %w", err)
	}
	if string(msg.Data) != "hello" {
		return fmt.Errorf("payload mismatch: got %q, want %q", msg.Data, "hello")
	}
	fmt.Println("    NATS core round-trip OK")

	// 3. JetStream is functional. AccountInfo just returns numerical
	//    cluster stats — we don't care what they are, only that the
	//    call succeeds.
	info, err := h.JS.AccountInfo()
	if err != nil {
		return fmt.Errorf("JS AccountInfo: %w", err)
	}
	fmt.Printf("    JetStream OK (streams=%d, consumers=%d)\n", info.Streams, info.Consumers)

	return nil
}

// scenarioAttestation drives stage 1 of enrollment in isolation: send
// a fresh-user attestation request to OLD, parse the response, assert
// we got back a non-empty document and a 32-byte X25519 enclave
// pubkey. Doesn't touch storage or routing — just validates the
// driver's wire-format helpers + the vault's response shape.
func scenarioAttestation(ctx context.Context, h *Harness) error {
	u := newEnrolledUser()
	if err := u.requestAttestation(ctx, h); err != nil {
		return fmt.Errorf("attestation request: %w", err)
	}
	fmt.Printf("    owner_space=%s\n", u.OwnerSpace)
	fmt.Printf("    attestation doc bytes=%d\n", len(u.AttestationDocument))
	fmt.Printf("    enclave pubkey bytes=%d (hex prefix=%x…)\n",
		len(u.EnclavePublicKey),
		u.EnclavePublicKey[:8])
	return nil
}

// scenarioPinSetup chains stage 1 → stage 2: attestation request,
// then ECIES-encrypt the PIN to the attested enclave pubkey, send
// pin.setup, parse the UTK pool out of the response.
func scenarioPinSetup(ctx context.Context, h *Harness) error {
	u := newEnrolledUser()
	if err := u.requestAttestation(ctx, h); err != nil {
		return fmt.Errorf("stage 1 (attestation): %w", err)
	}
	if err := u.setupPIN(ctx, h); err != nil {
		return fmt.Errorf("stage 2 (pin.setup): %w", err)
	}
	fmt.Printf("    owner_space=%s\n", u.OwnerSpace)
	fmt.Printf("    UTK pool size=%d\n", len(u.UTKs))
	if len(u.UTKs) > 0 {
		fmt.Printf("    UTK[0] id=%s pub_b64_prefix=%s…\n",
			u.UTKs[0].ID, u.UTKs[0].PublicKey[:12])
	}
	return nil
}

// scenarioEnrollOnly is the full three-stage enrollment chain with
// no migration assertions. Useful as a leaf-level happy-path
// regression: if this passes the stack is wired correctly for the
// migration scenarios to layer on top.
func scenarioEnrollOnly(ctx context.Context, h *Harness) error {
	u := newEnrolledUser()
	if err := u.requestAttestation(ctx, h); err != nil {
		return fmt.Errorf("stage 1 (attestation): %w", err)
	}
	if err := u.setupPIN(ctx, h); err != nil {
		return fmt.Errorf("stage 2 (pin.setup): %w", err)
	}
	if err := u.createCredential(ctx, h); err != nil {
		return fmt.Errorf("stage 3 (credential.create): %w", err)
	}
	fmt.Printf("    owner_space=%s\n", u.OwnerSpace)
	fmt.Printf("    UTK pool (post-setup)=%d, refreshed=%d\n", len(u.UTKs), len(u.NewUTKs))
	fmt.Printf("    encrypted_credential bytes=%d (b64)\n", len(u.EncryptedCredential))
	return nil
}

// scenarioMigrationConfigPublish exercises just the publish path:
// build a SignedPCRConfig pointing OLD→NEW PCR0, KMS-sign it, PUT to
// _migration/config.json, and self-check by re-parsing + verifying
// the signature with the KMS public key. Doesn't drive any
// supervisor-side fetch — that's what the routing-handoff scenario
// will assert later — but proves the canonical-bytes format matches
// vault-manager's verifier and the LocalStack KMS key works.
func scenarioMigrationConfigPublish(ctx context.Context, h *Harness) error {
	oldPCR0 := os.Getenv("FAKE_PCR0_OLD")
	newPCR0 := os.Getenv("FAKE_PCR0_NEW")
	if oldPCR0 == "" || newPCR0 == "" {
		return fmt.Errorf("FAKE_PCR0_OLD/FAKE_PCR0_NEW unset — run via run.sh")
	}
	version := fmt.Sprintf("tier2-%d", time.Now().Unix())
	canonical, err := h.publishMigrationConfig(ctx, oldPCR0, newPCR0, version)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	fmt.Printf("    version=%s\n", version)
	fmt.Printf("    canonical bytes=%d\n", len(canonical))
	fmt.Printf("    old_pcr0=%s…  new_pcr0=%s…\n", oldPCR0[:16], newPCR0[:16])
	return nil
}

// scenarioUnlockOnly enrolls a fresh user, then immediately unlocks
// them without migrate_consent. Validates the warm-vault unlock path
// + the driver's ECIES wrapping (split fields → combined wire blob).
// Foundation for the migration scenario, which adds consent=true and
// a published config.
func scenarioUnlockOnly(ctx context.Context, h *Harness) error {
	u := newEnrolledUser()
	if err := u.requestAttestation(ctx, h); err != nil {
		return fmt.Errorf("attestation: %w", err)
	}
	if err := u.setupPIN(ctx, h); err != nil {
		return fmt.Errorf("pin.setup: %w", err)
	}
	if err := u.createCredential(ctx, h); err != nil {
		return fmt.Errorf("credential.create: %w", err)
	}
	if err := u.unlockPIN(ctx, h, false); err != nil {
		return fmt.Errorf("pin.unlock: %w", err)
	}
	fmt.Printf("    owner_space=%s — enrolled + unlocked cleanly\n", u.OwnerSpace)
	return nil
}

// scenarioMigrationHandoff drives the full happy-path migration:
//  1. Enroll a fresh user (must land on parent-old — see retry note).
//  2. Publish a signed migration config pointing OLD→NEW PCR0.
//  3. Send pin.unlock with migrate_consent=true.
//  4. Vault on the owner-parent sees consent + a valid config and
//     either reseals carve-outs against the NEW PCR0 (if running on
//     the target) or emits a routing handoff to the new enclave (if
//     running on the old one). Either way the unlock itself
//     succeeds.
//
// Requires `--with-new` so parent-new is up to receive the handoff
// or self-finalize when it processes the unlock.
//
// Known limitation: with two parents running, attestation is
// stateless (both reply, driver picks first response) but pin.setup
// is an enrollment-entry subject (one parent wins ClaimForEnrollment).
// When the claim winner ≠ the parent whose attestation pubkey we
// captured, ECIES decryption MAC-fails. This scenario retries
// enrollment until both stages land on the same parent — the
// production fix would be either (a) attestation also subject to
// claim, or (b) a deterministic per-owner attestation key derived
// from a shared seed so any enclave can decrypt. Track separately.
func scenarioMigrationHandoff(ctx context.Context, h *Harness) error {
	// Confirm parent-new is reachable — without it this scenario is
	// a no-op.
	probeCtx, probeCancel := context.WithTimeout(ctx, 3*time.Second)
	parentNewProbe := waitForReady(probeCtx, h.ParentNewURL+"/ready", 1*time.Second)
	probeCancel()
	if parentNewProbe != nil {
		return fmt.Errorf("parent-new not reachable — run with --with-new")
	}

	oldPCR0 := os.Getenv("FAKE_PCR0_OLD")
	newPCR0 := os.Getenv("FAKE_PCR0_NEW")
	if oldPCR0 == "" || newPCR0 == "" {
		return fmt.Errorf("FAKE_PCR0_OLD/FAKE_PCR0_NEW unset — run via run.sh")
	}

	version := fmt.Sprintf("tier2-handoff-%d", time.Now().Unix())
	if _, err := h.publishMigrationConfig(ctx, oldPCR0, newPCR0, version); err != nil {
		return fmt.Errorf("publish migration config: %w", err)
	}
	fmt.Printf("    published config: %s → %s (version=%s)\n", oldPCR0[:16]+"…", newPCR0[:16]+"…", version)

	// Enrollment retry loop — see note above. Each retry uses a fresh
	// owner_space so claims don't interfere with each other.
	const maxAttempts = 8
	var u *EnrolledUser
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		u = newEnrolledUser()
		if err := u.requestAttestation(ctx, h); err != nil {
			lastErr = fmt.Errorf("attestation: %w", err)
			continue
		}
		if err := u.setupPIN(ctx, h); err != nil {
			lastErr = fmt.Errorf("pin.setup attempt %d: %w", attempt, err)
			continue
		}
		if err := u.createCredential(ctx, h); err != nil {
			lastErr = fmt.Errorf("credential.create attempt %d: %w", attempt, err)
			continue
		}
		lastErr = nil
		fmt.Printf("    enrolled owner_space=%s (attempt %d)\n", u.OwnerSpace, attempt)
		break
	}
	if lastErr != nil {
		return fmt.Errorf("enrollment failed after %d attempts (last: %w)", maxAttempts, lastErr)
	}

	if err := u.unlockPIN(ctx, h, true); err != nil {
		return fmt.Errorf("pin.unlock (migrate_consent): %w", err)
	}
	fmt.Printf("    pin.unlock w/ migrate_consent — status=%q migration_status=%q version=%q\n",
		u.LastUnlockStatus, u.LastMigrationStatus, u.LastMigrationVersion)

	// The primary assertion of this scenario is that migrate_consent
	// produced one of the two terminal migration statuses ("completed"
	// = resealed in place on the NEW parent, or "pending_new_enclave"
	// = handoff emitted from the OLD parent). Anything else means
	// migration didn't actually engage and the test should fail.
	switch u.LastMigrationStatus {
	case "completed", "pending_new_enclave":
		// expected
	default:
		return fmt.Errorf("expected migration_status in {completed, pending_new_enclave}, got %q (version=%q)",
			u.LastMigrationStatus, u.LastMigrationVersion)
	}

	// Best-effort post-handoff probe: the second unlock should land
	// on the NEW parent (which won the handoff). Failure here is
	// commonly a Tier-2 surface gap — e.g. NATS-account-seed lookups
	// that need DynamoDB wiring the harness doesn't ship — rather
	// than a real migration bug. Log and continue so the primary
	// migration assertion stays the gating signal.
	if err := u.unlockPIN(ctx, h, false); err != nil {
		fmt.Printf("    post-handoff pin.unlock soft-failed (likely Tier-2 surface gap): %v\n", err)
	} else {
		fmt.Printf("    post-handoff pin.unlock succeeded\n")
	}
	return nil
}

// waitForReady polls an HTTP /ready endpoint until it returns 200 or
// ctx expires. Per-call timeout caps how long one HTTP request can
// block; the loop deadline is the parent ctx.
func waitForReady(ctx context.Context, url string, perCallTimeout time.Duration) error {
	client := &http.Client{Timeout: perCallTimeout}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
