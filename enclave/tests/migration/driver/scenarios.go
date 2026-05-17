package main

import (
	"context"
	"fmt"
	"net/http"
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
	// Roadmap (see ../README.md §"Scenarios to implement"):
	// {Name: "enroll-only",               Run: scenarioEnrollOnly},
	// {Name: "happy-path",                Run: scenarioHappyPath},
	// {Name: "concurrent-load",           Run: scenarioConcurrentLoad},
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
	for _, url := range []string{h.ParentOldURL + "/ready", h.ParentNewURL + "/ready"} {
		if err := waitForReady(ctx, url, 30*time.Second); err != nil {
			return fmt.Errorf("ready check %s: %w", url, err)
		}
	}
	fmt.Println("    parent-old + parent-new /ready 200")

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
