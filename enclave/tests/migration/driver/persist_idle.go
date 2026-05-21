package main

// Regression guard for the supervisor always-drain refactor
// (docs/SUPERVISOR-ALWAYS-DRAIN-PLAN.md).
//
// The wedge it guards against: the vault-manager emits a
// store_vault_state persist (~1MB sealer request) on the subprocess
// pipe. Before the always-drain refactor the supervisor read that
// pipe only while inside a ProcessMessage call, so a persist emitted
// between ops sat unserviced until its 30s sealer-proxy timeout,
// stalling the single-threaded op loop. The fix is a persistent
// per-VaultProcess reader goroutine that always drains the pipe.
//
// Every other scenario fires ops back-to-back, so a ProcessMessage is
// essentially always reading and the wedge never surfaces. This
// scenario reproduces the trigger directly: enroll + unlock a user,
// then run several op->idle cycles where each idle exceeds the
// vault-manager's persistDebounceInterval. The op after each gap
// triggers a real persist with no other op holding a read window
// open. With the always-drain reader every such op completes in well
// under a second; a regression shows up as an op latency spike toward
// 30s.

import (
	"context"
	"fmt"
	"time"
)

// persistIdleGap must exceed the vault-manager's persistDebounceInterval
// (15s) so the op after the gap triggers a real store_vault_state
// flush rather than a debounced no-op.
const persistIdleGap = 17 * time.Second

// persistIdleRounds is how many idle->op cycles to run.
const persistIdleRounds = 3

// opStallBudget is the per-op latency ceiling. A healthy op is well
// under a second; the wedge this scenario guards against was a
// 25-30s stall. 10s sits far above any legitimate op — including a
// real store_vault_state round-trip through LocalStack — and far
// below the wedge.
const opStallBudget = 10 * time.Second

// scenarioPersistIdleNoStall asserts that an op fired after an idle
// period long enough to make its persist a real flush still completes
// promptly — i.e. the always-drain pipe reader services the
// between-ops persist instead of letting it stall the op loop.
func scenarioPersistIdleNoStall(ctx context.Context, h *Harness) error {
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
	fmt.Printf("    owner_space=%s — enrolled + unlocked; %d op→idle cycles, %s idle each\n",
		u.OwnerSpace, persistIdleRounds, persistIdleGap)

	const op = "connection.list"
	var worst time.Duration
	for round := 1; round <= persistIdleRounds; round++ {
		// Idle past the persist-debounce window: the next op's persist
		// is then a real flush, and no other op is holding a supervisor
		// read window open — exactly the condition that wedged before
		// the always-drain reader.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(persistIdleGap):
		}

		opStart := time.Now()
		respBytes, err := h.publishAndAwait(ctx, u.OwnerSpace, op, map[string]any{})
		latency := time.Since(opStart)
		if latency > worst {
			worst = latency
		}
		if err != nil {
			return fmt.Errorf("round %d: %s after %s idle: %w", round, op, persistIdleGap, err)
		}
		if _, err := checkResponse(op, respBytes); err != nil {
			return fmt.Errorf("round %d: %s response: %w", round, op, err)
		}
		fmt.Printf("    round %d: %s after %s idle — %s\n",
			round, op, persistIdleGap, latency.Round(time.Millisecond))
		if latency > opStallBudget {
			return fmt.Errorf("round %d: %s took %s (budget %s) — persist-wedge regression: "+
				"an op after an idle stalled, the always-drain reader is not servicing the between-ops persist",
				round, op, latency.Round(time.Millisecond), opStallBudget)
		}
	}
	fmt.Printf("    no stall — worst op latency %s (budget %s)\n",
		worst.Round(time.Millisecond), opStallBudget)
	return nil
}
