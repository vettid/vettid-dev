package main

// Concurrency / load scenario — the oracle for the vsock-multiplex work.
//
// Every other scenario drives ONE op at a time, so none of them
// exercise concurrent in-flight requests through the
// parent↔supervisor↔vault-manager chain. The production wedge on
// 2026-05-19 was exactly that: a multiplexer that mis-correlated
// concurrent responses. This scenario reproduces the load pattern —
// fire N read ops in parallel against one warm vault — and asserts
// every response comes back AND lands on the right request.
//
// Pass criteria (correctness — independent of whether the transport
// is serial or multiplexed):
//   - every concurrent op gets a response within the budget
//     (a vsock wedge shows up here as timeouts)
//   - each response's request_type matches the op that was sent
//     (a mis-correlated multiplexer shows up here as a mismatch)
//
// The serial transport passes this too — just slower. That's the
// point: the scenario is a correctness gate the multiplex must keep
// green, and the wall-clock line shows whether the multiplex
// actually bought any parallelism.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// concurrentReadOps is the set of independent, idempotent read ops
// fired in parallel. All are safe on a freshly-enrolled+unlocked
// user (they return empty/minimal data, never mutate, never need
// phone approval). All were observed routing cleanly in production
// parent logs. Mixing distinct op types is deliberate: a
// mis-correlated response (op A's reply delivered to op B's
// subject) is caught by the per-op request_type assertion.
var concurrentReadOps = []string{
	"personal-data.get",
	"wallet.list",
	"secret.list",
	"profile.categories.get",
	"profile.get-published",
	"connection.list",
}

// concurrentRounds is how many times the op set is fired. Total
// in-flight ops = rounds × len(concurrentReadOps). 4×6 = 24 — enough
// to overflow any single-op assumption without making the harness
// run slow.
const concurrentRounds = 4

// opResult is one concurrent op's outcome, collected for reporting.
type opResult struct {
	op       string
	round    int
	err      error
	latency  time.Duration
	gotType  string // request_type echoed in the response
}

// scenarioConcurrentLoad enrolls one user, unlocks them, then fires
// concurrentRounds × len(concurrentReadOps) read ops simultaneously
// and verifies every one returns correctly.
func scenarioConcurrentLoad(ctx context.Context, h *Harness) error {
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
	fmt.Printf("    owner_space=%s — enrolled + unlocked, firing %d concurrent ops\n",
		u.OwnerSpace, concurrentRounds*len(concurrentReadOps))

	// Launch every op as a goroutine, all at once. Each waits on its
	// own correlated NATS response subject (publishAndAwait embeds a
	// unique event_id), so driver-side correlation is never the
	// variable — only the parent↔supervisor transport is.
	results := make([]opResult, 0, concurrentRounds*len(concurrentReadOps))
	var mu sync.Mutex
	var wg sync.WaitGroup

	start := time.Now()
	for round := 0; round < concurrentRounds; round++ {
		for _, op := range concurrentReadOps {
			wg.Add(1)
			go func(op string, round int) {
				defer wg.Done()
				opStart := time.Now()
				respBytes, err := h.publishAndAwait(ctx, u.OwnerSpace, op, map[string]any{})
				res := opResult{op: op, round: round, latency: time.Since(opStart)}
				if err != nil {
					res.err = err
				} else {
					res.gotType, res.err = checkResponse(op, respBytes)
				}
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			}(op, round)
		}
	}
	wg.Wait()
	elapsed := time.Since(start)

	// Tally. Any error (timeout = wedge, type mismatch = mis-correlation)
	// fails the scenario.
	var failures []string
	var slowest time.Duration
	for _, r := range results {
		if r.latency > slowest {
			slowest = r.latency
		}
		if r.err != nil {
			failures = append(failures,
				fmt.Sprintf("[round %d] %s: %v", r.round, r.op, r.err))
		}
	}

	fmt.Printf("    %d ops, wall-clock=%s, slowest single op=%s\n",
		len(results), elapsed.Round(time.Millisecond), slowest.Round(time.Millisecond))

	if len(failures) > 0 {
		// Cap the list so a total wedge doesn't print 24 identical lines.
		shown := failures
		if len(shown) > 6 {
			shown = shown[:6]
		}
		for _, f := range shown {
			fmt.Printf("    FAIL %s\n", f)
		}
		return fmt.Errorf("%d/%d concurrent ops failed", len(failures), len(results))
	}
	return nil
}

// concurrentUsers is how many distinct users the multi-user
// scenario enrolls. The supervisor-concurrency win only appears
// ACROSS users — each user has one single-threaded vault-manager
// subprocess, so one user's ops serialize no matter what. With K
// users and a serial supervisor, total ≈ K × opsPerUser × latency;
// with a concurrent supervisor it drops toward opsPerUser × latency.
const concurrentUsers = 4

// scenarioConcurrentMultiUser is the throughput oracle for the
// vsock-multiplex work. It enrolls concurrentUsers users, then fires
// the read-op set for every user simultaneously and reports
// wall-clock. Run it with HARNESS_OP_LATENCY_MS set (e.g. 50) so the
// serial-vs-concurrent gap is measurable:
//
//	serial supervisor:     ≈ users × ops × latency
//	concurrent supervisor: ≈ ops × latency   (users run in parallel)
//
// Correctness criteria are identical to concurrent-load: every op
// must return, and request_type must match. The wall-clock line is
// the perf signal — a green run with no speedup means the multiplex
// didn't actually parallelize across users.
func scenarioConcurrentMultiUser(ctx context.Context, h *Harness) error {
	users := make([]*EnrolledUser, 0, concurrentUsers)
	for i := 0; i < concurrentUsers; i++ {
		u := newEnrolledUser()
		if err := u.requestAttestation(ctx, h); err != nil {
			return fmt.Errorf("user %d attestation: %w", i, err)
		}
		if err := u.setupPIN(ctx, h); err != nil {
			return fmt.Errorf("user %d pin.setup: %w", i, err)
		}
		if err := u.createCredential(ctx, h); err != nil {
			return fmt.Errorf("user %d credential.create: %w", i, err)
		}
		if err := u.unlockPIN(ctx, h, false); err != nil {
			return fmt.Errorf("user %d pin.unlock: %w", i, err)
		}
		users = append(users, u)
	}
	total := len(users) * len(concurrentReadOps)
	fmt.Printf("    enrolled %d users — firing %d concurrent ops (%d ops × %d users)\n",
		len(users), total, len(concurrentReadOps), len(users))

	results := make([]opResult, 0, total)
	var mu sync.Mutex
	var wg sync.WaitGroup

	start := time.Now()
	for _, u := range users {
		for _, op := range concurrentReadOps {
			wg.Add(1)
			go func(ownerSpace, op string) {
				defer wg.Done()
				opStart := time.Now()
				respBytes, err := h.publishAndAwait(ctx, ownerSpace, op, map[string]any{})
				res := opResult{op: op, latency: time.Since(opStart)}
				if err != nil {
					res.err = err
				} else {
					res.gotType, res.err = checkResponse(op, respBytes)
				}
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			}(u.OwnerSpace, op)
		}
	}
	wg.Wait()
	elapsed := time.Since(start)

	var failures []string
	var slowest time.Duration
	for _, r := range results {
		if r.latency > slowest {
			slowest = r.latency
		}
		if r.err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", r.op, r.err))
		}
	}
	fmt.Printf("    %d ops, wall-clock=%s, slowest single op=%s\n",
		len(results), elapsed.Round(time.Millisecond), slowest.Round(time.Millisecond))

	if len(failures) > 0 {
		shown := failures
		if len(shown) > 6 {
			shown = shown[:6]
		}
		for _, f := range shown {
			fmt.Printf("    FAIL %s\n", f)
		}
		return fmt.Errorf("%d/%d concurrent ops failed", len(failures), len(results))
	}
	return nil
}

// checkResponse validates one op's response: it must not carry an
// error field, and its request_type must match the op that was sent.
// A mismatch means the transport delivered the wrong vault response
// to this request's subject — the mis-correlation bug. Returns the
// observed request_type for the caller's report.
func checkResponse(op string, respBytes []byte) (string, error) {
	var resp struct {
		RequestType string `json:"request_type"`
		Error       string `json:"error"`
		Type        string `json:"type"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return "", fmt.Errorf("unmarshal response: %w (raw=%.120s)", err, string(respBytes))
	}
	if resp.Error != "" {
		return resp.RequestType, fmt.Errorf("vault error: %s", resp.Error)
	}
	// request_type is the parent's echo of the originating op. When
	// present it must match; an empty value (some ops don't stamp it)
	// is tolerated — the correctness signal there is just "got a
	// non-error response on my own correlated subject".
	if resp.RequestType != "" && resp.RequestType != op {
		return resp.RequestType,
			fmt.Errorf("response cross-delivered: sent %q, got request_type %q", op, resp.RequestType)
	}
	return resp.RequestType, nil
}
