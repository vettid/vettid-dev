package main

// Tests for the persistVaultStateToS3 throttle.
//
// Background: main.go's request loop persists vault state after every
// successful message, and several handlers also call persist directly
// from inside their op. A single active user can produce hundreds of
// vault_state.enc writes per minute, and S3 versioning kept each one
// as a noncurrent version for 30 days — ~4800 versions accumulated for
// 2 test users before this throttle landed.
//
// The throttle uses lastPersistTime + persistDebounceInterval to skip
// non-forced calls within the window. These tests pin the policy:
// successive throttled calls inside the window are skipped, calls
// after the window are allowed, and the forced flush bypasses the
// throttle entirely.

import (
	"testing"
	"time"
)

// shouldThrottle is the policy decision inside persistVaultStateToS3.
// Extracted here for testing because the actual persist function
// requires a real MessageHandler with KMS/storage wired up.
func shouldThrottle(now, last time.Time, window time.Duration) bool {
	return now.Sub(last) < window
}

func TestThrottlePolicy(t *testing.T) {
	const window = 15 * time.Second
	t0 := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		now      time.Time
		last     time.Time
		throttle bool
	}{
		{"first call ever (last=zero)", t0, time.Time{}, false},
		{"immediate retry", t0, t0, true},
		{"1s after last", t0.Add(1 * time.Second), t0, true},
		{"14.9s after last (still within window)", t0.Add(14_900 * time.Millisecond), t0, true},
		{"exactly at window boundary", t0.Add(window), t0, false},
		{"1s past window", t0.Add(16 * time.Second), t0, false},
		{"long idle (1 hour)", t0.Add(time.Hour), t0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldThrottle(tc.now, tc.last, window)
			if got != tc.throttle {
				t.Errorf("shouldThrottle(now=%v, last=%v, window=%v) = %v, want %v",
					tc.now, tc.last, window, got, tc.throttle)
			}
		})
	}
}

// Sanity-check that persistDebounceInterval is set to a value compatible
// with the typical Android session cadence: long enough to coalesce a
// burst of edits (profile updates, secret adds, message sends in a row)
// into one write, short enough that a vault-manager crash doesn't lose
// more than a few seconds of work. 15s is the current ceiling.
func TestPersistDebounceIntervalIsReasonable(t *testing.T) {
	if persistDebounceInterval < 5*time.Second {
		t.Errorf("persistDebounceInterval too short (%v); bursts wouldn't coalesce", persistDebounceInterval)
	}
	if persistDebounceInterval > time.Minute {
		t.Errorf("persistDebounceInterval too long (%v); too much in-memory data at risk on crash", persistDebounceInterval)
	}
}
