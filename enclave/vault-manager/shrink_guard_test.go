package main

// Regression tests for the persistVaultStateToS3 shrink guard.
//
// History: two data-loss incidents on 2026-05-06 and 2026-05-09 had
// the same shape — an enclave instance whose in-memory storage was
// incomplete for a given user persisted a ~12 KB encrypted stub on
// top of a healthy ~220 KB S3 vault_state.enc, silently destroying
// the user's vault data.
//
// The architect's storage-invariants doc (§3) calls for a guard:
// refuse the write when an existing object >= 50 KB would shrink to
// < 50% of its size. shouldRefuseShrink encodes that policy; this
// test pins the threshold so a future change can't accidentally
// loosen it.

import "testing"

func TestShouldRefuseShrink(t *testing.T) {
	const KB = int64(1024)
	cases := []struct {
		name     string
		prevSize int64
		newSize  int64
		refuse   bool
	}{
		// The incident shape.
		{"220KB → 12KB (incident shape, must refuse)", 220 * KB, 12 * KB, true},
		// Threshold edge cases.
		{"50KB → 24KB (exactly at floor, below half — refuse)", 50 * KB, 24 * KB, true},
		{"50KB → 25KB (at floor, at exactly half — allow)", 50 * KB, 25 * KB, false},
		{"49KB → 1KB (just under floor — allow, too small to matter)", 49 * KB, 1 * KB, false},
		// Legitimate edits within tolerance.
		{"100KB → 80KB (20% trim — allow)", 100 * KB, 80 * KB, false},
		{"100KB → 60KB (40% trim — allow)", 100 * KB, 60 * KB, false},
		{"100KB → 51KB (just over half — allow)", 100 * KB, 51 * KB, false},
		// Growth and no-op writes.
		{"100KB → 100KB (same size — allow)", 100 * KB, 100 * KB, false},
		{"100KB → 200KB (growth — allow)", 100 * KB, 200 * KB, false},
		// No prior reference (fresh enrollment, first write).
		{"prev=0 → 12KB (no reference, allow)", 0, 12 * KB, false},
		{"prev=0 → 0 (no reference and empty, allow — caller decides separately)", 0, 0, false},
		// Pathological inputs.
		{"prev<0 (corrupt) → 12KB (allow — guard not triggered)", -1, 12 * KB, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldRefuseShrink(tc.prevSize, tc.newSize)
			if got != tc.refuse {
				t.Errorf("shouldRefuseShrink(%d, %d) = %v, want %v",
					tc.prevSize, tc.newSize, got, tc.refuse)
			}
		})
	}
}
