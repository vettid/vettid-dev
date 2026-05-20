//go:build testharness

package main

import (
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// SECURITY: compiled only with `-tags testharness`. The production
// vettid-supervisor binary never includes this file, never reads
// HARNESS_OP_LATENCY_MS, and harnessOpLatency stays the no-op from
// harness_hooks.go.
//
// When the env var is a positive integer, every vault op sleeps that
// many milliseconds inside handleVaultOp — simulating the S3/KMS
// round-trip latency LocalStack doesn't have, so the Tier-2
// concurrent-load scenario can measure serial-vs-concurrent
// throughput.
func init() {
	raw := os.Getenv("HARNESS_OP_LATENCY_MS")
	if raw == "" {
		return
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		log.Warn().Str("value", raw).Msg("testharness: HARNESS_OP_LATENCY_MS invalid — ignoring")
		return
	}
	d := time.Duration(ms) * time.Millisecond
	harnessOpLatency = func() { time.Sleep(d) }
	log.Info().Int("latency_ms", ms).Msg("testharness: per-op latency injection enabled")
}
