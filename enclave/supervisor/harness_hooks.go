package main

// Harness instrumentation hooks. Production builds compile this file
// and get the no-op defaults; the Tier-2 test harness build
// (`-tags testharness`) overrides them in harness_hooks_testharness.go.
//
// harnessOpLatency is invoked once per vault op at the top of
// handleVaultOp. In production it does nothing. Under the harness it
// sleeps a configurable amount (HARNESS_OP_LATENCY_MS), simulating
// the real S3/KMS round-trip cost that LocalStack — being local and
// near-zero-latency — does not reproduce. Without injected latency
// the concurrent-load scenario can't tell a serial transport from a
// concurrent one: 24 ops complete in ~20ms either way. With it, a
// serial supervisor shows N×latency and a concurrent one shows
// roughly latency, making the throughput change measurable.
var harnessOpLatency = func() {}
