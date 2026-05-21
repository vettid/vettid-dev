package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// This file adds a supervisor-side stall watchdog. It exists because the
// supervisor was a journal blind spot: a vault op that stalls *before*
// it reaches the vault-manager subprocess (waiting on a per-user procMu,
// a slow GetOrCreate spawn, a wedged ProcessMessage) is invisible to the
// in-subprocess watchdog in vault-manager/main.go — that one only times
// in-op execution. The 2026-05-21 ~30s device-approval stall was traced
// to exactly this gap.
//
// The watchdog tracks every in-flight handleVaultOp; if one runs longer
// than supervisorOpStallThreshold it dumps EVERY supervisor goroutine
// stack, routed through Supervisor.SendLog so it lands in the parent
// journal (the supervisor's ordinary zerolog goes only to the enclave
// console). The dump shows precisely what each ProcessMessage goroutine
// is blocked on — procMu.Lock, the respCh select, a pipe write.
//
// Keep the watchdog past tech-preview (cheap, good hygiene); only the
// threshold is tuned aggressively for the current investigation.

// supervisorOpStallThreshold is how long a single handleVaultOp may run
// before the watchdog treats it as wedged and dumps goroutines. Normal
// ops finish well under a second; the stall under investigation is ~30s.
// 12s is far past any legitimate op (incl. a cold subprocess spawn) and
// well inside the parent's 120s mux request timeout, so the dump lands
// before anything upstream gives up.
const supervisorOpStallThreshold = 12 * time.Second

// supervisorWatchdogTick is how often the watchdog scans in-flight ops.
const supervisorWatchdogTick = 2 * time.Second

// opTrace records one in-flight vault op for the stall watchdog.
type opTrace struct {
	id         uint64
	ownerSpace string
	subject    string
	startedAt  int64        // unix nanos
	stage      atomic.Value // string — coarse progress marker
	dumped     atomic.Bool  // goroutine dump already emitted for this op
}

func (t *opTrace) curStage() string {
	if s, ok := t.stage.Load().(string); ok {
		return s
	}
	return "?"
}

var (
	opTraceSeq atomic.Uint64
	opTraces   sync.Map // id (uint64) -> *opTrace
)

// startOpTrace registers a new in-flight op and returns its trace handle.
// Call finish() (deferred) when the op returns.
func startOpTrace(ownerSpace, subject string) *opTrace {
	t := &opTrace{
		id:         opTraceSeq.Add(1),
		ownerSpace: ownerSpace,
		subject:    subject,
		startedAt:  time.Now().UnixNano(),
	}
	t.stage.Store("entry")
	opTraces.Store(t.id, t)
	return t
}

// setStage updates the coarse progress marker. nil-safe.
func (t *opTrace) setStage(stage string) {
	if t == nil {
		return
	}
	t.stage.Store(stage)
}

// finish removes the op from the in-flight registry. nil-safe.
func (t *opTrace) finish() {
	if t == nil {
		return
	}
	opTraces.Delete(t.id)
}

// runSupervisorStallWatchdog scans in-flight ops every supervisorWatchdogTick
// and, when one has been running longer than supervisorOpStallThreshold,
// dumps every supervisor goroutine stack via sendLog AND asks requestDump
// to SIGUSR1 each stalled owner's subprocess (so the subprocess produces
// its own goroutine dump — the supervisor dump alone cannot see a wedge
// inside the vault-manager). Each stalled op is dumped at most once (the
// dumped flag). Blocks until ctx is cancelled.
func runSupervisorStallWatchdog(ctx context.Context, sendLog func(level, source, message string), requestDump func(ownerSpace string)) {
	ticker := time.NewTicker(supervisorWatchdogTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scanForStalledOps(sendLog, requestDump)
		}
	}
}

func scanForStalledOps(sendLog func(level, source, message string), requestDump func(ownerSpace string)) {
	now := time.Now().UnixNano()
	var firstStall *opTrace
	opTraces.Range(func(_, v any) bool {
		t := v.(*opTrace)
		if time.Duration(now-t.startedAt) >= supervisorOpStallThreshold && !t.dumped.Load() {
			if firstStall == nil {
				firstStall = t
			}
		}
		return true
	})
	if firstStall == nil {
		return
	}
	// Mark every currently-stalled op as dumped so a single goroutine
	// dump covers them all and a long wedge does not dump every tick.
	// Collect the distinct stalled owners to SIGUSR1 afterwards.
	stalledOwners := make(map[string]bool)
	opTraces.Range(func(_, v any) bool {
		t := v.(*opTrace)
		if time.Duration(now-t.startedAt) >= supervisorOpStallThreshold {
			t.dumped.Store(true)
			stalledOwners[t.ownerSpace] = true
		}
		return true
	})

	// Summary: every in-flight op and the stage it is parked at.
	var summary strings.Builder
	summary.WriteString("WATCHDOG(supervisor): vault op exceeded stall threshold — in-flight ops:\n")
	opTraces.Range(func(_, v any) bool {
		t := v.(*opTrace)
		fmt.Fprintf(&summary, "  op#%d owner=%s subject=%s stage=%s elapsed=%s\n",
			t.id, t.ownerSpace, t.subject, t.curStage(),
			time.Duration(now-t.startedAt).Round(time.Millisecond))
		return true
	})
	sendLog("error", "supervisor-watchdog", summary.String())

	// Full goroutine dump, chunked so each journal line stays readable.
	buf := make([]byte, 2<<20)
	n := runtime.Stack(buf, true)
	dump := buf[:n]
	const chunkSize = 3072
	total := len(dump)
	for off := 0; off < total; off += chunkSize {
		end := off + chunkSize
		if end > total {
			end = total
		}
		sendLog("error", "supervisor-watchdog",
			fmt.Sprintf("WATCHDOG(supervisor) goroutines [%d-%d/%d]\n%s",
				off, end, total, dump[off:end]))
	}

	// Ask each stalled owner's subprocess to dump its own goroutines
	// (SIGUSR1). The supervisor dump above only covers supervisor
	// goroutines; a wedge inside the vault-manager is invisible to it.
	for owner := range stalledOwners {
		requestDump(owner)
	}
}
