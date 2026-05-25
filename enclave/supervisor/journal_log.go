package main

import (
	"io"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog"
)

// This file tees the supervisor's own zerolog output to the parent
// journal. The supervisor runs inside the Nitro Enclave; its ordinary
// zerolog goes only to os.Stderr -> the enclave console, which a
// production enclave (no debug console) does not capture. That made the
// supervisor a journal blind spot: while vault-manager logs reach
// `journalctl -u vettid-parent` (forwarded as MessageTypeLog) and the
// parent logs directly, every supervisor line — "handleVaultOp
// received", "Processing message", ProcessMessage breadcrumbs, the
// stall-watchdog dump — was invisible in production. The 2026-05-21
// device-approval stall investigation needed supervisor visibility.
//
// Journal forwarding is gated at WARN+ (see journalMinLevel) so DEBUG
// chatter stays console-only and doesn't flood the mux. Bump back to
// DEBUG via this constant only when actively investigating something.
//
// Forwarding is asynchronous and lossy by design: Write does a
// non-blocking enqueue and drops on a full queue, so logging never
// blocks a supervisor goroutine, and a log emitted as a side effect of
// forwarding cannot recurse on the stack — it is just another queue
// item drained by the single forwarder goroutine.

const journalLogQueueSize = 512

// journalMinLevel is the minimum zerolog level forwarded to the parent
// journal. Below this stays console-only.
const journalMinLevel = zerolog.WarnLevel

// leveledLevelWriter is a zerolog.LevelWriter that drops events below
// journalMinLevel before they reach the inner writer. The unfiltered
// Write path is required so direct io.Writer use (e.g. internal zerolog
// bookkeeping) compiles, but the per-event log path always routes
// through WriteLevel — which is where the filtering happens.
type leveledLevelWriter struct {
	inner io.Writer
}

func (w *leveledLevelWriter) Write(p []byte) (int, error) {
	return w.inner.Write(p)
}

func (w *leveledLevelWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	if level < journalMinLevel {
		return len(p), nil
	}
	return w.inner.Write(p)
}

// journalLogWriter is an io.Writer that hands formatted log lines to an
// async forwarder goroutine.
type journalLogWriter struct {
	queue chan string
}

func (w *journalLogWriter) Write(p []byte) (int, error) {
	// zerolog/ConsoleWriter may reuse the backing buffer — copy now.
	line := strings.TrimRight(string(p), "\n")
	if line != "" {
		select {
		case w.queue <- line:
		default:
			// Queue full — drop. Logging must never block the supervisor.
		}
	}
	return len(p), nil
}

// forward drains the queue, shipping each line to the parent via sink
// (Supervisor.SendLog). Runs for the life of the process.
func (w *journalLogWriter) forward(sink func(level, source, message string)) {
	for line := range w.queue {
		sink("info", "supervisor", line)
	}
}

var (
	supervisorJournal     *journalLogWriter
	supervisorJournalOnce sync.Once
)

// newSupervisorLogger returns a zerolog writer that tees every event to
// both the enclave console (os.Stderr) and the parent journal. The
// journal half is dormant until startJournalForwarding wires in a sink.
func newSupervisorLogger() zerolog.LevelWriter {
	supervisorJournalOnce.Do(func() {
		supervisorJournal = &journalLogWriter{queue: make(chan string, journalLogQueueSize)}
	})
	stderrConsole := zerolog.ConsoleWriter{Out: os.Stderr, NoColor: true}
	journalConsole := zerolog.ConsoleWriter{Out: supervisorJournal, NoColor: true}
	filteredJournal := &leveledLevelWriter{inner: journalConsole}
	return zerolog.MultiLevelWriter(stderrConsole, filteredJournal)
}

// startJournalForwarding launches the forwarder goroutine once a parent
// log sink is available. Safe to call before a parent connects — sink
// (Supervisor.SendLog) is itself a no-op until the mux is wired.
func startJournalForwarding(sink func(level, source, message string)) {
	if supervisorJournal == nil {
		return
	}
	go supervisorJournal.forward(sink)
}
