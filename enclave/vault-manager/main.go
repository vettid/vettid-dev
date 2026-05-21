// Package main implements the Vault Manager for VettID Nitro Enclave.
// Each vault-manager process handles a single user's vault operations,
// holding their unsealed credential in secure enclave memory.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Version is set at build time
var Version = "dev"

func main() {
	// Parse command line flags
	ownerSpace := flag.String("owner-space", "", "Owner space (user GUID) for this vault")
	parentFD := flag.Int("parent-fd", 0, "File descriptor for parent communication")
	devMode := flag.Bool("dev-mode", false, "Run in development mode")
	flag.Parse()

	if *ownerSpace == "" {
		fmt.Fprintln(os.Stderr, "Error: --owner-space is required")
		os.Exit(1)
	}

	// Configure logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().
		Str("owner_space", *ownerSpace).
		Logger()

	log.Info().
		Str("version", Version).
		Bool("dev_mode", *devMode).
		Msg("Vault Manager starting")

	// SECURITY: Enforce process isolation hardening
	// This must be done early before any sensitive data is loaded
	isoCfg := DefaultIsolationConfig(*devMode)
	if err := EnforceIsolation(isoCfg); err != nil {
		log.Error().Err(err).Msg("Failed to enforce process isolation")
		// In production, this is a fatal error
		if !*devMode {
			os.Exit(1)
		}
	}

	// Create vault manager
	cfg := &VaultConfig{
		OwnerSpace: *ownerSpace,
		ParentFD:   *parentFD,
		DevMode:    *devMode,
	}

	vault, err := NewVaultManager(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create vault manager")
	}

	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
	}()

	// Run vault manager (blocks until context is cancelled)
	if err := vault.Run(ctx); err != nil {
		log.Fatal().Err(err).Msg("Vault manager error")
	}

	// SECURITY: Secure erase all sensitive data before exit
	vault.SecureShutdown()

	log.Info().Msg("Vault manager shutdown complete")
}

// VaultConfig holds the vault manager configuration
type VaultConfig struct {
	OwnerSpace string
	ParentFD   int
	DevMode    bool
}

// VaultManager handles a single user's vault operations
type VaultManager struct {
	config         *VaultConfig
	storage        *EncryptedStorage
	session        *Session
	messageHandler *MessageHandler
	publisher      *VsockPublisher
	parentConn     *ParentConnection // IPC connection to supervisor
}

// Session holds session state for authenticated operations
type Session struct {
	Token       []byte
	ExpiresAt   int64
	Permissions []string
}

// NewVaultManager creates a new vault manager
func NewVaultManager(cfg *VaultConfig) (*VaultManager, error) {
	// Create encrypted storage adapter
	storage, err := NewEncryptedStorage(cfg.OwnerSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	vm := &VaultManager{
		config:     cfg,
		storage:    storage,
		parentConn: NewParentConnection(), // IPC to supervisor via stdin/stdout
	}

	// Create publisher for sending messages via supervisor
	vm.publisher = NewVsockPublisher(cfg.OwnerSpace, vm.sendToParent)

	// Create message handler with call support
	// Pass sendFn so the sealer proxy can request KMS operations from supervisor
	vm.messageHandler = NewMessageHandler(cfg.OwnerSpace, storage, vm.publisher, vm.sendToParent)

	// Wire the device-connection lister so PublishToApp fans every
	// forApp event out to each paired desktop's MessageSpace channel.
	// Done here (after both publisher and messageHandler exist) so
	// the closure can reach the live connection storage.
	vm.publisher.SetDeviceLister(func() []string {
		return listActiveDeviceConnectionIDs(storage)
	})

	return vm, nil
}

// Run starts the vault manager and processes messages
func (vm *VaultManager) Run(ctx context.Context) error {
	log.Info().Str("owner_space", vm.config.OwnerSpace).Msg("Vault manager running")

	// Initialize message handler (loads block list, etc.)
	if err := vm.messageHandler.Initialize(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to initialize message handler (continuing)")
	}

	// Message processing loop
	msgChan := make(chan *IncomingMessage, 10)

	// Channel for sealer responses from supervisor
	// This allows the sealer proxy to receive KMS responses asynchronously
	// IMPORTANT: Sealer responses are routed directly in receiveMessages() to avoid
	// a deadlock where the main loop blocks in HandleMessage waiting for the sealer
	// response, but the main loop is the only thing that reads from msgChan.
	sealerResponseCh := make(chan *IncomingMessage, 5)
	vm.messageHandler.SetSealerResponseChannel(sealerResponseCh)

	// Channel for HTTP proxy responses from parent (via supervisor)
	// Same pattern as sealer responses: routed directly to avoid deadlock
	httpResponseCh := make(chan *IncomingMessage, 5)
	vm.messageHandler.SetHTTPResponseChannel(httpResponseCh)

	// Start message receiver (reads from parent FD)
	// Pass response channels so proxy responses can be routed directly, bypassing the main loop
	go vm.receiveMessages(ctx, msgChan, sealerResponseCh, httpResponseCh)

	// Stall watchdog: a vault op is reads plus small writes, so any op
	// that runs past opStallThreshold means the subprocess is wedged
	// (the 2026-05-20 ~2-minute stall behind the device-approval
	// timeouts). The watchdog dumps every goroutine's stack so the
	// cause is captured in the journal; the supervisor's read-timeout
	// eviction is what tears the wedged subprocess down.
	opStartedAt := new(atomic.Int64)
	go runStallWatchdog(ctx, opStartedAt)

	// SECURITY: Periodic cleanup of expired replay prevention events (every hour)
	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer cleanupTicker.Stop()

	// Auto-save is now triggered after each successful request handling (below)
	// instead of on a timer. Timer-based auto-save caused a deadlock: vault-manager
	// sends sealer requests via stdout, but the supervisor only reads from the
	// subprocess pipe during ProcessMessage (active parent request). Timer-based
	// persists fire outside of request processing, so the sealer request sits
	// unread in the pipe until timeout.

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Vault manager shutting down")
			// Persist vault state before shutdown to avoid data loss
			vm.messageHandler.PersistVaultStateToS3()
			return nil
		case <-cleanupTicker.C:
			// SECURITY: Clean up expired replay prevention events
			if deleted, err := vm.storage.CleanupExpiredEvents(); err != nil {
				log.Warn().Err(err).Msg("Failed to cleanup expired replay prevention events")
			} else if deleted > 0 {
				log.Debug().Int64("deleted", deleted).Msg("Cleaned up expired replay prevention events")
			}

			// Clean up old events based on retention policies
			if eventHandler := vm.messageHandler.GetEventHandler(); eventHandler != nil {
				if deleted, err := eventHandler.RunCleanup(ctx); err != nil {
					log.Warn().Err(err).Msg("Failed to cleanup events")
				} else if deleted > 0 {
					log.Info().Int64("deleted", deleted).Msg("Event cleanup completed")
				}
			}
		case msg := <-msgChan:
			opStartedAt.Store(time.Now().UnixNano()) // arm the stall watchdog
			// Note: Sealer responses are now routed directly in receiveMessages()
			// to avoid a deadlock when HandleMessage blocks waiting for sealer responses.

			// Handle regular vault operations
			response, err := vm.messageHandler.HandleMessage(ctx, msg)
			if err != nil {
				log.Error().Err(err).Str("msg_id", msg.GetID()).Msg("Error handling message")
				response = &OutgoingMessage{
					RequestID: msg.GetID(),
					Type:      MessageTypeError,
					Error:     err.Error(),
				}
			}
			// Auto-persist vault state BEFORE sending the response.
			//
			// persistVaultStateToS3 is throttled (debounced), so most
			// ops are a no-op here; but when it does fire it emits a
			// store_vault_state sealer request of ~500KB-1.3MB on the
			// stdout pipe. The supervisor only drains that pipe while
			// ProcessMessage for THIS op is active — and ProcessMessage
			// returns the instant it reads the op response. Persisting
			// AFTER the response therefore sent a >1MB write into a
			// pipe nobody was draining: it blocked on the full 64KB
			// pipe buffer until the next op arrived to drain it — a
			// 30s-to-2min subprocess wedge, the root cause of the
			// 2026-05-20 stalls (the stall watchdog's goroutine dump
			// caught goroutine 1 blocked in this exact write syscall).
			// Persisting first keeps the supervisor reading the pipe,
			// so the large write drains as it is written. Cost: an op
			// that actually persists waits ~0.5-2s longer for its
			// response — and debouncing means that is roughly once per
			// persistDebounceInterval window, not every op.
			//
			// Mutating handlers still call persistVaultStateToS3()
			// explicitly inside HandleMessage (also throttled); those
			// run mid-op while the pipe is being drained, so they were
			// never affected. Durability semantics are unchanged.
			if err == nil && response != nil && response.Type != MessageTypeError {
				vm.messageHandler.persistVaultStateToS3()
			}

			if response != nil {
				// Echo the supervisor's pipe-transport correlation
				// token onto the response. Done here, in one place, so
				// it is consistent across every handler regardless of
				// whether the handler set RequestID — the supervisor's
				// per-VaultProcess pipe reader routes the response to
				// the waiting op by this token.
				response.PipeID = msg.PipeID
				if err := vm.sendToParent(response); err != nil {
					log.Error().Err(err).Msg("Failed to send response")
				}
			}

			// D3 self-eviction: a persist this iteration (or a prior
			// one) tripped the split-brain conditional-PUT guard. The
			// response above has already been flushed to the parent,
			// so exit now — cleanly, exit code 0. The supervisor's
			// waitForExit reaps the subprocess and removes it from
			// its map; the next op for this user spawns a FRESH
			// subprocess that cold-loads whichever vault_state.enc
			// won the race. Turns what used to be a permanent wedge
			// (ownershipRevoked, never cleared) into a self-heal.
			if vm.messageHandler.IsSelfEvictRequested() {
				log.Warn().
					Str("owner_space", vm.config.OwnerSpace).
					Msg("D3 self-eviction: exiting subprocess so the next op cold-reloads vault_state.enc")
				os.Exit(0)
			}
			opStartedAt.Store(0) // op complete — disarm the stall watchdog
		}
	}
}

// opStallThreshold is how long a single vault op may run before the
// stall watchdog treats the subprocess as wedged. Vault ops are reads
// and small writes — well under a second normally — so 25s is far past
// any legitimate op, and still inside the supervisor's 30s op deadline
// so the dump lands before the wedged subprocess is torn down.
const opStallThreshold = 25 * time.Second

// runStallWatchdog dumps every goroutine's stack to stderr (forwarded
// to the journal) when the main loop has been inside a single op
// longer than opStallThreshold. It fires at most once per wedge:
// opStartedAt carries a fresh timestamp per op, so a new op re-arms
// it, and an idle subprocess (opStartedAt == 0) re-arms it too.
func runStallWatchdog(ctx context.Context, opStartedAt *atomic.Int64) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	var dumpedFor int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			started := opStartedAt.Load()
			if started == 0 {
				dumpedFor = 0 // idle — re-arm for the next op
				continue
			}
			elapsed := time.Since(time.Unix(0, started))
			if elapsed < opStallThreshold || started == dumpedFor {
				continue
			}
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			log.Error().
				Dur("op_elapsed", elapsed).
				Msg("WATCHDOG: vault op exceeded stall threshold — subprocess wedged; full goroutine dump follows")
			_, _ = os.Stderr.Write(buf[:n])
			dumpedFor = started
		}
	}
}

// receiveMessages reads messages from the supervisor via stdin pipe.
// Sealer responses (sealer_response type) and HTTP responses (http_response type)
// are routed directly to their respective channels to avoid a deadlock with the
// main message processing loop.
func (vm *VaultManager) receiveMessages(ctx context.Context, msgChan chan<- *IncomingMessage, sealerResponseCh chan<- *IncomingMessage, httpResponseCh chan<- *IncomingMessage) {
	log.Debug().Msg("Message receiver started, reading from stdin")

	for {
		select {
		case <-ctx.Done():
			log.Debug().Msg("Message receiver stopping")
			return
		default:
			// Read next message from supervisor
			msg, err := vm.parentConn.ReadMessage()
			if err != nil {
				log.Error().Err(err).Msg("Failed to read message from supervisor")
				// If pipe is closed, the supervisor has terminated us
				return
			}

			// Route sealer responses directly to avoid deadlock.
			// The main loop blocks in HandleMessage waiting for sealer responses,
			// so we can't route through msgChan (main loop can't read it when blocked).
			if vm.messageHandler.IsSealerResponse(msg) {
				select {
				case sealerResponseCh <- msg:
					log.Debug().Str("msg_id", msg.GetID()).Msg("Routed sealer response directly")
				default:
					log.Warn().Str("msg_id", msg.GetID()).Msg("Sealer response channel full, dropping")
				}
				continue
			}

			// Route HTTP proxy responses directly (same pattern as sealer responses).
			// HandleMessage may block waiting for HTTP responses from parent.
			if vm.messageHandler.IsHTTPResponse(msg) {
				select {
				case httpResponseCh <- msg:
					log.Debug().Str("msg_id", msg.GetID()).Msg("Routed HTTP response directly")
				default:
					log.Warn().Str("msg_id", msg.GetID()).Msg("HTTP response channel full, dropping")
				}
				continue
			}

			// Apply routing-ownership revocation immediately — do NOT
			// route through msgChan/HandleMessage. The supervisor sends
			// this when the parent lost our routing claim; the whole
			// point is that it lands even while the main loop is blocked
			// mid-request, so the in-flight request's tail-end
			// force-flush sees the fence. See split-brain fix (D2).
			if vm.messageHandler.IsRevokeOwnership(msg) {
				vm.messageHandler.MarkOwnershipRevoked()
				continue
			}

			// Send regular messages to processing channel
			select {
			case msgChan <- msg:
			case <-ctx.Done():
				return
			}
		}
	}
}

// sendToParent sends a message to the supervisor via stdout pipe
func (vm *VaultManager) sendToParent(msg *OutgoingMessage) error {
	return vm.parentConn.WriteMessage(msg)
}

// SecureShutdown performs secure cleanup of all sensitive data
// SECURITY: This must be called before process exit to prevent credential leakage
func (vm *VaultManager) SecureShutdown() {
	log.Info().Msg("Performing secure shutdown")

	// 1. Credential plaintext is no longer cached on VaultManager
	//    (Phase D moved to per-op decrypt). Nothing to zero here.

	// 2. Zero session token
	if vm.session != nil {
		zeroBytes(vm.session.Token)
		vm.session = nil
		log.Debug().Msg("Zeroed session token")
	}

	// 3. Zero message handler state (which holds VaultState)
	if vm.messageHandler != nil {
		vm.messageHandler.SecureErase()
		log.Debug().Msg("Zeroed message handler state")
	}

	// 4. Close parent connection
	if vm.parentConn != nil {
		vm.parentConn.Close()
	}

	log.Info().Msg("Secure shutdown complete - all sensitive data zeroed")
}
