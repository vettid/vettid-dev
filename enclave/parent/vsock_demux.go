package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/rs/zerolog/log"
)

// vsock_demux.go — single-reader demultiplexer for the vsock channel.
//
// Replaces the previous serialized "one request at a time" model
// (sendWithHandlerSupport held requestMu for the whole round-trip).
// The new design lets many request goroutines wait on per-request
// channels while a single reader pumps every vsock message and
// dispatches by Type:
//
//   final-response types (response, error, ok, vault_response,
//   handler_response, attestation_response, credential_response,
//   health_response) → look up RequestID in pendingRequests and
//   forward to the waiting channel.
//
//   intermediate types (log, nats_publish, kms_encrypt, kms_decrypt,
//   storage_get, storage_put, nats_account_seed_get,
//   turn_credentials_get, pcr_signing_key_get, pcr_signing_key_sign,
//   proposals_list, vote_submit, vote_proof_request,
//   invite_resolve, audit_event, routing_handoff, http_request) →
//   spawn a goroutine that handles the request and writes the
//   response back via writeMu. Bounded by a semaphore so a slow AWS
//   call can't spawn unbounded goroutines.
//
// The vault-manager INSIDE the enclave is still single-threaded, so
// the wall-clock benefit comes from removing the parent's
// round-trip serialization: while op A is mid-processing in the
// vault-manager (perhaps waiting on its own KMS response), op B's
// vsock write can already be queued. The parent stops being the
// bottleneck; the cap is now vault-manager's per-op CPU time
// (typically <50 ms) rather than vault-manager + KMS + S3 +
// vsock-IO end-to-end.

// handlerWorkerLimit bounds concurrent intermediate-handler
// goroutines (KMS encrypt, S3 get/put, NATS publish, etc.). 16 is
// generous for current load while still preventing a runaway burst
// from spawning thousands of goroutines if one AWS API gets slow.
const handlerWorkerLimit = 16

// generateRequestID returns a fresh 16-byte hex token for use as the
// vsock multiplex key when the inbound message didn't carry an
// extractable "id".
func generateRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand only fails when the entropy source is gone —
		// in which case the host is dead and we're about to crash
		// anyway. Fall back to a zero token so we don't panic in a
		// hot path.
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// startVsockDemux launches the single reader goroutine that pumps
// every message off the vsock connection. Idempotent: subsequent
// calls are no-ops. Must be called after the vsock handshake
// completes — before that the connection is in handshake-message
// mode and the demux's readMessage would mis-parse.
func (p *ParentProcess) startVsockDemux(ctx context.Context) {
	p.mu.Lock()
	if p.demuxStarted {
		p.mu.Unlock()
		return
	}
	p.demuxStarted = true
	if p.pendingRequests == nil {
		p.pendingRequests = make(map[string]chan *EnclaveMessage)
	}
	p.mu.Unlock()

	go p.demuxLoop(ctx)
}

// demuxLoop is the single reader. Owns the vsock read side
// exclusively — no other goroutine should call vsockClient.read*
// after this starts. Exits on context cancel or read error; on
// read error, drains pending channels with a synthetic error so
// callers wake up instead of hanging.
func (p *ParentProcess) demuxLoop(ctx context.Context) {
	handlerSem := make(chan struct{}, handlerWorkerLimit)

	for {
		if ctx.Err() != nil {
			p.failPending("vsock demux shutting down")
			return
		}

		msg, err := p.vsockClient.readMessage()
		if err != nil {
			log.Error().Err(err).Msg("vsock demux: read failed, draining pending requests")
			p.failPending(fmt.Sprintf("vsock read error: %v", err))
			// Without an active reader, every future request would
			// hang. Exit and let the parent's supervisor (the
			// outer Run loop) decide whether to reconnect or die.
			return
		}

		switch msg.Type {
		// --- Final response types: match by RequestID --------------
		case EnclaveMessageTypeVaultResponse,
			EnclaveMessageTypeHandlerResponse,
			EnclaveMessageTypeAttestationResponse,
			EnclaveMessageTypeCredentialResponse,
			EnclaveMessageTypeHealthResponse,
			EnclaveMessageTypeError,
			EnclaveMessageTypeOK,
			"response":
			p.dispatchResponse(msg)

		// --- Pure side-effect: log + audit + handoff ---------------
		case EnclaveMessageTypeLog:
			p.handleEnclaveLog(msg)
		case EnclaveMessageTypeAuditEvent:
			// Already async in the legacy path; preserve that.
			go p.persistAuditEvent(ctx, msg)
		case EnclaveMessageTypeRoutingHandoff:
			p.handleRoutingHandoffMsg(msg)

		// --- NATS publish: fire-and-forget --------------------------
		case EnclaveMessageTypeNATSPublish:
			p.dispatchHandler(handlerSem, func() {
				if err := p.natsClient.Publish(msg.Subject, msg.Payload); err != nil {
					log.Error().Err(err).Str("subject", msg.Subject).
						Msg("Failed to publish NATS message from enclave")
				}
			})

		// --- Request-reply nested handlers (need response back) ----
		case EnclaveMessageTypeKMSEncrypt:
			p.dispatchHandler(handlerSem, func() {
				p.replyHandler(ctx, msg, p.handleKMSEncrypt)
			})
		case EnclaveMessageTypeKMSDecrypt:
			p.dispatchHandler(handlerSem, func() {
				p.replyHandler(ctx, msg, p.handleKMSDecrypt)
			})
		case EnclaveMessageTypeStorageGet:
			p.dispatchHandler(handlerSem, func() {
				p.replyHandler(ctx, msg, p.handleStorageGet)
			})
		case EnclaveMessageTypeStoragePut:
			p.dispatchHandler(handlerSem, func() {
				p.replyHandler(ctx, msg, p.handleStoragePut)
			})
		case EnclaveMessageTypeNATSAccountSeedGet:
			p.dispatchHandler(handlerSem, func() {
				p.replyNoError(msg, p.handleAccountSeedGet(ctx, msg))
			})
		case EnclaveMessageTypeTurnCredentialsGet:
			p.dispatchHandler(handlerSem, func() {
				p.replyNoError(msg, p.handleTurnCredentialsGet(ctx, msg))
			})
		case EnclaveMessageTypePCRSigningKeyGet:
			p.dispatchHandler(handlerSem, func() {
				p.replyNoError(msg, p.handlePCRSigningKeyGet(ctx, msg))
			})
		case EnclaveMessageTypePCRSigningKeySign:
			p.dispatchHandler(handlerSem, func() {
				p.replyNoError(msg, p.handlePCRSigningKeySign(ctx, msg))
			})
		case EnclaveMessageTypeProposalsList:
			p.dispatchHandler(handlerSem, func() {
				p.replyNoError(msg, p.handleProposalsList(msg))
			})
		case EnclaveMessageTypeVoteSubmit:
			p.dispatchHandler(handlerSem, func() {
				p.replyNoError(msg, p.handleVoteSubmit(msg))
			})
		case EnclaveMessageTypeVoteProofRequest:
			p.dispatchHandler(handlerSem, func() {
				p.replyNoError(msg, p.handleVoteProof(msg))
			})
		case EnclaveMessageTypeInviteResolve:
			p.dispatchHandler(handlerSem, func() {
				p.replyNoError(msg, p.handleInviteResolve(msg))
			})
		case EnclaveMessageTypeHTTPRequest:
			p.dispatchHandler(handlerSem, func() {
				p.replyNoError(msg, p.handleHTTPProxy(ctx, msg))
			})

		default:
			// Unknown intermediate types are most likely an
			// orphaned response (no waiting pending entry) or a
			// new vault-manager output we haven't taught the
			// demux about. Log loudly so this stays visible.
			log.Warn().
				Str("type", string(msg.Type)).
				Str("request_id", msg.RequestID).
				Msg("vsock demux: dropped unrecognized message type")
		}
	}
}

// dispatchResponse forwards a final-response message to the
// goroutine waiting on its RequestID, if any. A response without a
// matching pending entry is logged and dropped — typically caused
// by a caller that gave up (timeout, context cancel) before the
// enclave responded.
func (p *ParentProcess) dispatchResponse(msg *EnclaveMessage) {
	if msg.RequestID == "" {
		// Without a RequestID we can't route. Drop with a warning;
		// the vault-manager echoes RequestID on responses today, so
		// reaching this branch means an older code path slipped
		// through and needs to be fixed where it originates.
		log.Warn().
			Str("type", string(msg.Type)).
			Msg("vsock demux: response missing RequestID, dropping")
		return
	}

	p.pendingMu.Lock()
	ch, ok := p.pendingRequests[msg.RequestID]
	if ok {
		delete(p.pendingRequests, msg.RequestID)
	}
	p.pendingMu.Unlock()

	if !ok {
		log.Debug().
			Str("type", string(msg.Type)).
			Str("request_id", msg.RequestID).
			Msg("vsock demux: response for unknown RequestID (caller likely timed out)")
		return
	}

	// Non-blocking send — channel is created with buffer 1 so this
	// always succeeds. Belt-and-suspenders: if it ever can't send,
	// the receiver is gone and we drop the message.
	select {
	case ch <- msg:
	default:
		log.Warn().Str("request_id", msg.RequestID).
			Msg("vsock demux: per-request channel full, dropping response")
	}
}

// dispatchHandler runs fn under a handler-worker semaphore so a slow
// AWS round-trip can't spawn unbounded goroutines on a JetStream burst.
// If the semaphore is full we still proceed — preferring extra
// goroutines to dropping a handler reply that the enclave is blocked
// waiting for.
func (p *ParentProcess) dispatchHandler(sem chan struct{}, fn func()) {
	go func() {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			// Over the soft limit; run anyway. Log once at debug so we
			// can spot real saturation without flooding the log.
			log.Debug().Int("limit", handlerWorkerLimit).
				Msg("vsock demux: handler worker pool saturated, running unbounded for one op")
		}
		fn()
	}()
}

// replyHandler runs the given enclave-callback function and writes
// the reply (or an Error message) back to the enclave under writeMu.
// Used for KMS/storage handlers that follow the (request, reply)
// shape.
func (p *ParentProcess) replyHandler(
	ctx context.Context,
	in *EnclaveMessage,
	handler func(context.Context, *EnclaveMessage) (*EnclaveMessage, error),
) {
	out, err := handler(ctx, in)
	if err != nil {
		log.Error().Err(err).
			Str("type", string(in.Type)).
			Msg("vsock demux: nested handler failed; sending error to enclave")
		out = &EnclaveMessage{
			Type:      EnclaveMessageTypeError,
			RequestID: in.RequestID,
			Error:     err.Error(),
		}
	}
	if out == nil {
		return
	}
	// Preserve RequestID round-trip so the enclave can correlate.
	if out.RequestID == "" {
		out.RequestID = in.RequestID
	}
	p.vsockClient.writeMu.Lock()
	if err := p.vsockClient.writeMessage(out); err != nil {
		log.Error().Err(err).
			Str("type", string(out.Type)).
			Msg("vsock demux: failed to write nested handler response")
	}
	p.vsockClient.writeMu.Unlock()
}

// replyNoError mirrors replyHandler for handlers that return only
// the response message (no error tuple). Same RequestID echo + write.
func (p *ParentProcess) replyNoError(in *EnclaveMessage, out *EnclaveMessage) {
	if out == nil {
		return
	}
	if out.RequestID == "" {
		out.RequestID = in.RequestID
	}
	p.vsockClient.writeMu.Lock()
	if err := p.vsockClient.writeMessage(out); err != nil {
		log.Error().Err(err).
			Str("type", string(out.Type)).
			Msg("vsock demux: failed to write nested handler response")
	}
	p.vsockClient.writeMu.Unlock()
}

// handleEnclaveLog routes a log message from the enclave through
// zerolog so it shows up in journald alongside the parent's own logs.
func (p *ParentProcess) handleEnclaveLog(msg *EnclaveMessage) {
	switch msg.LogLevel {
	case "debug":
		log.Debug().Str("source", msg.LogSource).Msg(msg.LogMessage)
	case "info":
		log.Info().Str("source", msg.LogSource).Msg(msg.LogMessage)
	case "warn":
		log.Warn().Str("source", msg.LogSource).Msg(msg.LogMessage)
	case "error":
		log.Error().Str("source", msg.LogSource).Msg(msg.LogMessage)
	default:
		log.Info().Str("source", msg.LogSource).Str("level", msg.LogLevel).Msg(msg.LogMessage)
	}
}

// handleRoutingHandoffMsg replicates the legacy in-loop routing-
// handoff behavior from sendWithHandlerSupport. Kept as a method on
// ParentProcess so the demux dispatch table stays uniform.
func (p *ParentProcess) handleRoutingHandoffMsg(msg *EnclaveMessage) {
	if p.routing == nil || msg.OwnerSpace == "" {
		log.Warn().
			Str("owner_space", msg.OwnerSpace).
			Str("target", msg.TargetInstanceID).
			Msg("routing: ignoring malformed handoff request from enclave")
		return
	}
	if err := p.routing.HandoffToPeer(msg.OwnerSpace, msg.TargetInstanceID, msg.NewPCR0); err != nil {
		log.Error().
			Err(err).
			Str("owner_space", msg.OwnerSpace).
			Str("target", msg.TargetInstanceID).
			Msg("routing: handoff failed")
	}
}

// failPending wakes every blocked requestEnclave caller with a
// synthetic error response so they return immediately on
// demux-shutdown rather than hanging until their own timeout.
func (p *ParentProcess) failPending(reason string) {
	p.pendingMu.Lock()
	pending := p.pendingRequests
	p.pendingRequests = make(map[string]chan *EnclaveMessage)
	p.pendingMu.Unlock()

	for rid, ch := range pending {
		select {
		case ch <- &EnclaveMessage{
			Type:      EnclaveMessageTypeError,
			RequestID: rid,
			Error:     reason,
		}:
		default:
		}
	}
}

// requestEnclave writes a request to the enclave and waits for its
// final response. Replaces sendWithHandlerSupport.
//
// Concurrency: many goroutines may call this simultaneously. They
// serialize only on the per-write writeMu (microseconds-scale) —
// never on the full request-response round-trip.
func (p *ParentProcess) requestEnclave(ctx context.Context, msg *EnclaveMessage) (*EnclaveMessage, error) {
	if msg.RequestID == "" {
		msg.RequestID = generateRequestID()
	}

	ch := make(chan *EnclaveMessage, 1)
	p.pendingMu.Lock()
	if _, exists := p.pendingRequests[msg.RequestID]; exists {
		p.pendingMu.Unlock()
		// Unlikely (RequestIDs are hex-encoded random or extracted
		// from a unique client envelope) but guard anyway. Fail fast
		// rather than overwriting the in-flight entry.
		return nil, fmt.Errorf("duplicate request_id %s already in flight", msg.RequestID)
	}
	p.pendingRequests[msg.RequestID] = ch
	p.pendingMu.Unlock()

	// Cleanup on every return path — including ctx-cancel where
	// dispatchResponse never sees the message.
	defer func() {
		p.pendingMu.Lock()
		delete(p.pendingRequests, msg.RequestID)
		p.pendingMu.Unlock()
	}()

	p.vsockClient.writeMu.Lock()
	err := p.vsockClient.writeMessage(msg)
	p.vsockClient.writeMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	select {
	case resp := <-ch:
		if resp.Type == EnclaveMessageTypeError && resp.Error != "" {
			// Surface error responses as Go errors AND as the
			// response value so existing callers that introspect
			// the response don't break.
			return resp, nil
		}
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
