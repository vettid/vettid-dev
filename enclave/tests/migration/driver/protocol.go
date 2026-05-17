package main

// Wire-protocol helpers the driver uses to talk to the vault. The
// vault parent publishes responses on two subjects per request:
//
//   OwnerSpace.<guid>.forApp.<op>.<event_id>.response   (correlated)
//   OwnerSpace.<guid>.forApp.<op>.response              (push/broadcast)
//
// We subscribe to the correlated subject so concurrent requests of
// the same op type don't collide. Push subjects (e.g.
// forApp.connection.data-grant-fetch-response) are a separate path
// used for async events; pushSubscribe handles those.
//
// Request envelopes follow the Android app's convention:
//
//   { "id":        "<event_id>",
//     "type":      "<op>",
//     "timestamp": "<RFC3339Z>",
//     "payload":   { ... op-specific ... } }
//
// Published via JetStream so the response stream's ENROLLMENT
// subjects (OwnerSpace.*.forApp.>) catch it for replay.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

// Envelope is the outer wrapping every forVault request uses.
type Envelope struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Timestamp string          `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
}

// publishAndAwait publishes a request envelope on
// OwnerSpace.<ownerSpace>.forVault.<op> and waits for the matching
// response on OwnerSpace.<ownerSpace>.forApp.<op>.<event_id>.response.
// Returns the raw response bytes (the parent's published payload,
// pre-decoded from JSON envelope or not — depends on the op).
//
// op is the dotted operation name (e.g. "attestation", "pin",
// "credential.create"). For ops whose forApp suffix differs from the
// forVault suffix, use publishAndAwaitOn instead.
func (h *Harness) publishAndAwait(
	ctx context.Context,
	ownerSpace string,
	op string,
	payload any,
) ([]byte, error) {
	return h.publishAndAwaitOn(ctx, ownerSpace, op, op, payload)
}

// publishWithType is the explicit-envelope-type form of publishAndAwait.
// Some ops (pin.setup / pin.unlock / pin.change) use a *single* subject
// suffix (`.forVault.pin`) and disambiguate via the envelope's outer
// `type` field — the vault's central unwrapPayload promotes that type
// to msg.PayloadType, which the dispatcher reads. envType is the
// envelope `type` (e.g. "pin.setup"); subjectOp is the topic suffix
// (e.g. "pin"); responseOp is the forApp suffix (same as subjectOp
// for the parent's pub/sub default).
func (h *Harness) publishWithType(
	ctx context.Context,
	ownerSpace string,
	subjectOp string,
	responseOp string,
	envType string,
	payload any,
) ([]byte, error) {
	return h.publishCore(ctx, ownerSpace, subjectOp, responseOp, envType, payload)
}

// publishAndAwaitOn lets the caller specify a different forApp suffix
// than the forVault one. Necessary for ops like "pin" where the
// forVault subject is `.forVault.pin` but the response lands on
// `.forApp.pin.<id>.response` — same suffix here — vs ops where the
// reply subject embeds an inner type. Kept as a separate seam in
// case future ops diverge.
func (h *Harness) publishAndAwaitOn(
	ctx context.Context,
	ownerSpace string,
	forVaultOp string,
	forAppOp string,
	payload any,
) ([]byte, error) {
	return h.publishCore(ctx, ownerSpace, forVaultOp, forAppOp, forVaultOp, payload)
}

// publishCore is the shared implementation: subscribes to the
// correlated response subject, publishes via JetStream, returns the
// first matching response body or the context error.
func (h *Harness) publishCore(
	ctx context.Context,
	ownerSpace string,
	subjectOp string,
	responseOp string,
	envType string,
	payload any,
) ([]byte, error) {
	eventID := uuid.NewString()

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	envelope := Envelope{
		ID:        eventID,
		Type:      envType,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Payload:   payloadBytes,
	}
	envBytes, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	respSubject := fmt.Sprintf("OwnerSpace.%s.forApp.%s.%s.response",
		ownerSpace, responseOp, eventID)
	reqSubject := fmt.Sprintf("OwnerSpace.%s.forVault.%s", ownerSpace, subjectOp)

	// Subscribe BEFORE publishing so the correlated response can't be
	// missed by a sub set up after the parent already replied.
	sub, err := h.NC.SubscribeSync(respSubject)
	if err != nil {
		return nil, fmt.Errorf("subscribe %s: %w", respSubject, err)
	}
	defer sub.Unsubscribe()

	if _, err := h.JS.Publish(reqSubject, envBytes); err != nil {
		return nil, fmt.Errorf("js publish %s: %w", reqSubject, err)
	}

	msg, err := sub.NextMsgWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("await response on %s: %w", respSubject, err)
	}
	return msg.Data, nil
}

// pushSubscribe sets up a per-subject queue that pushSubscribe.next
// can pull from. Returns a closer the caller defers. Used for async
// events the vault publishes without a correlated event_id — e.g.
// forApp.connection.data-grant-fetch-response.
type pushQueue struct {
	sub *nats.Subscription
	ch  chan *nats.Msg
}

// pushSubscribe returns a pushQueue listening on subject. Buffered to
// 32 messages; if the buffer fills the NATS client drops oldest. For
// the driver's purposes that's fine — we're either consuming
// immediately or the test failed anyway.
func (h *Harness) pushSubscribe(subject string) (*pushQueue, error) {
	q := &pushQueue{ch: make(chan *nats.Msg, 32)}
	sub, err := h.NC.Subscribe(subject, func(m *nats.Msg) {
		select {
		case q.ch <- m:
		default:
			// buffer full — drop oldest
			<-q.ch
			q.ch <- m
		}
	})
	if err != nil {
		return nil, fmt.Errorf("subscribe %s: %w", subject, err)
	}
	q.sub = sub
	return q, nil
}

func (q *pushQueue) next(ctx context.Context) (*nats.Msg, error) {
	select {
	case m := <-q.ch:
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (q *pushQueue) close() { _ = q.sub.Unsubscribe() }
