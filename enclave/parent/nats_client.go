package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
)

// NATSMessage represents a message received from NATS.
type NATSMessage struct {
	Subject string
	Reply   string
	Data    []byte
}

// ConnectionStateCallback is called when NATS connection state changes
type ConnectionStateCallback func(connected bool)

// NATSClient wraps a NATS connection with optional JetStream support
type NATSClient struct {
	conn          *nats.Conn
	js            nats.JetStreamContext
	config        NATSConfig
	subs          []*nats.Subscription
	stateCallback ConnectionStateCallback
	publishMu     sync.Mutex // Serializes all publish operations to prevent interleaving
}

// NewNATSClient creates a new NATS client with optional connection state callback
func NewNATSClient(cfg NATSConfig, stateCallback ConnectionStateCallback) (*NATSClient, error) {
	client := &NATSClient{
		config:        cfg,
		stateCallback: stateCallback,
	}

	// Build connection options
	opts := []nats.Option{
		nats.Name("vettid-enclave-parent"),
		nats.ReconnectWait(time.Duration(cfg.ReconnectWait) * time.Millisecond),
		nats.MaxReconnects(cfg.MaxReconnects),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			log.Warn().Err(err).Msg("NATS disconnected")
			if client.stateCallback != nil {
				client.stateCallback(false)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Info().Str("url", nc.ConnectedUrl()).Msg("NATS reconnected")
			if client.stateCallback != nil {
				client.stateCallback(true)
			}
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			log.Info().Msg("NATS connection closed")
			if client.stateCallback != nil {
				client.stateCallback(false)
			}
		}),
	}

	// Add credentials if provided
	if cfg.CredentialsFile != "" {
		if _, err := os.Stat(cfg.CredentialsFile); err == nil {
			opts = append(opts, nats.UserCredentials(cfg.CredentialsFile))
		}
	}

	// Connect
	conn, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	client.conn = conn

	// Initialize JetStream context
	js, err := conn.JetStream(nats.PublishAsyncMaxPending(256))
	if err != nil {
		log.Warn().Err(err).Msg("JetStream not available, falling back to core NATS")
	} else {
		client.js = js
		log.Info().Msg("JetStream context initialized")

		// Ensure enrollment stream exists for mobile app responses
		if err := client.ensureEnrollmentStream(); err != nil {
			log.Warn().Err(err).Msg("Failed to create enrollment stream, JetStream publish may fail")
		}

		// Long-TTL stream scoped to peer-to-peer message subjects.
		// Bound to the vault's JS durable consumer so offline peers
		// can catch up on missed messages — without replaying
		// credential ops (those live in ENROLLMENT only).
		if err := client.ensureVaultMessagesStream(); err != nil {
			log.Warn().Err(err).Msg("Failed to create vault messages stream — offline peer-message replay disabled")
		}

		// Ensure invitations stream exists for connection invitation broker
		if err := client.ensureInvitationsStream(); err != nil {
			log.Warn().Err(err).Msg("Failed to create invitations stream")
		}

		// Ensure routing KV bucket exists. Holds per-user ownership
		// state (which enclave instance is currently authoritative
		// for a user). See enclave/parent/routing.go.
		if err := client.ensureRoutingKV(); err != nil {
			log.Warn().Err(err).Msg("Failed to create routing KV — per-user routing will fall back to wildcard")
		}
	}

	return client, nil
}

// RoutingKV exposes the JetStream KeyValue store used for per-user
// ownership. Returns nil if JetStream isn't available or the bucket
// doesn't exist yet.
func (c *NATSClient) RoutingKV() (nats.KeyValue, error) {
	if c.js == nil {
		return nil, fmt.Errorf("JetStream not available")
	}
	return c.js.KeyValue(routingBucketName)
}

const (
	routingBucketName = "vault-routing"
	routingKVHistory  = uint8(5)
	routingKVMaxValue = int32(512)
)

// ensureRoutingKV creates the KV bucket that holds per-user
// ownership state. See enclave/parent/routing.go for the protocol.
//
// History=5 so we can look at recent ownership transitions for
// forensics. No TTL — heartbeat keeps keys fresh, so absence is
// meaningful. MaxValueSize caps writes to catch bugs (our JSON is
// ~200 B).
func (c *NATSClient) ensureRoutingKV() error {
	if c.js == nil {
		return fmt.Errorf("JetStream not available")
	}

	if existing, err := c.js.KeyValue(routingBucketName); err == nil && existing != nil {
		log.Debug().Str("bucket", routingBucketName).Msg("Routing KV bucket already exists")
		return nil
	}

	_, err := c.js.CreateKeyValue(&nats.KeyValueConfig{
		Bucket:       routingBucketName,
		Description:  "Per-user vault ownership (instance_id, pcr0, lease_until)",
		History:      routingKVHistory,
		MaxValueSize: routingKVMaxValue,
		Storage:      nats.FileStorage,
		Replicas:     1,
	})
	if err != nil {
		return fmt.Errorf("create routing KV: %w", err)
	}
	log.Info().Str("bucket", routingBucketName).Msg("Created routing KV bucket")
	return nil
}

// ensureEnrollmentStream persists short-TTL traffic for the enrollment
// flow and for in-flight request/response pairs: forApp responses the
// mobile app expects to collect after a reconnect, and forVault
// requests the parent may need to replay to the enclave over a brief
// disconnect. 30-minute retention is deliberate — this stream must NOT
// outlive the request lifetime, because a durable consumer on it
// would otherwise replay credential ops, migration starts, etc. on
// every new enclave instance (see the peer-message replay comment in
// parent.routeNATSToEnclave). Long-lived peer messaging durability
// lives in the VAULT_MESSAGES stream instead.
func (c *NATSClient) ensureEnrollmentStream() error {
	if c.js == nil {
		return fmt.Errorf("JetStream not available")
	}

	streamName := "ENROLLMENT"
	subjects := []string{
		"OwnerSpace.*.forApp.>",   // Mobile app responses
		"OwnerSpace.*.forVault.>", // Vault requests (for persistence)
	}

	cfg := &nats.StreamConfig{
		Name:       streamName,
		Subjects:   subjects,
		Retention:  nats.LimitsPolicy,
		MaxAge:     30 * time.Minute,
		Storage:    nats.FileStorage,
		Replicas:   1,
		Discard:    nats.DiscardOld,
		MaxMsgs:    10000,
		MaxBytes:   100 * 1024 * 1024, // 100MB
		Duplicates: 5 * time.Minute,
	}

	if existing, err := c.js.StreamInfo(streamName); err == nil {
		log.Debug().
			Str("stream", streamName).
			Int64("messages", int64(existing.State.Msgs)).
			Dur("desired_max_age", cfg.MaxAge).
			Dur("current_max_age", existing.Config.MaxAge).
			Msg("Updating ENROLLMENT stream config")
		if _, err := c.js.UpdateStream(cfg); err != nil {
			log.Warn().Err(err).Msg("ENROLLMENT stream update failed — continuing with existing config")
		}
		return nil
	}
	if _, err := c.js.AddStream(cfg); err != nil {
		return fmt.Errorf("failed to create enrollment stream: %w", err)
	}
	log.Info().Str("stream", streamName).Strs("subjects", subjects).Msg("Created enrollment stream")
	return nil
}

// ensureVaultMessagesStream persists peer-to-peer vault messages for
// offline replay. Scope is strict: only message subjects, no
// credential / migration / connection ops. 7-day MaxAge so a peer
// message sent while the receiver is offline still replays when they
// next unlock. Publishes to these subjects ALSO land in ENROLLMENT
// (subject overlap); that is fine — ENROLLMENT is short-TTL and has
// no subscriber bound to it, so the duplicate copy simply ages out.
// The vault-side JS durable consumer binds to THIS stream, which is
// what prevents credential ops from being replayed.
func (c *NATSClient) ensureVaultMessagesStream() error {
	if c.js == nil {
		return fmt.Errorf("JetStream not available")
	}

	streamName := "VAULT_MESSAGES"
	subjects := []string{
		"OwnerSpace.*.forVault.message.>",
	}

	cfg := &nats.StreamConfig{
		Name:       streamName,
		Subjects:   subjects,
		Retention:  nats.LimitsPolicy,
		MaxAge:     7 * 24 * time.Hour,
		Storage:    nats.FileStorage,
		Replicas:   1,
		Discard:    nats.DiscardOld,
		MaxMsgs:    250_000,
		MaxBytes:   2 * 1024 * 1024 * 1024, // 2GB
		Duplicates: 5 * time.Minute,
	}

	if existing, err := c.js.StreamInfo(streamName); err == nil {
		log.Debug().
			Str("stream", streamName).
			Int64("messages", int64(existing.State.Msgs)).
			Msg("VAULT_MESSAGES stream exists")
		if _, err := c.js.UpdateStream(cfg); err != nil {
			log.Warn().Err(err).Msg("VAULT_MESSAGES stream update failed — continuing with existing config")
		}
		return nil
	}
	if _, err := c.js.AddStream(cfg); err != nil {
		return fmt.Errorf("failed to create vault messages stream: %w", err)
	}
	log.Info().Str("stream", streamName).Strs("subjects", subjects).Msg("Created vault messages stream")
	return nil
}

// ensureInvitationsStream creates the stream for connection invitation broker.
// Invitations are published here by the parent when a vault creates an invite.
// Scanners fetch invitation data using a guest NATS account with just the short code.
func (c *NATSClient) ensureInvitationsStream() error {
	if c.js == nil {
		return fmt.Errorf("JetStream not available")
	}

	streamName := "INVITATIONS"
	subjects := []string{"invite.>"}

	// Check if stream exists
	stream, err := c.js.StreamInfo(streamName)
	if err == nil {
		log.Debug().Str("stream", streamName).Int64("messages", int64(stream.State.Msgs)).Msg("Invitations stream exists")
		return nil
	}

	_, err = c.js.AddStream(&nats.StreamConfig{
		Name:       streamName,
		Subjects:   subjects,
		Retention:  nats.LimitsPolicy,
		MaxAge:     5 * time.Minute,         // Short-lived — scan the QR promptly
		Storage:    nats.MemoryStorage,       // Ephemeral, no disk persistence needed
		Replicas:   1,
		Discard:    nats.DiscardOld,
		MaxMsgs:    10000,
		MaxBytes:   50 * 1024 * 1024,        // 50MB
		Duplicates: 1 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("failed to create invitations stream: %w", err)
	}

	log.Info().Str("stream", streamName).Strs("subjects", subjects).Msg("Created invitations stream")
	return nil
}

// Subscribe subscribes to a subject and sends messages to the channel
func (c *NATSClient) Subscribe(subject string, msgChan chan *NATSMessage) error {
	sub, err := c.conn.Subscribe(subject, func(msg *nats.Msg) {
		select {
		case msgChan <- &NATSMessage{
			Subject: msg.Subject,
			Reply:   msg.Reply,
			Data:    msg.Data,
		}:
		default:
			log.Warn().Str("subject", msg.Subject).Msg("Message channel full, dropping message")
		}
	})
	if err != nil {
		return err
	}

	c.subs = append(c.subs, sub)
	log.Debug().Str("subject", subject).Msg("Subscribed to NATS")
	return nil
}

// SubscribeJS attaches a durable JetStream push consumer to the given
// subject filter on the given stream and forwards delivered messages to
// msgChan. Unlike the core-NATS Subscribe above, this replays messages
// the consumer missed while the enclave was offline (peer messages,
// read receipts) and requires explicit Ack per message — the caller is
// expected to invoke msg.Ack after successful processing so JetStream
// can clear the record.
//
// durableName must be stable across restarts so state (last-delivered
// sequence, pending acks) carries over.
func (c *NATSClient) SubscribeJS(stream, subject, durableName string, msgChan chan *NATSMessage) error {
	if c.js == nil {
		return fmt.Errorf("JetStream not available")
	}

	sub, err := c.js.Subscribe(subject, func(msg *nats.Msg) {
		select {
		case msgChan <- &NATSMessage{
			Subject: msg.Subject,
			Reply:   msg.Reply,
			Data:    msg.Data,
		}:
			// Hand-off to the processing channel is our commit point.
			// Ack here — if the process crashes between Ack and the
			// downstream handler finishing, we lose the message, but
			// that's a narrow window and the normal case matters more.
			if err := msg.Ack(); err != nil {
				log.Warn().Err(err).Str("subject", msg.Subject).Msg("JetStream Ack failed")
			}
		default:
			// Channel full — do NOT ack. JetStream will redeliver
			// after the AckWait window expires.
			log.Warn().Str("subject", msg.Subject).Msg("Message channel full, leaving JetStream msg unacked for redelivery")
		}
	},
		nats.BindStream(stream),
		nats.Durable(durableName),
		nats.DeliverAll(),
		nats.ManualAck(),
		nats.AckExplicit(),
		nats.AckWait(30*time.Second),
		nats.MaxAckPending(500),
	)
	if err != nil {
		return fmt.Errorf("js subscribe %s (stream=%s, durable=%s): %w", subject, stream, durableName, err)
	}

	c.subs = append(c.subs, sub)
	log.Info().
		Str("subject", subject).
		Str("stream", stream).
		Str("durable", durableName).
		Msg("Subscribed via JetStream")
	return nil
}

// Publish publishes a message to a subject using JetStream if available.
// Thread-safe: serialized via publishMu to prevent concurrent publish interleaving.
func (c *NATSClient) Publish(subject string, data []byte) error {
	c.publishMu.Lock()
	defer c.publishMu.Unlock()

	// Reply subjects (_INBOX.*) aren't covered by any JetStream stream filter,
	// so js.Publish would block waiting for an ACK that never arrives. Send
	// these through core NATS only.
	if strings.HasPrefix(subject, "_INBOX.") {
		return c.conn.Publish(subject, data)
	}

	// Use JetStream for guaranteed delivery if available
	if c.js != nil {
		// Use UUID for message ID to prevent collisions from concurrent publishes
		msgID := fmt.Sprintf("%s-%s", subject, uuid.New().String()[:12])
		ack, err := c.js.Publish(subject, data, nats.MsgId(msgID))
		if err != nil {
			log.Warn().Err(err).Str("subject", subject).Msg("JetStream publish failed, falling back to core NATS")
			return c.conn.Publish(subject, data)
		}
		log.Debug().
			Str("subject", subject).
			Str("stream", ack.Stream).
			Uint64("seq", ack.Sequence).
			Msg("Published via JetStream")
		return nil
	}

	// Fallback to core NATS
	return c.conn.Publish(subject, data)
}

// PublishDirect publishes using core NATS only (no JetStream).
// Use this for push notifications that need to reach raw NATS subscribers
// immediately, without going through JetStream stream storage.
func (c *NATSClient) PublishDirect(subject string, data []byte) error {
	c.publishMu.Lock()
	defer c.publishMu.Unlock()
	return c.conn.Publish(subject, data)
}

// Request sends a request and waits for a response
func (c *NATSClient) Request(subject string, data []byte, timeout time.Duration) ([]byte, error) {
	msg, err := c.conn.Request(subject, data, timeout)
	if err != nil {
		return nil, err
	}
	return msg.Data, nil
}

// Close closes the NATS connection
func (c *NATSClient) Close() {
	for _, sub := range c.subs {
		sub.Unsubscribe()
	}
	c.conn.Close()
}

// IsConnected returns true if connected to NATS
func (c *NATSClient) IsConnected() bool {
	return c.conn.IsConnected()
}

// Status returns the connection status
func (c *NATSClient) Status() string {
	switch c.conn.Status() {
	case nats.CONNECTED:
		return "connected"
	case nats.CONNECTING:
		return "connecting"
	case nats.RECONNECTING:
		return "reconnecting"
	case nats.DISCONNECTED:
		return "disconnected"
	case nats.CLOSED:
		return "closed"
	default:
		return "unknown"
	}
}
