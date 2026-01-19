package main

import (
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
)

// NATSMessage represents a message received from NATS
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
	}

	return client, nil
}

// ensureEnrollmentStream creates or updates the stream for enrollment responses
func (c *NATSClient) ensureEnrollmentStream() error {
	if c.js == nil {
		return fmt.Errorf("JetStream not available")
	}

	streamName := "ENROLLMENT"
	subjects := []string{
		"OwnerSpace.*.forApp.>",      // Mobile app responses
		"OwnerSpace.*.forVault.>",    // Vault requests (for persistence)
	}

	// Check if stream exists
	stream, err := c.js.StreamInfo(streamName)
	if err == nil {
		log.Debug().Str("stream", streamName).Int64("messages", int64(stream.State.Msgs)).Msg("Enrollment stream exists")
		return nil
	}

	// Create stream with guaranteed delivery semantics
	//
	// Config rationale:
	// - LimitsPolicy: Keep messages until limits, allowing replay if needed
	// - FileStorage: Survive NATS restarts (critical enrollment data)
	// - 30 min MaxAge: App may go to background, need time to reconnect
	// - Dedup window prevents duplicate publishes from retries
	_, err = c.js.AddStream(&nats.StreamConfig{
		Name:       streamName,
		Subjects:   subjects,
		Retention:  nats.LimitsPolicy,       // Keep until limits (MaxAge/MaxMsgs)
		MaxAge:     30 * time.Minute,        // Messages expire after 30 min
		Storage:    nats.FileStorage,        // Persist to disk for durability
		Replicas:   1,                       // Single replica (increase for HA)
		Discard:    nats.DiscardOld,         // Drop oldest when full
		MaxMsgs:    10000,                   // Reasonable limit for enrollment
		MaxBytes:   100 * 1024 * 1024,       // 100MB max storage
		Duplicates: 5 * time.Minute,         // Dedup window for retries
	})
	if err != nil {
		return fmt.Errorf("failed to create enrollment stream: %w", err)
	}

	log.Info().Str("stream", streamName).Strs("subjects", subjects).Msg("Created enrollment stream")
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

// Publish publishes a message to a subject using JetStream if available
func (c *NATSClient) Publish(subject string, data []byte) error {
	// Use JetStream for guaranteed delivery if available
	if c.js != nil {
		ack, err := c.js.Publish(subject, data, nats.MsgId(fmt.Sprintf("%s-%d", subject, time.Now().UnixNano())))
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
