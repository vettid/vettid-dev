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

// NATSClient wraps a NATS connection
type NATSClient struct {
	conn   *nats.Conn
	config NATSConfig
	subs   []*nats.Subscription
}

// NewNATSClient creates a new NATS client
func NewNATSClient(cfg NATSConfig) (*NATSClient, error) {
	// Build connection options
	opts := []nats.Option{
		nats.Name("vettid-enclave-parent"),
		nats.ReconnectWait(time.Duration(cfg.ReconnectWait) * time.Millisecond),
		nats.MaxReconnects(cfg.MaxReconnects),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			log.Warn().Err(err).Msg("NATS disconnected")
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Info().Str("url", nc.ConnectedUrl()).Msg("NATS reconnected")
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			log.Info().Msg("NATS connection closed")
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

	return &NATSClient{
		conn:   conn,
		config: cfg,
	}, nil
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

// Publish publishes a message to a subject
func (c *NATSClient) Publish(subject string, data []byte) error {
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
