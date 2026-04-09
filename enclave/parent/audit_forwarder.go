package main

import (
	"context"
	"encoding/json"

	"github.com/rs/zerolog/log"
)

// persistAuditEvent forwards an audit event from the enclave to DynamoDB and NATS.
// This runs in a goroutine — audit persistence must not block the vsock response loop.
//
// Two destinations:
// 1. DynamoDB orgAudit table — persistent, queryable audit trail
// 2. NATS OrgAudit.{vault_id}.event — real-time streaming for demo UI
func (p *ParentProcess) persistAuditEvent(ctx context.Context, msg *EnclaveMessage) {
	if len(msg.Payload) == 0 {
		log.Warn().Msg("Received empty audit event payload")
		return
	}

	// Parse event to extract org_vault_id for NATS subject
	var event struct {
		OrgVaultID string `json:"org_vault_id"`
		EventID    string `json:"event_id"`
	}
	if err := json.Unmarshal(msg.Payload, &event); err != nil {
		log.Error().Err(err).Msg("Failed to parse audit event payload")
		return
	}

	log.Info().
		Str("event_id", event.EventID).
		Str("org_vault_id", event.OrgVaultID).
		Msg("Persisting audit event")

	// 1. Publish to NATS for real-time streaming
	if p.natsClient != nil && event.OrgVaultID != "" {
		subject := "OrgAudit." + event.OrgVaultID + ".event"
		if err := p.natsClient.Publish(subject, msg.Payload); err != nil {
			log.Warn().
				Err(err).
				Str("subject", subject).
				Msg("Failed to publish audit event to NATS (non-fatal)")
		} else {
			log.Debug().
				Str("subject", subject).
				Msg("Audit event published to NATS")
		}
	}

	// 2. Persist to DynamoDB orgAudit table for compliance queries
	if p.dynamoDBClient != nil {
		var eventMap map[string]interface{}
		if err := json.Unmarshal(msg.Payload, &eventMap); err != nil {
			log.Warn().Err(err).Msg("Failed to parse audit event for DynamoDB persistence")
		} else if err := p.dynamoDBClient.PutOrgAuditEvent(ctx, eventMap); err != nil {
			log.Warn().
				Err(err).
				Str("event_id", event.EventID).
				Msg("Failed to persist audit event to DynamoDB (non-fatal)")
		} else {
			log.Debug().
				Str("event_id", event.EventID).
				Msg("Audit event persisted to DynamoDB")
		}
	}
}
