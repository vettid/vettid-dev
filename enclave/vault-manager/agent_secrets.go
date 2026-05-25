package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// AgentSecretsHandler bridges agent-side catalog/get requests to the
// shared minor-secret storage that also backs the peer-facing profile
// catalog (see profile_builder.go buildSecretCatalog). Agents and peers
// share one visibility surface — each minor secret's Discoverability
// field decides whether it appears in any connection's catalog.
//
// Pre-2026-05-25 there was a parallel agent-secrets/{secret_id}
// namespace populated via agent-secrets.{share,update,revoke,list}
// ops. Those ops were never wired into the phone, so the namespace
// was permanently empty in practice. The whole concept has been
// removed — sharing is now an act of setting a minor secret's
// Discoverability to a non-private value via the existing
// secrets.update path.
type AgentSecretsHandler struct {
	ownerSpace   string
	storage      *EncryptedStorage
	eventHandler *EventHandler
}

// NewAgentSecretsHandler creates a new agent secrets handler.
func NewAgentSecretsHandler(ownerSpace string, storage *EncryptedStorage, eventHandler *EventHandler) *AgentSecretsHandler {
	return &AgentSecretsHandler{
		ownerSpace:   ownerSpace,
		storage:      storage,
		eventHandler: eventHandler,
	}
}

// AgentSharedSecret is the in-memory shape callers in agent_handler.go
// receive from GetSecret. Sourced from a SecretRecord in the main
// minor-secrets storage; AllowedActions is synthesized (every minor
// secret implicitly permits "retrieve"). Future per-secret action
// metadata can extend this; for now there's no per-secret allowlist.
type AgentSharedSecret struct {
	SecretID       string   `json:"secret_id"`
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	Description    string   `json:"description,omitempty"`
	Value          string   `json:"value"`
	AllowedActions []string `json:"allowed_actions"`
	UpdatedAt      string   `json:"updated_at"`
}

// AgentSecretCatalogEntry describes one secret in the agent's catalog.
// Mirrors CatalogedSecretItem (the peer-profile shape) plus a
// SecretID so the agent can request the value by reference.
type AgentSecretCatalogEntry struct {
	SecretID       string   `json:"secret_id"`
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	Description    string   `json:"description,omitempty"`
	AllowedActions []string `json:"allowed_actions"`
	UpdatedAt      string   `json:"updated_at,omitempty"`
}

// AgentSecretCatalog is the versioned catalog pushed to an agent.
// Version is now driven by storage state (sum of UpdatedAt across
// records would be ideal, but a per-build timestamp is sufficient
// for the "catalog changed; refetch" trigger the agent uses).
type AgentSecretCatalog struct {
	Entries   []AgentSecretCatalogEntry `json:"entries"`
	Version   uint64                    `json:"version"`
	UpdatedAt string                    `json:"updated_at"`
}

// GetSecret looks up a minor secret by ID and returns the agent-shaped
// view if it exists and is not Discoverability=private. Anything that
// would be hidden from the peer profile catalog is also hidden from
// agents — there is no separate "private to peers but visible to
// agents" axis.
func (h *AgentSecretsHandler) GetSecret(secretID string) (*AgentSharedSecret, error) {
	if secretID == "" {
		return nil, fmt.Errorf("secret_id is required")
	}

	indexData, err := h.storage.Get("secrets/_index")
	if err != nil {
		return nil, fmt.Errorf("secret not found: %s", secretID)
	}
	var keys []string
	if err := json.Unmarshal(indexData, &keys); err != nil {
		return nil, fmt.Errorf("read secrets index: %w", err)
	}

	for _, k := range keys {
		raw, err := h.storage.Get("secrets/" + k)
		if err != nil {
			continue
		}
		var rec SecretRecord
		if json.Unmarshal(raw, &rec) != nil {
			continue
		}
		if rec.ID != secretID {
			continue
		}
		if rec.Discoverability == DiscoverabilityPrivate {
			// Don't differentiate "private" from "not found" — leaking
			// the difference would let an agent enumerate IDs.
			return nil, fmt.Errorf("secret not found: %s", secretID)
		}
		return &AgentSharedSecret{
			SecretID:       rec.ID,
			Name:           rec.Name,
			Category:       rec.Category,
			Description:    rec.Description,
			Value:          rec.Value,
			AllowedActions: []string{"retrieve"},
			UpdatedAt:      time.Unix(rec.UpdatedAt, 0).UTC().Format(time.RFC3339),
		}, nil
	}

	return nil, fmt.Errorf("secret not found: %s", secretID)
}

// BuildCatalog enumerates every minor secret visible to peers (i.e.
// Discoverability != private) and returns the agent-shaped catalog.
// Capability gating (does the agent have secrets.catalog.read?) is
// the caller's responsibility — this function trusts that it should
// be running.
func (h *AgentSecretsHandler) BuildCatalog() *AgentSecretCatalog {
	entries := make([]AgentSecretCatalogEntry, 0)

	for _, rec := range MinorSecretRecords(h.storage) {
		if rec.Discoverability == DiscoverabilityPrivate {
			continue
		}
		entries = append(entries, AgentSecretCatalogEntry{
			SecretID:       rec.ID,
			Name:           rec.Name,
			Category:       rec.Category,
			Description:    rec.Description,
			AllowedActions: []string{"retrieve"},
		})
	}

	return &AgentSecretCatalog{
		Entries:   entries,
		Version:   uint64(time.Now().Unix()),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// HasAction reports whether a specific action is in the allowed-actions
// list for a secret. Kept for the agent_handler.go path that gates
// retrieve vs. use-with operations; future per-secret action allowlists
// will populate AllowedActions with more than just "retrieve".
func HasAction(action string, allowedActions []string) bool {
	for _, a := range allowedActions {
		if a == action {
			return true
		}
	}
	return false
}
