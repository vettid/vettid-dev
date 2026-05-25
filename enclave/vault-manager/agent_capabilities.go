package main

// Agent capability vocabulary.
//
// Contract.Scope holds capability tokens — what the agent is ALLOWED
// TO DO. This is distinct from sharing (what specific secrets are
// catalog-visible to it, which is gated globally by each item's
// Discoverability field on the user's profile catalog — see
// profile_builder.go buildSecretCatalog).
//
// Pre-2026-05-25 the same Scope slice was overloaded as a
// secret.Category allowlist; that conflation has been removed. Scope
// is now purely capability tokens.
//
// Pattern: <noun>.<verb> for ops, snake_case for the noun and verb.
// One token per distinct vault op-class the agent may invoke.

const (
	// CapSecretsCatalogRead lets the agent refresh / read the
	// profile catalog of secrets/wallets/keys the owner has made
	// catalog-visible. Does not gate access to individual values.
	CapSecretsCatalogRead = "secrets.catalog.read"

	// CapSecretsGet lets the agent request a specific secret value.
	// Every get still flows through the per-op approval gate
	// (always_ask / auto_within_contract).
	CapSecretsGet = "secrets.get"

	// CapSecretsAction lets the agent request use-with operations
	// against a secret (sign, derive, redirect, etc.) without ever
	// receiving the secret value itself. Subject to the same
	// approval gate as CapSecretsGet.
	CapSecretsAction = "secrets.action"

	// CapMessageSend lets the agent post messages to the owner via
	// agent.message (chat content and approval-request envelopes).
	CapMessageSend = "message.send"

	// CapMessageRecv lets the agent receive owner replies on the
	// forOwner.agent.<conn> subject. An agent without recv can
	// still send (push-only).
	CapMessageRecv = "message.recv"
)

// DefaultAgentCapabilities is the minimum useful capability set used
// when the owner approves a pair/extend without explicitly granting
// scope. Lets the agent read the catalog and request secret values /
// actions, and exchange messages. Does not pre-grant anything beyond
// what the user has already exposed via per-item Discoverability.
var DefaultAgentCapabilities = []string{
	CapSecretsCatalogRead,
	CapSecretsGet,
	CapSecretsAction,
	CapMessageSend,
	CapMessageRecv,
}

// HasCapability reports whether the connection's Contract grants the
// given capability token. A nil Contract or nil Scope denies; a
// Contract with an explicit Scope grants only the tokens it lists.
//
// Migration: agent connections that paired before the 2026-05-25
// scope refactor have category-name strings (e.g. "CREDIT_CARD") in
// Scope. Those don't match any capability constant, so every op
// HasCapability gates will be denied — the connection must be
// re-paired or the owner must edit Contract.Scope to capability
// tokens. Intentional: the new vocabulary is the supported one.
func HasCapability(scope []string, capability string) bool {
	for _, s := range scope {
		if s == capability {
			return true
		}
	}
	return false
}
