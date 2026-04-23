package main

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// BuildPublishedProfile constructs the published profile from vault storage.
// This is the single source of truth for what a user shares publicly.
//
// Used by:
// - ProfileHandler.HandlePublish (publishing to NATS JetStream)
// - ProfileHandler.HandleGetPublished (returning to the app for preview)
// - ConnectionsHandler.loadPublishedProfileForPeer (sending to peers during connection)
//
// The vaultState parameter is optional — if provided, the identity public key
// is read from the credential in memory. If nil, it falls back to storage.
func BuildPublishedProfile(
	ownerSpace string,
	storage *EncryptedStorage,
	vaultState *VaultState,
) *PublishedProfile {
	profile := &PublishedProfile{
		UserGUID:      ownerSpace,
		EmailVerified: true,
		Fields:        make(map[string]PublishedField),
	}

	// --- Identity Public Key ---
	// Primary: from vaultState (in-memory credential after PIN unlock)
	// Fallback: from storage (persisted during enrollment)
	if vaultState != nil {
		vaultState.mu.RLock()
		if vaultState.credential != nil && vaultState.credential.IdentityPublicKey != nil {
			profile.PublicKey = base64.StdEncoding.EncodeToString(vaultState.credential.IdentityPublicKey)
		}
		vaultState.mu.RUnlock()
	}
	if profile.PublicKey == "" {
		// Try storage fallback
		if pkData, err := storage.Get("identity_public_key"); err == nil && len(pkData) > 0 {
			var pkStr string
			if json.Unmarshal(pkData, &pkStr) == nil && pkStr != "" {
				profile.PublicKey = pkStr
			} else if len(pkData) > 0 {
				profile.PublicKey = string(pkData)
			}
		}
	}

	// --- System Fields (always included from registration) ---
	systemFields := []string{"_system_first_name", "_system_last_name", "_system_email"}
	for _, field := range systemFields {
		data, err := storage.Get("profile/" + field)
		if err != nil {
			continue
		}
		var entry ProfileEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		switch field {
		case "_system_first_name":
			profile.FirstName = entry.Value
		case "_system_last_name":
			profile.LastName = entry.Value
		case "_system_email":
			profile.Email = entry.Value
		}
	}

	// --- Profile Photo ---
	if photoData, err := storage.Get("profile/_photo"); err == nil {
		var photoEntry ProfileEntry
		if json.Unmarshal(photoData, &photoEntry) == nil && photoEntry.Value != "" {
			profile.Photo = photoEntry.Value
		}
	}

	// --- Published Fields (from public profile settings) ---
	var settings PublicProfileSettings
	settingsData, err := storage.Get("profile/_public")
	if err == nil {
		json.Unmarshal(settingsData, &settings)
		profile.Version = settings.Version
		if settings.PublishedAt > 0 {
			profile.UpdatedAt = time.Unix(settings.PublishedAt, 0).Format(time.RFC3339)
		}

		for _, fieldName := range settings.Fields {
			data, err := storage.Get("profile/" + fieldName)
			if err != nil {
				data, err = storage.Get("personal-data/" + fieldName)
				if err != nil {
					continue
				}
			}

			// Try PersonalDataField format first
			var field PersonalDataField
			if err := json.Unmarshal(data, &field); err == nil && field.Value != "" {
				// Skip sensitive fields
				if field.IsSensitive {
					continue
				}
				displayName := field.DisplayName
				if displayName == "" || displayName == fieldName {
					displayName = displayNameFromNamespace(fieldName)
				}
				profile.Fields[fieldName] = PublishedField{
					DisplayName: displayName,
					Value:       field.Value,
					FieldType:   string(field.FieldType),
				}
				continue
			}

			// Fall back to ProfileEntry format
			var entry ProfileEntry
			if err := json.Unmarshal(data, &entry); err != nil || entry.Value == "" {
				continue
			}
			displayName := displayNameFromNamespace(fieldName)
			profile.Fields[fieldName] = PublishedField{
				DisplayName: displayName,
				Value:       entry.Value,
				FieldType:   string(FieldTypeText),
			}
		}
	}

	// --- Public Wallet Addresses ---
	if indexData, err := storage.Get(walletIndexKey); err == nil {
		var walletIDs []string
		if json.Unmarshal(indexData, &walletIDs) == nil {
			for _, walletID := range walletIDs {
				wData, err := storage.Get(walletStorageKey(walletID))
				if err != nil {
					continue
				}
				var wallet WalletRecord
				if json.Unmarshal(wData, &wallet) != nil || !wallet.IsPublic || wallet.IsArchived {
					continue
				}
				profile.Wallets = append(profile.Wallets, PublishedWallet{
					WalletID: wallet.WalletID,
					Label:    wallet.Label,
					Address:  wallet.Address,
					Network:  wallet.Network,
				})
			}
		}
	}

	// --- Handlers (vault capabilities) ---
	// Surfaced so peers see the same "Handlers" row in their
	// connection-preview card that the user sees in their own
	// public-profile preview. The set is whatever this enclave
	// version exposes — handleHandlersOperation in messages.go is
	// the source of truth.
	profile.Handlers = publishedHandlerList()

	// --- Public Secrets Metadata ---
	// Stored at profile/_public_secrets by profile.publish — the
	// app derives this list from MinorSecretsStore and sends it
	// along with the field selection when the user publishes. We
	// never persist secret values here, only metadata.
	if secretsData, err := storage.Get("profile/_public_secrets"); err == nil && len(secretsData) > 0 {
		var publicSecrets []PublishedSecretMetadata
		if json.Unmarshal(secretsData, &publicSecrets) == nil {
			profile.PublicSecrets = publicSecrets
		}
	}

	log.Debug().
		Str("owner_space", ownerSpace).
		Int("field_count", len(profile.Fields)).
		Int("wallet_count", len(profile.Wallets)).
		Bool("has_photo", profile.Photo != "").
		Bool("has_public_key", profile.PublicKey != "").
		Msg("Built published profile")

	return profile
}

// PublishedProfileToMap converts a PublishedProfile to the map format
// used by loadPublishedProfileForPeer (for connection invitations).
func PublishedProfileToMap(p *PublishedProfile) map[string]interface{} {
	result := make(map[string]interface{})

	// System fields as flat keys (matches existing connection flow expectations)
	if p.FirstName != "" {
		result["_system_first_name"] = p.FirstName
	}
	if p.LastName != "" {
		result["_system_last_name"] = p.LastName
	}
	if p.Email != "" {
		result["_system_email"] = p.Email
	}
	if p.PublicKey != "" {
		result["public_key"] = p.PublicKey
	}
	if p.Photo != "" {
		result["photo"] = p.Photo
	}
	if p.UserGUID != "" {
		result["user_guid"] = p.UserGUID
	}

	// Fields as nested object
	if len(p.Fields) > 0 {
		fields := make(map[string]interface{})
		for k, v := range p.Fields {
			fields[k] = map[string]string{
				"display_name": v.DisplayName,
				"value":        v.Value,
			}
		}
		result["fields"] = fields
	}

	// Wallets as array
	if len(p.Wallets) > 0 {
		var wallets []map[string]string
		for _, w := range p.Wallets {
			wallets = append(wallets, map[string]string{
				"wallet_id": w.WalletID,
				"label":     w.Label,
				"address":   w.Address,
				"network":   w.Network,
			})
		}
		result["wallets"] = wallets
	}

	// Handlers (vault capabilities) — surfaced so peers see the
	// same "Handlers" row the user sees on their own preview.
	if len(p.Handlers) > 0 {
		var handlers []map[string]interface{}
		for _, h := range p.Handlers {
			handlers = append(handlers, map[string]interface{}{
				"id":          h.ID,
				"name":        h.Name,
				"description": h.Description,
				"operations":  h.Operations,
			})
		}
		result["handlers"] = handlers
	}

	// Public secret metadata — names/types/categories only,
	// never values.
	if len(p.PublicSecrets) > 0 {
		var secrets []map[string]string
		for _, s := range p.PublicSecrets {
			secrets = append(secrets, map[string]string{
				"name":     s.Name,
				"type":     s.Type,
				"category": s.Category,
			})
		}
		result["public_secrets"] = secrets
	}

	return result
}

// publishedHandlerList returns the vault's static handler catalog in
// the published-profile shape. Source of truth for the list is
// handleHandlersOperation; this helper keeps the two lists aligned
// without re-running the NATS handler just to build a profile.
func publishedHandlerList() []PublishedHandler {
	return []PublishedHandler{
		{ID: "profile", Name: "Profile", Description: "Manage vault profile, sharing settings, and photos", Operations: []string{"get", "update", "delete", "get-shared", "sharing-settings", "categories", "public", "publish", "photo"}},
		{ID: "personal-data", Name: "Personal Data", Description: "Store and manage personal identity data", Operations: []string{"get", "update", "delete", "update-sort-order", "get-sort-order"}},
		{ID: "secrets", Name: "Secrets", Description: "Encrypted secret storage and identity keys", Operations: []string{"add", "update", "retrieve", "delete", "list", "identity"}},
		{ID: "credential", Name: "Credentials", Description: "Credential lifecycle management", Operations: []string{"create", "store", "sync", "get", "delete", "password-change", "secret", "version"}},
		{ID: "connection", Name: "Connections", Description: "Peer connection management", Operations: []string{"create-invite", "initiate", "respond", "revoke", "list", "get", "update", "rotate", "get-credentials", "get-capabilities", "activity-summary"}},
		{ID: "message", Name: "Messaging", Description: "Encrypted peer messaging", Operations: []string{"send", "read-receipt"}},
		{ID: "feed", Name: "Event Feed", Description: "Activity feed and event management", Operations: []string{"list", "get", "read", "archive", "delete", "sync", "settings", "action"}},
		{ID: "location", Name: "Location", Description: "Location tracking and sharing", Operations: []string{"add", "list", "delete", "delete-all"}},
		{ID: "vote", Name: "Voting", Description: "Vault-signed governance voting", Operations: []string{"cast", "list"}},
		{ID: "audit", Name: "Audit", Description: "Audit log queries and export", Operations: []string{"query", "export"}},
		{ID: "call", Name: "Calls", Description: "Voice and video call management", Operations: []string{"start", "accept", "reject", "end", "signal", "history"}},
		{ID: "invitation", Name: "Invitations", Description: "Connection invitation lifecycle", Operations: []string{"list", "cancel", "resend", "viewed"}},
		{ID: "capability", Name: "Capabilities", Description: "Peer capability negotiation", Operations: []string{"request", "respond", "get", "list"}},
		{ID: "settings", Name: "Settings", Description: "Notification preferences", Operations: []string{"notifications"}},
		{ID: "notification", Name: "Notifications", Description: "Push notification routing", Operations: []string{"profile-broadcast", "revoke-notify"}},
		{ID: "service", Name: "Services", Description: "B2C service connections and contracts", Operations: []string{"connection", "contract", "data", "request", "profile", "activity", "notifications", "trust"}},
		{ID: "datastore", Name: "Data Stores", Description: "Shared collaborative data stores", Operations: []string{"create", "join", "read", "write", "delete", "subscribe", "audit"}},
		{ID: "pin", Name: "Security", Description: "PIN and vault access management", Operations: []string{"setup", "unlock", "change"}},
		{ID: "agent-secrets", Name: "Agent Secrets", Description: "Manage secrets shared with AI agents", Operations: []string{"share", "update", "revoke", "list"}},
		{ID: "wallet", Name: "Bitcoin Wallets", Description: "HD wallet management and BTC transactions", Operations: []string{"create", "list", "detail", "get-balance", "get-address", "get-fees", "send", "send-to-connection", "request-payment", "get-history", "delete", "set-visibility"}},
	}
}
