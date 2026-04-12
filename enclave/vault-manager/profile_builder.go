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

	return result
}
