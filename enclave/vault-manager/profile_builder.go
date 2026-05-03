package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
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
	// public-profile preview. Filtered against the user's
	// handlers/_state — only entries the user has enabled AND
	// elected to share globally appear. Per-connection grants
	// narrow further at peer-message dispatch (see gateOperation).
	profile.Handlers = buildPublishedHandlerList(storage)

	// --- Actions (shareable invocations, Phase 1) ---
	// New layer on top of Handlers: specific verbs the peer can invoke
	// (request payment, share field, delegate vote). Default-deny
	// entries are hidden from the broadcast profile; allowlist entries
	// are advertised but the auth engine rejects unauthorised invokes.
	profile.Actions = BuildPublishedActionsAdvert(storage)

	// --- Public Secrets Metadata (legacy) ---
	// Stored at profile/_public_secrets by profile.publish — kept for
	// backwards compat with older app builds; new clients should read
	// SecretCatalog instead.
	if secretsData, err := storage.Get("profile/_public_secrets"); err == nil && len(secretsData) > 0 {
		var publicSecrets []PublishedSecretMetadata
		if json.Unmarshal(secretsData, &publicSecrets) == nil {
			profile.PublicSecrets = publicSecrets
		}
	}

	// --- Data Catalog (every personal-data item the user has stored,
	//     metadata only, excluding entries flagged Private) ---
	// Peers browse this to know what kinds of data the user holds and
	// can request values via the capability flow. Values never appear.
	profile.DataCatalog = buildDataCatalog(storage)
	_ = vaultState // keep reference; used by secret-catalog below

	// --- Secret Catalog (every secret entry, metadata only,
	//     excluding entries flagged Private) ---
	// Same model as DataCatalog: peers see "Al has a credit card
	// called Personal Visa" and can request access; the value stays
	// behind the credential blob.
	profile.SecretCatalog = buildSecretCatalog(storage, vaultState)

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
				"category":    h.Category,
				"required":    h.Required,
				"shareable":   h.Shareable,
			})
		}
		result["handlers"] = handlers
	}

	// Public secret metadata (legacy — kept for older app builds that
	// haven't picked up SecretCatalog yet).
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

	if len(p.DataCatalog) > 0 {
		// Preserve alias on the wire — without it, two entries that
		// share a namespace ("contact.family.phone::Wife" vs "::Daughter")
		// arrive at the peer as visually identical rows. Use map[string]any
		// (not map[string]string) so empty fields can simply be absent.
		var items []map[string]any
		for _, d := range p.DataCatalog {
			row := map[string]any{
				"name":         d.Name,
				"display_name": d.DisplayName,
				"field_type":   d.FieldType,
			}
			if d.Category != "" {
				row["category"] = d.Category
			}
			if d.Alias != "" {
				row["alias"] = d.Alias
			}
			items = append(items, row)
		}
		result["data_catalog"] = items
	}

	if len(p.SecretCatalog) > 0 {
		var items []map[string]any
		for _, s := range p.SecretCatalog {
			row := map[string]any{
				"name": s.Name,
				"type": s.Type,
			}
			if s.Category != "" {
				row["category"] = s.Category
			}
			items = append(items, row)
		}
		result["secret_catalog"] = items
	}

	return result
}

// buildPublishedHandlerList returns the discovery surface for vault
// handlers — every handler that's both Surfaced (user-visible in the
// catalog) AND Shareable (declared as something a peer could
// legitimately invoke). Discovery is intentionally decoupled from
// the actual invocation gate: a peer seeing wallet in this list can
// know "Al's vault supports BTC", but whether they can actually call
// any wallet op still goes through gateOperation (enabled +
// share_globally + per-connection grant). Keeping discovery broad
// lets users see what's possible without needing to flip every
// toggle just to make the catalog visible.
func buildPublishedHandlerList(storage *EncryptedStorage) []PublishedHandler {
	out := make([]PublishedHandler, 0)
	for _, entry := range HandlerCatalog() {
		if !entry.Surfaced || !entry.Shareable {
			continue
		}
		out = append(out, PublishedHandler{
			ID:          entry.ID,
			Name:        entry.Name,
			Description: entry.Description,
			Operations:  entry.Operations,
			Category:    entry.Category,
			Required:    entry.Required,
			Shareable:   entry.Shareable,
		})
	}
	return out
}

// buildDataCatalog enumerates every personal-data field the user has
// stored and returns metadata-only entries. Items flagged
// Discoverability=private are excluded; everything else (public,
// cataloged, or unset — which defaults to cataloged) appears so
// peers can see "Al has a Mobile Phone" and request the value
// through the capability flow.
func buildDataCatalog(storage *EncryptedStorage) []CatalogedDataItem {
	if storage == nil {
		return nil
	}
	// Union the two indexes the personal-data system writes to —
	// older fields landed in profile/_index, newer ones in
	// personal-data/_index, and both are still active sources of
	// truth (see profile.HandleGet for the same union pattern).
	fieldNames := make(map[string]bool)
	for _, key := range []string{"profile/_index", "personal-data/_index"} {
		if data, err := storage.Get(key); err == nil && len(data) > 0 {
			var names []string
			if json.Unmarshal(data, &names) == nil {
				for _, n := range names {
					fieldNames[n] = true
				}
			}
		}
	}
	out := make([]CatalogedDataItem, 0, len(fieldNames))
	for name := range fieldNames {
		// Internal bookkeeping (timestamps, verification flags) is
		// system-only and stays out of the catalog. The user-visible
		// name + email values stored under `_system_first_name` etc.
		// DO surface here as Identity/Contact rows so the catalog is
		// the complete inventory of everything not marked private.
		if name == "_system_stored_at" || name == "_system_email_verified" {
			continue
		}
		// Try profile/<name> first (legacy) then personal-data/<name>.
		var data []byte
		var err error
		data, err = storage.Get("profile/" + name)
		if err != nil {
			data, err = storage.Get("personal-data/" + name)
			if err != nil {
				continue
			}
		}
		// PersonalDataField is the modern shape; ProfileEntry is the
		// older form and has no discoverability — treat as cataloged.
		var pdf PersonalDataField
		if err := json.Unmarshal(data, &pdf); err == nil && pdf.Name != "" {
			if pdf.Discoverability == DiscoverabilityPrivate {
				continue
			}
			out = append(out, CatalogedDataItem{
				Name:        pdf.Name,
				DisplayName: pdf.DisplayName,
				FieldType:   string(pdf.FieldType),
				Category:    pdf.Category,
				Alias:       pdf.Alias,
			})
			continue
		}
		// Personal-data path stores PersonalDataEntry. The `name` we
		// iterate is the composite fieldKey ("namespace::alias" or
		// plain namespace) — split it for display purposes so peers
		// see "Phone — Wife" / "Phone — Daughter" with proper names
		// even when the index entry is composite.
		var pde PersonalDataEntry
		_ = json.Unmarshal(data, &pde)
		ns, aliasFromKey := splitFieldKey(name)
		alias := pde.Alias
		if alias == "" {
			alias = aliasFromKey
		}
		nameForDisplay := pde.Namespace
		if nameForDisplay == "" {
			nameForDisplay = ns
		}
		out = append(out, CatalogedDataItem{
			Name:        nameForDisplay,
			DisplayName: displayNameFromNamespace(nameForDisplay),
			FieldType:   string(FieldTypeText),
			Category:    categoryFromNamespace(nameForDisplay),
			Alias:       alias,
		})
	}
	return out
}

// categoryFromNamespace maps a personal-data namespace to its
// display-side category (Identity, Contact, Family, Address, etc.)
// so catalog rows always carry a category — without this, peers and
// the owner's own preview see family/address/contact rows leak into
// the catch-all "Other" bucket.
func categoryFromNamespace(namespace string) string {
	switch namespace {
	case "_system_first_name", "_system_last_name":
		return "Identity"
	case "_system_email":
		return "Contact"
	}
	switch {
	case strings.HasPrefix(namespace, "personal.legal"),
		strings.HasPrefix(namespace, "personal.info"),
		strings.HasPrefix(namespace, "identity."):
		return "Identity"
	case strings.HasPrefix(namespace, "contact.family."):
		return "Family"
	case strings.HasPrefix(namespace, "contact."),
		strings.HasPrefix(namespace, "social."):
		return "Contact"
	case strings.HasPrefix(namespace, "address."):
		return "Address"
	case strings.HasPrefix(namespace, "financial."):
		return "Financial"
	case strings.HasPrefix(namespace, "medical."):
		return "Medical"
	case strings.HasPrefix(namespace, "professional."):
		return "Professional"
	case strings.HasPrefix(namespace, "education."):
		return "Education"
	case strings.HasPrefix(namespace, "vehicle."):
		return "Vehicle"
	case strings.HasPrefix(namespace, "legal."):
		return "Legal"
	case strings.HasPrefix(namespace, "digital."):
		return "Digital"
	case strings.HasPrefix(namespace, "travel."):
		return "Travel"
	case strings.HasPrefix(namespace, "membership."):
		return "Membership"
	case strings.HasPrefix(namespace, "property."):
		return "Property"
	default:
		return "Other"
	}
}

// buildSecretCatalog enumerates the user's "what I have" inventory:
//
//   1. Every credential secret in the metadata index (seed phrases,
//      private keys, etc.). Values stay sealed in the credential
//      blob; only the metadata row is shareable with peers.
//   2. Every active wallet — including ones whose seed has been
//      moved to the credential. The seed and the wallet itself are
//      separate things from a peer's perspective: peers care about
//      the wallet's public address, not the seed. Listing them
//      together gives an accurate "what I can share" view.
//   3. Every credential crypto key (ETH address, BTC pubkey, etc.).
//      The private half stays sealed; only the label/type and
//      public material are surfaced as catalog metadata.
//
// Items flagged Discoverability=private are excluded.
func buildSecretCatalog(storage *EncryptedStorage, vaultState *VaultState) []CatalogedSecretItem {
	if storage == nil {
		return nil
	}
	out := make([]CatalogedSecretItem, 0)

	if data, err := storage.Get("credential-secrets/_metadata"); err == nil && len(data) > 0 {
		var records []SecretMetadataRecord
		if err := json.Unmarshal(data, &records); err == nil {
			for _, r := range records {
				if r.Discoverability == DiscoverabilityPrivate {
					continue
				}
				out = append(out, CatalogedSecretItem{
					Name:     r.Name,
					Type:     r.Category,
					Category: "Critical Secret",
				})
			}
		}
	}

	// Minor secrets — vault-stored, retrievable without a password
	// re-prompt. Same catalog visibility rules apply (private hides
	// metadata; cataloged/public show name + category to peers).
	for _, m := range MinorSecretRecords(storage) {
		if m.Discoverability == DiscoverabilityPrivate {
			continue
		}
		category := m.Category
		if category == "" {
			category = "Secret"
		}
		out = append(out, CatalogedSecretItem{
			Name:     m.Name,
			Type:     m.Type,
			Category: category,
		})
	}

	if ids, err := storage.GetIndex("wallets/_index"); err == nil {
		for _, id := range ids {
			data, err := storage.Get("wallets/" + id)
			if err != nil {
				continue
			}
			var w WalletRecord
			if err := json.Unmarshal(data, &w); err != nil {
				continue
			}
			if w.IsArchived {
				continue
			}
			label := w.Label
			if label == "" {
				label = "BTC Wallet"
			}
			out = append(out, CatalogedSecretItem{
				Name:     label,
				Type:     "BTC_WALLET",
				Category: "Cryptocurrency",
			})
		}
	}

	// Credential crypto keys (ETH address, BTC pubkey, signing key,
	// etc.) live inside the in-memory credential blob — surface each
	// as its own row so peers see the full key inventory. Only the
	// label/type travel; the private material stays sealed.
	if vaultState != nil {
		vaultState.mu.RLock()
		credential := vaultState.credential
		vaultState.mu.RUnlock()
		if credential != nil {
			for _, k := range credential.CryptoKeys {
				label := k.Label
				if label == "" {
					label = string(k.Type)
				}
				if label == "" {
					continue
				}
				out = append(out, CatalogedSecretItem{
					Name:     label,
					Type:     string(k.Type),
					Category: "Crypto Key",
				})
			}
		}
	}

	return out
}

// isSystemFieldName recognises the registration-supplied fields that
// already render on the calling card. These don't need duplicate
// catalog entries.
func isSystemFieldName(name string) bool {
	switch name {
	case "_system_first_name", "_system_last_name", "_system_email",
		"_system_stored_at", "_system_email_verified":
		return true
	}
	return false
}
