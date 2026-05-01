package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// SharePolicy is the per-connection "what I share with this peer"
// authority. See vettid-dev/docs/SHARING-AND-CONTRACTS-PLAN.md §2.1.
//
// Storage key: connections/{connectionID}/_share_policy
//
// Phase 2 introduces this as the canonical store for handler grants
// and action allowlists. The legacy `handlers/_per_connection/{id}`
// blob is kept as a read-through fallback during the cutover, but
// every write goes through here.
type SharePolicy struct {
	Version   int                        `json:"version"`
	UpdatedAt int64                      `json:"updated_at"`
	Items     map[string]SharePolicyItem `json:"items"`
	Defaults  SharePolicyDefaults        `json:"defaults"`
}

type SharePolicyItem struct {
	Allowed          bool   `json:"allowed"`
	Tier             string `json:"tier,omitempty"`               // required | optional | on_demand | consent
	Retention        string `json:"retention,omitempty"`           // session | time_limited | until_revoked
	RateLimitPerHour int    `json:"rate_limit_per_hour,omitempty"`  // 0 = unlimited
	ExpiresAt        int64  `json:"expires_at,omitempty"`           // 0 = never
	RequiresApproval bool   `json:"requires_approval,omitempty"`
	Note             string `json:"note,omitempty"`
}

type SharePolicyDefaults struct {
	AllowPublishedProfile bool   `json:"allow_published_profile"`
	DefaultTier           string `json:"default_tier"`
	DefaultRetention      string `json:"default_retention"`
}

// Item key prefixes — keep them stringly-typed so a single map covers
// every shareable thing. Format: "<kind>:<id>".
const (
	SharePolicyKindData    = "data"    // personal-data field name
	SharePolicyKindSecret  = "secret"  // credential-secret entry id
	SharePolicyKindWallet  = "wallet"  // wallet record id
	SharePolicyKindHandler = "handler" // handler catalog id
	SharePolicyKindAction  = "action"  // action def id
	SharePolicyKindSetting = "setting" // setting:location | setting:presence
)

func sharePolicyKey(kind, id string) string {
	return kind + ":" + id
}

func sharePolicyStorageKey(connectionID string) string {
	return "connections/" + connectionID + "/_share_policy"
}

// loadSharePolicy returns the policy for a connection, or nil if none
// is set. Callers handling nil should fall through to legacy paths.
func loadSharePolicy(storage *EncryptedStorage, connectionID string) *SharePolicy {
	data, err := storage.Get(sharePolicyStorageKey(connectionID))
	if err != nil || len(data) == 0 {
		return nil
	}
	var p SharePolicy
	if json.Unmarshal(data, &p) != nil {
		return nil
	}
	return &p
}

func saveSharePolicy(storage *EncryptedStorage, connectionID string, p *SharePolicy) error {
	if p == nil {
		return fmt.Errorf("policy is nil")
	}
	p.UpdatedAt = time.Now().Unix()
	if p.Version == 0 {
		p.Version = 1
	}
	if p.Items == nil {
		p.Items = make(map[string]SharePolicyItem)
	}
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return storage.Put(sharePolicyStorageKey(connectionID), data)
}

// defaultSharePolicy builds the seed policy used when a connection
// activates. Per the plan: only published-profile fields are allowed
// out of the box; everything else is default-deny.
func defaultSharePolicy() *SharePolicy {
	return &SharePolicy{
		Version:   1,
		UpdatedAt: time.Now().Unix(),
		Items:     make(map[string]SharePolicyItem),
		Defaults: SharePolicyDefaults{
			AllowPublishedProfile: true,
			DefaultTier:           "consent",
			DefaultRetention:      "session",
		},
	}
}

// IsItemAllowed answers the per-connection "may this peer access X?"
// question with the policy's full ladder applied:
//
//  1. Explicit deny (item present, allowed=false) wins.
//  2. Expired items are denied.
//  3. Explicit allow (item present, allowed=true) returns true.
//  4. Items not present fall back to the published-profile default
//     for system fields, otherwise default-deny.
//
// `kind` is one of the SharePolicyKind* constants. `id` is the item's
// catalog identifier (e.g. "wallet" handler ID, "contact.email" data
// name, etc.).
func (p *SharePolicy) IsItemAllowed(kind, id string) bool {
	if p == nil {
		return false
	}
	key := sharePolicyKey(kind, id)
	if item, ok := p.Items[key]; ok {
		if item.ExpiresAt > 0 && item.ExpiresAt < time.Now().Unix() {
			return false
		}
		return item.Allowed
	}
	// Default rules: only published-profile system fields fall back to
	// allow when AllowPublishedProfile is on. Everything else is deny.
	if p.Defaults.AllowPublishedProfile && kind == SharePolicyKindData && isPublishedProfileSystemField(id) {
		return true
	}
	return false
}

// isPublishedProfileSystemField captures the "always-shared" calling-
// card set the broadcast profile already exposes. Anything not in
// here defaults to deny — explicit opt-in required.
func isPublishedProfileSystemField(name string) bool {
	switch name {
	case "_system_first_name", "_system_last_name", "_system_email",
		"public_key", "photo":
		return true
	}
	return false
}

// SeedDefaultSharePolicy writes a default policy ONLY if none exists
// already. Idempotent — safe to call from both the inviter and the
// scanner activation paths.
func SeedDefaultSharePolicy(storage *EncryptedStorage, connectionID string) {
	if existing := loadSharePolicy(storage, connectionID); existing != nil {
		return
	}
	if err := saveSharePolicy(storage, connectionID, defaultSharePolicy()); err != nil {
		log.Warn().Err(err).Str("connection_id", connectionID).Msg("SeedDefaultSharePolicy failed (non-fatal)")
	}
}

// ClearSharePolicy removes the policy when a connection is revoked /
// expired so storage doesn't accumulate orphans.
func ClearSharePolicy(storage *EncryptedStorage, connectionID string) {
	_ = storage.Delete(sharePolicyStorageKey(connectionID))
}

// MergePolicyItems applies a partial set of items to the stored
// policy, overwriting any that match by key. Used by share-policy.set
// to support both "replace this one row" and "replace many" without
// the caller having to read-modify-write themselves.
func MergePolicyItems(storage *EncryptedStorage, connectionID string, items map[string]SharePolicyItem) error {
	p := loadSharePolicy(storage, connectionID)
	if p == nil {
		p = defaultSharePolicy()
	}
	for k, v := range items {
		// Reject malformed keys early.
		if !strings.Contains(k, ":") {
			return fmt.Errorf("invalid policy key: %s", k)
		}
		p.Items[k] = v
	}
	return saveSharePolicy(storage, connectionID, p)
}
