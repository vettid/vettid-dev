package main

// Handler classification catalog. This is the single source of truth for
// which forVault.* dispatch roots exist, what category they belong to,
// whether the user can disable them, and whether they may be exposed to
// peers. The catalog is immutable code shipped with the enclave — any
// change requires a new PCR0 hash. User toggles live in vault storage
// (see handler_authorization.go).

const (
	// HandlerCategorySystem handlers are required for vault function
	// (pin, credential, attestation, sealing). They bypass the gate
	// unconditionally so the user cannot brick their vault.
	HandlerCategorySystem = "system"

	// HandlerCategoryDefault handlers are enabled by default for new
	// vaults and power the connection experience (messaging, calls,
	// profile, btc, etc.). Users may disable any non-Required entry.
	HandlerCategoryDefault = "default"

	// HandlerCategoryOptional handlers are disabled by default for new
	// vaults. The user opts in (e.g. a future Ethereum handler).
	HandlerCategoryOptional = "optional"
)

// HandlerCatalogEntry describes a single dispatch root: its classification,
// whether the user can see it in the handler-management UI, and the
// operations it exposes. Surfaced=false entries exist purely so the gate
// can resolve internal dispatch roots (pin-setup, unseal, etc.) — they
// are never shown to the user or peers.
type HandlerCatalogEntry struct {
	ID          string   // dispatch root in messages.go (e.g. "wallet", "pin-setup")
	Name        string   // user-facing display name
	Description string   // user-facing description
	Operations  []string // sub-operations under this root
	Category    string   // HandlerCategory{System,Default,Optional}
	Required    bool     // owner cannot disable
	Shareable   bool     // may appear in published profile / per-connection grants
	Surfaced    bool     // included in handlers.list response and published profile
}

// HandlerCatalog returns every dispatch root the vault-manager understands.
// Keyed by ID (dispatch root) for O(1) gate lookups via HandlerCatalogByID.
func HandlerCatalog() []HandlerCatalogEntry {
	return []HandlerCatalogEntry{
		// --- User-surfaced default handlers (the 20 entries the user sees) ---
		{
			ID: "profile", Name: "Profile",
			Description: "Manage vault profile, sharing settings, and photos",
			Operations:  []string{"get", "update", "delete", "get-shared", "sharing-settings", "categories", "public", "publish", "photo"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "personal-data", Name: "Personal Data",
			Description: "Store and manage personal identity data",
			Operations:  []string{"get", "update", "delete", "update-sort-order", "get-sort-order"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "secrets", Name: "Secrets",
			Description: "Encrypted secret storage and identity keys",
			Operations:  []string{"add", "update", "retrieve", "delete", "list", "identity"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "credential", Name: "Credentials",
			Description: "Credential lifecycle management",
			Operations:  []string{"create", "store", "sync", "get", "delete", "password-change", "secret", "version"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "connection", Name: "Connections",
			Description: "Peer connection management",
			Operations:  []string{"create-invite", "initiate", "respond", "revoke", "list", "get", "update", "rotate", "get-credentials", "get-capabilities", "activity-summary"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "message", Name: "Messaging",
			Description: "Encrypted peer messaging",
			Operations:  []string{"send", "read-receipt"},
			Category:    HandlerCategoryDefault, Required: false, Shareable: true, Surfaced: true,
		},
		{
			ID: "feed", Name: "Event Feed",
			Description: "Activity feed and event management",
			Operations:  []string{"list", "get", "read", "archive", "delete", "sync", "settings", "action"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "location", Name: "Location",
			Description: "Location tracking and sharing",
			Operations:  []string{"add", "list", "delete", "delete-all"},
			Category:    HandlerCategoryDefault, Required: false, Shareable: true, Surfaced: true,
		},
		{
			ID: "vote", Name: "Voting",
			Description: "Vault-signed governance voting",
			Operations:  []string{"cast", "list"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "audit", Name: "Audit",
			Description: "Audit log queries and export",
			Operations:  []string{"query", "export"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "call", Name: "Calls",
			Description: "Voice and video call management",
			Operations:  []string{"start", "accept", "reject", "end", "signal", "history"},
			Category:    HandlerCategoryDefault, Required: false, Shareable: true, Surfaced: true,
		},
		{
			ID: "invitation", Name: "Invitations",
			Description: "Connection invitation lifecycle",
			Operations:  []string{"list", "cancel", "resend", "viewed"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "capability", Name: "Capabilities",
			Description: "Peer capability negotiation",
			Operations:  []string{"request", "respond", "get", "list"},
			Category:    HandlerCategoryDefault, Required: false, Shareable: true, Surfaced: true,
		},
		{
			ID: "settings", Name: "Settings",
			Description: "Notification preferences",
			Operations:  []string{"notifications"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "notification", Name: "Notifications",
			Description: "Push notification routing",
			Operations:  []string{"profile-broadcast", "revoke-notify"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "service", Name: "Services",
			Description: "B2C service connections and contracts",
			Operations:  []string{"connection", "contract", "data", "request", "profile", "activity", "notifications", "trust"},
			Category:    HandlerCategoryDefault, Required: false, Shareable: true, Surfaced: true,
		},
		{
			ID: "datastore", Name: "Data Stores",
			Description: "Shared collaborative data stores",
			Operations:  []string{"create", "join", "read", "write", "delete", "subscribe", "audit"},
			Category:    HandlerCategoryDefault, Required: false, Shareable: true, Surfaced: true,
		},
		{
			ID: "pin", Name: "Security",
			Description: "PIN and vault access management",
			Operations:  []string{"setup", "unlock", "change"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "agent-secrets", Name: "Agent Secrets",
			Description: "Manage secrets shared with AI agents",
			Operations:  []string{"share", "update", "revoke", "list"},
			Category:    HandlerCategoryDefault, Required: false, Shareable: false, Surfaced: true,
		},
		{
			ID: "wallet", Name: "Bitcoin Wallets",
			Description: "HD wallet management and BTC transactions",
			Operations:  []string{"create", "list", "detail", "get-balance", "get-address", "get-fees", "send", "send-to-connection", "request-payment", "get-history", "delete", "set-visibility"},
			Category:    HandlerCategoryDefault, Required: false, Shareable: true, Surfaced: true,
		},
		// --- User-surfaced default handlers added beyond the legacy list ---
		{
			ID: "presence", Name: "Online Presence",
			Description: "Opt-in online/offline signal to peers",
			Operations:  []string{"get", "set-default", "set-override"},
			Category:    HandlerCategoryDefault, Required: false, Shareable: true, Surfaced: true,
		},
		{
			ID: "agent", Name: "AI Agents",
			Description: "Manage AI agent connections",
			Operations:  []string{"approval", "list", "revoke", "info"},
			Category:    HandlerCategoryDefault, Required: false, Shareable: false, Surfaced: true,
		},
		{
			ID: "device", Name: "Devices",
			Description: "Desktop and secondary device pairing",
			Operations:  []string{"pair", "list", "revoke"},
			Category:    HandlerCategoryDefault, Required: false, Shareable: false, Surfaced: true,
		},
		{
			ID: "guide", Name: "Guide",
			Description: "Welcome and tutorial event sync",
			Operations:  []string{"list", "complete", "dismiss"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "block", Name: "Blocks",
			Description: "Block list management",
			Operations:  []string{"add", "remove", "list"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "enrollment", Name: "Enrollment",
			Description: "Identity mismatch reports and enrollment helpers",
			Operations:  []string{"identity-mismatch"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		{
			ID: "notifications", Name: "Notification Digest",
			Description: "Notification digest and aggregation",
			Operations:  []string{"digest"},
			Category:    HandlerCategorySystem, Required: true, Shareable: false, Surfaced: true,
		},
		// --- System-internal dispatch roots (not user-visible) ---
		// These exist so the gate's lookup table can resolve every root
		// the dispatcher recognises. They always bypass the gate.
		{ID: "app", Category: HandlerCategorySystem, Required: true},
		{ID: "bootstrap", Category: HandlerCategorySystem, Required: true},
		{ID: "vault", Category: HandlerCategorySystem, Required: true},
		{ID: "handlers", Category: HandlerCategorySystem, Required: true},
		{ID: "unseal", Category: HandlerCategorySystem, Required: true},
		{ID: "sign", Category: HandlerCategorySystem, Required: true},
		{ID: "pin-setup", Category: HandlerCategorySystem, Required: true},
		{ID: "pin-unlock", Category: HandlerCategorySystem, Required: true},
		{ID: "pin-change", Category: HandlerCategorySystem, Required: true},
	}
}

// HandlerCatalogByID returns the catalog as a map for O(1) gate lookups.
// Built once per call; callers in hot paths should hold the result.
func HandlerCatalogByID() map[string]HandlerCatalogEntry {
	out := make(map[string]HandlerCatalogEntry, len(HandlerCatalog()))
	for _, e := range HandlerCatalog() {
		out[e.ID] = e
	}
	return out
}

// SurfacedHandlerCatalog returns only the entries the user can manage and
// that may be surfaced in the handlers.list response.
func SurfacedHandlerCatalog() []HandlerCatalogEntry {
	all := HandlerCatalog()
	out := make([]HandlerCatalogEntry, 0, len(all))
	for _, e := range all {
		if e.Surfaced {
			out = append(out, e)
		}
	}
	return out
}
