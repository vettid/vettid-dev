package main

// Shared-action catalog. This is a NEW layer on top of the existing
// dispatch-root handler catalog (handler_catalog.go).
//
// Where the dispatch-root catalog answers "may this peer use my wallet
// handler at all", the action catalog defines specific *invocations* a
// peer can request from me — request a payment, share a field, delegate
// a vote — each with its own parameter schema, result schema, default
// auth mode, and per-peer enablement.
//
// The catalog is hard-coded in this enclave release. Hard cutover per
// release: the wire envelope carries an action_id + version; mismatches
// are rejected so the invoker's app can prompt for upgrade.

// ActionScope classifies what the action does in the owner's vault.
type ActionScope string

const (
	ActionScopeRead      ActionScope = "read"       // peer reads owner's data
	ActionScopeReadWrite ActionScope = "read-write" // peer mutates owner's data
	ActionScopePropose   ActionScope = "propose"    // peer proposes an act, owner decides
)

// ActionAuthMode controls who may invoke and how.
type ActionAuthMode string

const (
	// ActionAuthDefaultDeny: hidden until owner enables the action AND adds
	// the peer to its allowlist. Strict opt-in per peer.
	ActionAuthDefaultDeny ActionAuthMode = "default-deny"
	// ActionAuthAllowList: visible only to peers in the allowlist. Tap → run.
	ActionAuthAllowList ActionAuthMode = "allowlist"
	// ActionAuthPromptEachTime: visible to all enabled peers. Owner gets a
	// push notification for each invocation; nothing executes without an
	// explicit Approve.
	ActionAuthPromptEachTime ActionAuthMode = "prompt-each-time"
	// ActionAuthDefaultAllow: visible to all enabled peers. Auto-executes
	// (read-only by convention).
	ActionAuthDefaultAllow ActionAuthMode = "default-allow"
)

// ActionDef is a Phase-1 catalog entry. Param/Result schemas are JSON
// Schema 2020-12 documents stored as raw bytes — both sides validate.
type ActionDef struct {
	ID              string         `json:"id"`
	Version         int            `json:"version"`
	Label           string         `json:"label"`
	Description     string         `json:"description"`
	Icon            string         `json:"icon"`
	Scope           ActionScope    `json:"scope"`
	DefaultAuthMode ActionAuthMode `json:"default_auth_mode"`
	ParamSchema     string         `json:"param_schema"`
	ResultSchema    string         `json:"result_schema"`
}

// ActionCatalogVersion bumps any time we add, remove, or reshape an
// entry. The wire protocol returns this in ERR_ACTION_VERSION responses
// so the invoker knows whether their app's mirror is stale.
const ActionCatalogVersion = 1

// ActionCatalog returns every Phase-1 shareable action.
func ActionCatalog() []ActionDef {
	return []ActionDef{
		{
			ID: ActionIDProfileFieldsRead, Version: 1,
			Label:       "Share contact field",
			Description: "Share specific personal-data fields (phone, email, address) with this connection.",
			Icon:        "person_search",
			Scope:       ActionScopeRead, DefaultAuthMode: ActionAuthAllowList,
			ParamSchema: `{
				"$schema": "https://json-schema.org/draft/2020-12/schema",
				"type": "object",
				"required": ["field_ids"],
				"properties": {
					"field_ids": {
						"type": "array",
						"items": { "type": "string", "minLength": 1, "maxLength": 64 },
						"minItems": 1, "maxItems": 16
					}
				},
				"additionalProperties": false
			}`,
			ResultSchema: `{"type":"object","properties":{"values":{"type":"object"}},"required":["values"]}`,
		},
		{
			ID: ActionIDSecretsShare, Version: 1,
			Label:       "Share a secret",
			Description: "Share the plaintext of one of your stored secrets (wifi password, recovery code, etc).",
			Icon:        "key",
			Scope:       ActionScopeRead, DefaultAuthMode: ActionAuthPromptEachTime,
			ParamSchema: `{
				"type":"object","required":["secret_id"],
				"properties":{"secret_id":{"type":"string","minLength":1,"maxLength":64}},
				"additionalProperties": false
			}`,
			ResultSchema: `{"type":"object","properties":{"secret_id":{"type":"string"},"plaintext":{"type":"string"}},"required":["secret_id","plaintext"]}`,
		},
		{
			ID: ActionIDWalletRequestAddress, Version: 1,
			Label:       "Request payment address",
			Description: "Get this peer's next BTC receive address so you can pay them.",
			Icon:        "qr_code",
			Scope:       ActionScopeRead, DefaultAuthMode: ActionAuthDefaultAllow,
			ParamSchema: `{
				"type":"object",
				"properties":{"asset":{"type":"string","enum":["BTC"]}},
				"additionalProperties": false
			}`,
			ResultSchema: `{"type":"object","properties":{"address":{"type":"string"},"asset":{"type":"string"}},"required":["address","asset"]}`,
		},
		{
			ID: ActionIDWalletRequestPayment, Version: 1,
			Label:       "Request a payment",
			Description: "Ask this peer to send a BTC payment. They approve and broadcast manually.",
			Icon:        "request_quote",
			Scope:       ActionScopePropose, DefaultAuthMode: ActionAuthPromptEachTime,
			ParamSchema: `{
				"type":"object","required":["asset","amount_sats"],
				"properties":{
					"asset":{"type":"string","enum":["BTC"]},
					"amount_sats":{"type":"integer","minimum":1,"maximum":2100000000000000},
					"memo":{"type":"string","maxLength":280}
				},
				"additionalProperties": false
			}`,
			ResultSchema: `{"type":"object","properties":{"status":{"type":"string"},"prepared_tx_hex":{"type":"string"}},"required":["status"]}`,
		},
		{
			ID: ActionIDVoteDelegateProxy, Version: 1,
			Label:       "Delegate vote",
			Description: "Ask this peer to cast a proxy vote on a proposal on your behalf.",
			Icon:        "how_to_vote",
			Scope:       ActionScopePropose, DefaultAuthMode: ActionAuthPromptEachTime,
			ParamSchema: `{
				"type":"object","required":["proposal_id","choice"],
				"properties":{
					"proposal_id":{"type":"string","minLength":1,"maxLength":128},
					"choice":{"type":"string","minLength":1,"maxLength":64}
				},
				"additionalProperties": false
			}`,
			ResultSchema: `{"type":"object","properties":{"status":{"type":"string"},"voted_at":{"type":"string"}},"required":["status"]}`,
		},
		{
			ID: ActionIDConnectionHandoff, Version: 1,
			Label:       "Introduce me to a connection",
			Description: "Ask this peer to introduce you to one of their connections (peer-mediated invitation).",
			Icon:        "share",
			Scope:       ActionScopePropose, DefaultAuthMode: ActionAuthPromptEachTime,
			ParamSchema: `{
				"type":"object","required":["target_label","intro_message"],
				"properties":{
					"target_label":{"type":"string","minLength":1,"maxLength":80},
					"intro_message":{"type":"string","minLength":1,"maxLength":280}
				},
				"additionalProperties": false
			}`,
			ResultSchema: `{"type":"object","properties":{"status":{"type":"string"}},"required":["status"]}`,
		},
		{
			ID: ActionIDAuditRecent, Version: 1,
			Label:       "View recent activity",
			Description: "Let this peer see recent audit events you logged about them (their messages with you, etc).",
			Icon:        "history",
			Scope:       ActionScopeRead, DefaultAuthMode: ActionAuthAllowList,
			ParamSchema: `{
				"type":"object",
				"properties":{
					"since":{"type":"string"},
					"limit":{"type":"integer","minimum":1,"maximum":200}
				},
				"additionalProperties": false
			}`,
			ResultSchema: `{"type":"object","properties":{"events":{"type":"array"}},"required":["events"]}`,
		},
	}
}

// Phase-1 action IDs — typed constants so call sites don't carry typos.
const (
	ActionIDProfileFieldsRead    = "profile.fields.read"
	ActionIDSecretsShare         = "secrets.share"
	ActionIDWalletRequestAddress = "wallet.request-address"
	ActionIDWalletRequestPayment = "wallet.request-payment"
	ActionIDVoteDelegateProxy    = "vote.delegate-proxy"
	ActionIDConnectionHandoff    = "connection.handoff"
	ActionIDAuditRecent          = "audit.recent"
)

// ActionCatalogByID is the O(1) lookup used by the auth engine.
func ActionCatalogByID() map[string]ActionDef {
	all := ActionCatalog()
	m := make(map[string]ActionDef, len(all))
	for _, a := range all {
		m[a.ID] = a
	}
	return m
}

// LookupAction returns the catalog entry for an action ID.
func LookupAction(id string) (ActionDef, bool) {
	for _, a := range ActionCatalog() {
		if a.ID == id {
			return a, true
		}
	}
	return ActionDef{}, false
}

// PublishedAction is the wire shape that lands in PublishedProfile.Actions.
// The visibility filter (action_authorization.go canSeeActionOnPublishedProfile)
// determines which catalog entries reach which viewer.
type PublishedAction struct {
	ID              string         `json:"id"`
	Version         int            `json:"version"`
	Label           string         `json:"label"`
	Description     string         `json:"description"`
	Icon            string         `json:"icon"`
	Scope           ActionScope    `json:"scope"`
	AuthMode        ActionAuthMode `json:"auth_mode"`
	ParamSchema     string         `json:"param_schema"`
	ResultSchema    string         `json:"result_schema"`
	AvailableToMe   bool           `json:"available_to_me"`
}

// BuildPublishedActionsAdvert returns the actions[] slice published in
// the broadcast profile (read by every peer). Phase 1 includes all
// enabled actions with their auth_mode — viewers learn the action
// exists; the auth engine still rejects unauthorized invocations.
//
// For per-viewer narrowing (e.g. truly hidden allowlist entries) use
// BuildPublishedActionsFor with the specific viewerGUID.
//
// Free function so profile_builder.go can call it without depending on
// MessageHandler. Reads the persisted EnabledActionState directly.
func BuildPublishedActionsAdvert(storage *EncryptedStorage) []PublishedAction {
	if storage == nil {
		return nil
	}
	var st EnabledActionState
	if err := storage.GetJSON(enabledActionsKey, &st); err != nil {
		// No state yet → fall back to catalog defaults
		out := make([]PublishedAction, 0)
		for _, def := range ActionCatalog() {
			if def.DefaultAuthMode == ActionAuthDefaultDeny {
				continue
			}
			out = append(out, PublishedAction{
				ID: def.ID, Version: def.Version, Label: def.Label,
				Description: def.Description, Icon: def.Icon, Scope: def.Scope,
				AuthMode:     def.DefaultAuthMode,
				ParamSchema:  def.ParamSchema,
				ResultSchema: def.ResultSchema,
			})
		}
		return out
	}
	out := make([]PublishedAction, 0)
	for _, def := range ActionCatalog() {
		mode := def.DefaultAuthMode
		if ea := st.Actions[def.ID]; ea != nil {
			mode = ea.Mode
		}
		if mode == ActionAuthDefaultDeny {
			continue
		}
		out = append(out, PublishedAction{
			ID: def.ID, Version: def.Version, Label: def.Label,
			Description: def.Description, Icon: def.Icon, Scope: def.Scope,
			AuthMode:     mode,
			ParamSchema:  def.ParamSchema,
			ResultSchema: def.ResultSchema,
		})
	}
	return out
}

// BuildPublishedActionsFor returns the actions[] slice that goes into the
// owner's profile when read by `viewerGUID`. Hidden / non-allowlisted
// entries are stripped — viewers never learn they exist.
func (mh *MessageHandler) BuildPublishedActionsFor(viewerGUID string) []PublishedAction {
	if err := mh.ensureEnabledActions(); err != nil {
		return nil
	}
	state := mh.snapshotEnabledActions()
	out := make([]PublishedAction, 0)
	for _, def := range ActionCatalog() {
		if !mh.canSeeActionOnPublishedProfile(def.ID, viewerGUID) {
			continue
		}
		ea := state.Actions[def.ID]
		mode := def.DefaultAuthMode
		if ea != nil {
			mode = ea.Mode
		}
		out = append(out, PublishedAction{
			ID:            def.ID,
			Version:       def.Version,
			Label:         def.Label,
			Description:   def.Description,
			Icon:          def.Icon,
			Scope:         def.Scope,
			AuthMode:      mode,
			ParamSchema:   def.ParamSchema,
			ResultSchema:  def.ResultSchema,
			AvailableToMe: true,
		})
	}
	return out
}
