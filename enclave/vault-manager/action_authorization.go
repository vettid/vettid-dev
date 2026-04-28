package main

import (
	"fmt"
	"sync"
	"time"
)

// Per-vault enabled-action store. Sits beside handler_authorization.go
// (the existing dispatch-root gate) but governs the new shared-action
// layer: which actions the owner has turned on, what auth mode applies,
// and — for AllowList / DefaultDeny modes — which peers may invoke.
//
// Storage key: actions/_enabled (JSON, encrypted via EncryptedStorage).

const enabledActionsKey = "actions/_enabled"

// EnabledAction is the per-action owner choice. Mode overrides the
// catalog's DefaultAuthMode. Allowlist applies only when Mode is
// AllowList or DefaultDeny. OwnerParams is the owner's hard cap on what
// the action may return — e.g. for profile.fields.read it's the set of
// field IDs the owner has flagged shareable; the per-invocation params
// can only narrow further.
type EnabledAction struct {
	ID          string                 `json:"id"`
	Mode        ActionAuthMode         `json:"mode"`
	Allowlist   []string               `json:"allowlist,omitempty"`   // peer user_guids
	OwnerParams map[string]interface{} `json:"owner_params,omitempty"`
	UpdatedAt   int64                  `json:"updated_at"`
}

// EnabledActionState is the persisted top-level blob.
type EnabledActionState struct {
	Version   int                       `json:"version"`
	Actions   map[string]*EnabledAction `json:"actions"`
	UpdatedAt int64                     `json:"updated_at"`
}

// actionAuthMu guards the in-memory cache. Persistence calls go through
// EncryptedStorage which is itself thread-safe.
var actionAuthMu sync.RWMutex

// loadEnabledActionsLocked reads actions/_enabled, materialising defaults
// from the catalog on first call. Caller holds actionAuthMu for write.
func (mh *MessageHandler) loadEnabledActionsLocked() error {
	if mh.storage == nil {
		return fmt.Errorf("storage not initialized")
	}
	var st EnabledActionState
	err := mh.storage.GetJSON(enabledActionsKey, &st)
	if err == ErrKeyNotFound {
		st = defaultEnabledActionState()
		if perr := mh.storage.PutJSON(enabledActionsKey, &st); perr != nil {
			return fmt.Errorf("persist default enabled actions: %w", perr)
		}
	} else if err != nil {
		return fmt.Errorf("read enabled actions: %w", err)
	}
	if st.Actions == nil {
		st.Actions = map[string]*EnabledAction{}
	}
	// Reconcile: catalog may have grown since the blob was last written.
	dirty := false
	for _, def := range ActionCatalog() {
		if _, ok := st.Actions[def.ID]; ok {
			continue
		}
		st.Actions[def.ID] = &EnabledAction{
			ID:        def.ID,
			Mode:      def.DefaultAuthMode,
			UpdatedAt: time.Now().Unix(),
		}
		dirty = true
	}
	if dirty {
		st.UpdatedAt = time.Now().Unix()
		_ = mh.storage.PutJSON(enabledActionsKey, &st)
	}
	mh.enabledActions = &st
	return nil
}

func defaultEnabledActionState() EnabledActionState {
	st := EnabledActionState{
		Version:   1,
		Actions:   map[string]*EnabledAction{},
		UpdatedAt: time.Now().Unix(),
	}
	for _, def := range ActionCatalog() {
		st.Actions[def.ID] = &EnabledAction{
			ID:        def.ID,
			Mode:      def.DefaultAuthMode,
			UpdatedAt: time.Now().Unix(),
		}
	}
	return st
}

// snapshotEnabledActions returns a deep-copied state for read paths.
func (mh *MessageHandler) snapshotEnabledActions() EnabledActionState {
	actionAuthMu.RLock()
	defer actionAuthMu.RUnlock()
	if mh.enabledActions == nil {
		return defaultEnabledActionState()
	}
	out := EnabledActionState{
		Version:   mh.enabledActions.Version,
		Actions:   make(map[string]*EnabledAction, len(mh.enabledActions.Actions)),
		UpdatedAt: mh.enabledActions.UpdatedAt,
	}
	for k, v := range mh.enabledActions.Actions {
		copyAllow := append([]string(nil), v.Allowlist...)
		copyParams := map[string]interface{}{}
		for pk, pv := range v.OwnerParams {
			copyParams[pk] = pv
		}
		out.Actions[k] = &EnabledAction{
			ID:          v.ID,
			Mode:        v.Mode,
			Allowlist:   copyAllow,
			OwnerParams: copyParams,
			UpdatedAt:   v.UpdatedAt,
		}
	}
	return out
}

// setActionConfig is the single mutator used by the app-facing
// `action.set-enabled` operation. Validates against the catalog, writes
// through to storage, refreshes cache.
func (mh *MessageHandler) setActionConfig(id string, mode ActionAuthMode, allowlist []string, ownerParams map[string]interface{}) error {
	if _, ok := LookupAction(id); !ok {
		return fmt.Errorf("unknown action: %s", id)
	}
	switch mode {
	case ActionAuthDefaultDeny, ActionAuthAllowList, ActionAuthPromptEachTime, ActionAuthDefaultAllow:
	default:
		return fmt.Errorf("invalid auth mode: %s", mode)
	}

	actionAuthMu.Lock()
	defer actionAuthMu.Unlock()
	if mh.enabledActions == nil {
		if err := mh.loadEnabledActionsLocked(); err != nil {
			return err
		}
	}
	mh.enabledActions.Actions[id] = &EnabledAction{
		ID:          id,
		Mode:        mode,
		Allowlist:   append([]string(nil), allowlist...),
		OwnerParams: ownerParams,
		UpdatedAt:   time.Now().Unix(),
	}
	mh.enabledActions.UpdatedAt = time.Now().Unix()
	return mh.storage.PutJSON(enabledActionsKey, mh.enabledActions)
}

// ensureEnabledActions hydrates the cache from storage if needed.
// Called from any path that needs to read/write the state.
func (mh *MessageHandler) ensureEnabledActions() error {
	actionAuthMu.RLock()
	loaded := mh.enabledActions != nil
	actionAuthMu.RUnlock()
	if loaded {
		return nil
	}
	actionAuthMu.Lock()
	defer actionAuthMu.Unlock()
	if mh.enabledActions == nil {
		return mh.loadEnabledActionsLocked()
	}
	return nil
}

// resolveActionForInvoke combines the catalog entry, the owner's stored
// EnabledAction, and the invoker's user_guid into the effective Mode +
// Allowlist used by the auth engine. Returns ErrActionNotEnabled when
// the action is disabled (mode == DefaultDeny and the invoker is NOT in
// allowlist) so the caller can return a clean error.
func (mh *MessageHandler) resolveActionForInvoke(actionID, invokerGUID string) (ActionDef, *EnabledAction, error) {
	def, ok := LookupAction(actionID)
	if !ok {
		return ActionDef{}, nil, fmt.Errorf("ERR_ACTION_UNKNOWN: %s", actionID)
	}
	if err := mh.ensureEnabledActions(); err != nil {
		return def, nil, err
	}
	actionAuthMu.RLock()
	ea := mh.enabledActions.Actions[actionID]
	actionAuthMu.RUnlock()
	if ea == nil {
		// New catalog entry the persisted state didn't seed yet — fall
		// back to the catalog default.
		ea = &EnabledAction{ID: def.ID, Mode: def.DefaultAuthMode}
	}
	mode := ea.Mode
	if mode == ActionAuthDefaultDeny {
		if !actionAllowlistContains(ea.Allowlist, invokerGUID) {
			return def, ea, fmt.Errorf("ERR_ACTION_DISABLED: %s", actionID)
		}
		// DefaultDeny + on the allowlist behaves like AllowList: visible
		// and invokable.
		mode = ActionAuthAllowList
	}
	if mode == ActionAuthAllowList && !actionAllowlistContains(ea.Allowlist, invokerGUID) {
		return def, ea, fmt.Errorf("ERR_NOT_AUTHORIZED: %s not in allowlist", actionID)
	}
	return def, ea, nil
}

// canSeeActionOnPublishedProfile is the visibility filter applied when
// building the published profile read by `viewerGUID`. Returns true when
// the action should appear in the profile's `actions[]`.
func (mh *MessageHandler) canSeeActionOnPublishedProfile(actionID, viewerGUID string) bool {
	if err := mh.ensureEnabledActions(); err != nil {
		return false
	}
	actionAuthMu.RLock()
	ea := mh.enabledActions.Actions[actionID]
	actionAuthMu.RUnlock()
	if ea == nil {
		return false
	}
	switch ea.Mode {
	case ActionAuthDefaultDeny:
		return actionAllowlistContains(ea.Allowlist, viewerGUID)
	case ActionAuthAllowList:
		return actionAllowlistContains(ea.Allowlist, viewerGUID)
	case ActionAuthPromptEachTime, ActionAuthDefaultAllow:
		return true
	}
	return false
}

func actionAllowlistContains(list []string, item string) bool {
	for _, x := range list {
		if x == item {
			return true
		}
	}
	return false
}
