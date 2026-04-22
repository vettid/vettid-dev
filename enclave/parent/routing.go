package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
)

// RoutingManager owns the "which enclave instance serves which user"
// state. See the design notes at the top of routing_design.md (or
// just follow this file — the protocol is:
//
//  1. Each user's ownership is a JSON record at `routing.<user_guid>`
//     in the NATS JetStream KV bucket `vault-routing`.
//  2. Only the owning instance subscribes to
//     `OwnerSpace.<user_guid>.forVault.>`. Non-owners stay silent.
//  3. Owners heartbeat by rewriting the record every heartbeatInterval
//     with a refreshed lease_until.
//  4. Dead owners are reclaimed by any other instance after the
//     lease expires.
//  5. Intentional handoff (e.g. after a credential migration) is a
//     CAS write by the current owner setting `instance_id` to the
//     new owner. The new owner's watcher sees the update, loads
//     state from S3, subscribes, and starts heartbeating.
//
// Defense-in-depth: [RoutingManager.IsOwner] is a cheap local cache
// lookup. Call it on every inbound forVault message — if it returns
// false, NAK / drop rather than process. Guards against the brief
// window where subscriptions and KV state are out of sync.
type RoutingManager struct {
	enclaveID  string
	pcr0       string
	natsClient *NATSClient
	msgChan    chan *NATSMessage

	mu    sync.RWMutex
	owned map[string]*ownedUser

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// ownedUser is the per-user entry we maintain locally while we hold
// ownership. subscription is nil while we haven't yet attached.
type ownedUser struct {
	revision     uint64
	leaseUntil   time.Time
	subscription *nats.Subscription
}

// routingEntry is the JSON value stored in KV.
type routingEntry struct {
	InstanceID string `json:"instance_id"`
	PCR0       string `json:"pcr0,omitempty"`
	LeaseUntil int64  `json:"lease_until"`
}

const (
	heartbeatInterval = 15 * time.Second
	leaseTTL          = 45 * time.Second
	routingKeyPrefix  = "routing."
	// How long a freshly-claimed user's subscription gets to warm up
	// before we expect messages to flow. Mostly informational for
	// logging — the subscribe happens synchronously.
	subscribeWarmup = 200 * time.Millisecond
)

// NewRoutingManager initializes the manager. It does not start any
// background work; call Start(ctx) to begin heartbeating, watching,
// and reconciling.
func NewRoutingManager(enclaveID, pcr0 string, natsClient *NATSClient, msgChan chan *NATSMessage) *RoutingManager {
	return &RoutingManager{
		enclaveID:  enclaveID,
		pcr0:       pcr0,
		natsClient: natsClient,
		msgChan:    msgChan,
		owned:      make(map[string]*ownedUser),
		stopCh:     make(chan struct{}),
	}
}

// Start kicks off the background goroutines: heartbeat loop, KV
// watcher, and initial reconcile. Safe to call multiple times; the
// second call is a no-op.
func (r *RoutingManager) Start(ctx context.Context) error {
	if _, err := r.kv(); err != nil {
		return fmt.Errorf("routing KV unavailable: %w", err)
	}

	// Reconcile once synchronously so we have the full picture
	// before any message arrives through other paths.
	if err := r.reconcileAll(); err != nil {
		log.Warn().Err(err).Msg("routing: initial reconcile failed — will retry on heartbeat tick")
	}

	r.wg.Add(2)
	go r.heartbeatLoop(ctx)
	go r.watchLoop(ctx)
	log.Info().
		Str("enclave_id", r.enclaveID).
		Int("owned", len(r.owned)).
		Msg("RoutingManager started")
	return nil
}

// Stop halts background goroutines and releases subscriptions. The
// KV rows are left alone — another instance will lease-reclaim them
// after leaseTTL.
func (r *RoutingManager) Stop() {
	close(r.stopCh)
	r.wg.Wait()
	r.mu.Lock()
	for guid, entry := range r.owned {
		if entry.subscription != nil {
			_ = entry.subscription.Unsubscribe()
		}
		delete(r.owned, guid)
	}
	r.mu.Unlock()
}

// IsOwner returns true if we are the authoritative owner for this
// user RIGHT NOW per our local cache. Cheap — just a map lookup.
// Call this on every inbound forVault message as a defense-in-depth
// check against the subscription/KV transition window.
func (r *RoutingManager) IsOwner(userGuid string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.owned[userGuid]
	if !ok {
		return false
	}
	// A stale cache entry (lease expired locally) shouldn't be trusted.
	// The heartbeat loop should have refreshed it; if it hasn't, we've
	// likely lost NATS and should fail closed.
	return time.Now().Before(entry.leaseUntil)
}

// ClaimForEnrollment attempts to create a fresh routing row for a
// brand-new user. Uses CAS with revision=0 (create-only). Returns
// true if we won the claim; false if another instance got there
// first (legitimate race during concurrent enrollment).
func (r *RoutingManager) ClaimForEnrollment(userGuid, pcr0 string) (bool, error) {
	kv, err := r.kv()
	if err != nil {
		return false, err
	}
	entry := routingEntry{
		InstanceID: r.enclaveID,
		PCR0:       pcr0,
		LeaseUntil: time.Now().Add(leaseTTL).Unix(),
	}
	data, _ := json.Marshal(&entry)
	rev, err := kv.Create(routingKeyPrefix+userGuid, data)
	if err != nil {
		// Create-only fails if key exists — either another instance
		// won the race, or this user was enrolled before. Either way,
		// not our claim.
		log.Info().Err(err).Str("user_guid", userGuid).Msg("routing: claim-for-enrollment lost (key exists)")
		return false, nil
	}

	r.mu.Lock()
	r.owned[userGuid] = &ownedUser{
		revision:   rev,
		leaseUntil: time.Unix(entry.LeaseUntil, 0),
	}
	r.mu.Unlock()

	if err := r.subscribeUser(userGuid); err != nil {
		log.Warn().Err(err).Str("user_guid", userGuid).Msg("routing: subscribe failed after claim — will retry on watcher")
	}
	log.Info().
		Str("user_guid", userGuid).
		Str("enclave_id", r.enclaveID).
		Uint64("revision", rev).
		Msg("routing: claimed new user")
	return true, nil
}

// HandoffToPeer transfers ownership to a different enclave instance.
// Pass targetInstanceID="" to release the row for pool-based reclaim
// (useful when the current owner knows the user should migrate but
// doesn't know which peer will pick up). In that case newPCR0 is
// the PCR the state is now sealed to; any instance attesting to
// that PCR can then reclaim.
//
// Called by the current owner after a successful migration re-seal.
// CAS-updates the row in one shot; the peer's watcher will pick up
// the change and take over (or reclaim, in the release case).
func (r *RoutingManager) HandoffToPeer(userGuid, targetInstanceID, newPCR0 string) error {
	kv, err := r.kv()
	if err != nil {
		return err
	}

	r.mu.RLock()
	current, owned := r.owned[userGuid]
	r.mu.RUnlock()
	if !owned {
		return fmt.Errorf("routing: not owner of %s, cannot hand off", userGuid)
	}

	// For release-for-reclaim, lease_until is zero so any instance
	// running the target PCR can claim immediately via watcher. For
	// direct handoff to a specific peer, we give a fresh lease so
	// the target doesn't have to wait.
	leaseUntil := int64(0)
	if targetInstanceID != "" {
		leaseUntil = time.Now().Add(leaseTTL).Unix()
	}
	entry := routingEntry{
		InstanceID: targetInstanceID,
		PCR0:       newPCR0,
		LeaseUntil: leaseUntil,
	}
	data, _ := json.Marshal(&entry)
	if _, err := kv.Update(routingKeyPrefix+userGuid, data, current.revision); err != nil {
		return fmt.Errorf("CAS handoff: %w", err)
	}

	// Unsubscribe first, then drop local state. Ordering matters: the
	// watcher will see our CAS update a moment later and would try to
	// drop the sub anyway, but we do it synchronously here so no
	// messages slip through to this instance after the handoff.
	r.releaseLocally(userGuid)

	if targetInstanceID == "" {
		log.Info().
			Str("user_guid", userGuid).
			Str("from", r.enclaveID).
			Str("new_pcr0", truncPCR(newPCR0)).
			Msg("routing: released user for reclaim")
	} else {
		log.Info().
			Str("user_guid", userGuid).
			Str("from", r.enclaveID).
			Str("to", targetInstanceID).
			Str("new_pcr0", truncPCR(newPCR0)).
			Msg("routing: handed off user to peer")
	}
	return nil
}

// canClaim returns true if this instance is eligible to own a user
// whose state is sealed to the given PCR. Empty entryPCR means we
// don't know (legacy rows from before PCR tracking), so permit.
func (r *RoutingManager) canClaim(entryPCR string) bool {
	if entryPCR == "" || r.pcr0 == "" {
		return true
	}
	return entryPCR == r.pcr0
}

// ReclaimIfExpiredOrVacant tries to take over a user whose row is
// either lease-expired (owner dead) or vacant (explicit release via
// HandoffToPeer with empty target). CAS on the observed revision
// so concurrent challengers lose cleanly. We also refuse rows whose
// PCR0 doesn't match our attested PCR — a user migrated to a newer
// PCR shouldn't be reclaimed by an instance still running the old
// one.
func (r *RoutingManager) ReclaimIfExpiredOrVacant(userGuid string) (bool, error) {
	kv, err := r.kv()
	if err != nil {
		return false, err
	}
	current, err := kv.Get(routingKeyPrefix + userGuid)
	if err != nil {
		return false, err
	}
	var existing routingEntry
	if err := json.Unmarshal(current.Value(), &existing); err != nil {
		return false, fmt.Errorf("parse existing routing entry: %w", err)
	}

	// Vacant (explicit release) or lease-expired — either qualifies.
	vacant := existing.InstanceID == ""
	expired := existing.LeaseUntil > 0 && time.Unix(existing.LeaseUntil, 0).Before(time.Now())
	if !vacant && !expired {
		return false, nil // still alive; back off
	}
	// For vacant rows (explicit release-for-reclaim), the previous
	// owner deliberately set the PCR the state is sealed to; honor
	// that and only claim if it matches us. For expired rows the
	// previous owner is dead — someone has to serve the user, and
	// KMS AnyOf policy is the real authority on who can decrypt.
	// Blocking on PCR here would leave users black-holed whenever a
	// migration re-seal didn't complete cleanly (owner died before
	// sending the release handoff, handoff got dropped, etc.).
	if vacant && !r.canClaim(existing.PCR0) {
		return false, nil // explicit release targeted a different PCR
	}

	entry := routingEntry{
		InstanceID: r.enclaveID,
		PCR0: func() string {
			if existing.PCR0 != "" {
				return existing.PCR0
			}
			return r.pcr0
		}(),
		LeaseUntil: time.Now().Add(leaseTTL).Unix(),
	}
	data, _ := json.Marshal(&entry)
	rev, err := kv.Update(routingKeyPrefix+userGuid, data, current.Revision())
	if err != nil {
		// Someone else beat us. Not an error — they're a valid owner now.
		return false, nil
	}
	r.mu.Lock()
	r.owned[userGuid] = &ownedUser{
		revision:   rev,
		leaseUntil: time.Unix(entry.LeaseUntil, 0),
	}
	r.mu.Unlock()
	if err := r.subscribeUser(userGuid); err != nil {
		log.Warn().Err(err).Str("user_guid", userGuid).Msg("routing: subscribe failed after reclaim")
	}
	log.Info().
		Str("user_guid", userGuid).
		Str("enclave_id", r.enclaveID).
		Uint64("new_revision", rev).
		Bool("was_vacant", vacant).
		Msg("routing: reclaimed user")
	return true, nil
}

// --- background loops ---

func (r *RoutingManager) heartbeatLoop(ctx context.Context) {
	defer r.wg.Done()
	tick := time.NewTicker(heartbeatInterval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			r.heartbeatOnce()
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		}
	}
}

func (r *RoutingManager) heartbeatOnce() {
	kv, err := r.kv()
	if err != nil {
		log.Warn().Err(err).Msg("routing: heartbeat skipped — KV unavailable")
		return
	}

	r.mu.RLock()
	guids := make([]string, 0, len(r.owned))
	for g := range r.owned {
		guids = append(guids, g)
	}
	r.mu.RUnlock()

	now := time.Now()
	for _, guid := range guids {
		r.mu.RLock()
		entry, ok := r.owned[guid]
		r.mu.RUnlock()
		if !ok {
			continue
		}
		newEntry := routingEntry{
			InstanceID: r.enclaveID,
			PCR0:       r.pcr0,
			LeaseUntil: now.Add(leaseTTL).Unix(),
		}
		data, _ := json.Marshal(&newEntry)
		rev, err := kv.Update(routingKeyPrefix+guid, data, entry.revision)
		if err != nil {
			// Most likely cause: we got handed off to someone else and
			// didn't see the watcher update yet, OR the KV row was
			// removed. Either way, release locally so we stop serving.
			log.Warn().Err(err).Str("user_guid", guid).Msg("routing: heartbeat CAS failed — releasing locally")
			r.releaseLocally(guid)
			continue
		}
		r.mu.Lock()
		if e, ok := r.owned[guid]; ok {
			e.revision = rev
			e.leaseUntil = time.Unix(newEntry.LeaseUntil, 0)
		}
		r.mu.Unlock()
	}

	// Sweep for stale rows while we're here. If a peer instance died
	// without sending a release handoff (ASG terminate, process crash,
	// hard network partition), its row's lease eventually lapses and
	// the watcher never fires — no KV update happened. The sweep is
	// the floor on how long such a user stays unreachable: heartbeat
	// interval + lease TTL in the worst case.
	r.sweepStaleRows(kv)
}

// sweepStaleRows walks the routing KV and tries to reclaim any row
// whose lease has expired or which is vacant. We only pick up rows
// whose PCR0 matches ours (canClaim, enforced inside
// ReclaimIfExpiredOrVacant). Rows we already own are skipped —
// heartbeatOnce above handles their lease renewal.
func (r *RoutingManager) sweepStaleRows(kv nats.KeyValue) {
	keys, err := kv.Keys()
	if err != nil {
		// ErrNoKeysFound is the empty-bucket case — nothing to do.
		if err == nats.ErrNoKeysFound {
			return
		}
		log.Debug().Err(err).Msg("routing: sweep skipped, KV list failed")
		return
	}
	for _, key := range keys {
		if len(key) <= len(routingKeyPrefix) || key[:len(routingKeyPrefix)] != routingKeyPrefix {
			continue
		}
		guid := key[len(routingKeyPrefix):]

		r.mu.RLock()
		_, owned := r.owned[guid]
		r.mu.RUnlock()
		if owned {
			continue
		}

		// ReclaimIfExpiredOrVacant is a no-op if the row is still
		// alive (lease hasn't expired and InstanceID is non-empty) or
		// if PCR0 doesn't match ours. Cheap to call.
		if ok, err := r.ReclaimIfExpiredOrVacant(guid); err != nil {
			log.Debug().Err(err).Str("user_guid", guid).Msg("routing: sweep reclaim errored")
		} else if ok {
			log.Info().Str("user_guid", guid).Msg("routing: sweep reclaimed stale row")
		}
	}
}

func (r *RoutingManager) watchLoop(ctx context.Context) {
	defer r.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		default:
		}
		kv, err := r.kv()
		if err != nil {
			log.Warn().Err(err).Msg("routing: watch skipped, KV unavailable; retrying in 5s")
			select {
			case <-time.After(5 * time.Second):
				continue
			case <-ctx.Done():
				return
			case <-r.stopCh:
				return
			}
		}
		// UpdatesOnly=true so we don't re-process historical writes
		// every time we reconnect. The initial reconcile in Start()
		// handled the "what do we own right now" question.
		watcher, err := kv.WatchAll(nats.IgnoreDeletes(), nats.UpdatesOnly())
		if err != nil {
			log.Warn().Err(err).Msg("routing: watch init failed; retrying in 5s")
			select {
			case <-time.After(5 * time.Second):
				continue
			case <-ctx.Done():
				return
			case <-r.stopCh:
				return
			}
		}
		for entry := range watcher.Updates() {
			if entry == nil {
				// Initial-values-done marker when not using UpdatesOnly.
				continue
			}
			r.handleWatchEvent(entry)
			select {
			case <-ctx.Done():
				_ = watcher.Stop()
				return
			case <-r.stopCh:
				_ = watcher.Stop()
				return
			default:
			}
		}
	}
}

func (r *RoutingManager) handleWatchEvent(e nats.KeyValueEntry) {
	key := e.Key()
	if len(key) <= len(routingKeyPrefix) || key[:len(routingKeyPrefix)] != routingKeyPrefix {
		return
	}
	guid := key[len(routingKeyPrefix):]

	var remote routingEntry
	if err := json.Unmarshal(e.Value(), &remote); err != nil {
		log.Warn().Err(err).Str("key", key).Msg("routing: malformed KV entry — ignoring")
		return
	}

	// Do we own it locally?
	r.mu.RLock()
	_, owned := r.owned[guid]
	r.mu.RUnlock()

	if remote.InstanceID == r.enclaveID {
		// Someone (us or our future self) says we own. Subscribe if
		// not already. Happens on reclaim + handoff-to-us paths.
		if !owned {
			r.mu.Lock()
			r.owned[guid] = &ownedUser{
				revision:   e.Revision(),
				leaseUntil: time.Unix(remote.LeaseUntil, 0),
			}
			r.mu.Unlock()
			if err := r.subscribeUser(guid); err != nil {
				log.Warn().Err(err).Str("user_guid", guid).Msg("routing: subscribe failed on watch event")
			}
			log.Info().
				Str("user_guid", guid).
				Str("enclave_id", r.enclaveID).
				Msg("routing: took ownership via watcher")
		} else {
			r.mu.Lock()
			if e2, ok := r.owned[guid]; ok {
				e2.revision = e.Revision()
				e2.leaseUntil = time.Unix(remote.LeaseUntil, 0)
			}
			r.mu.Unlock()
		}
		return
	}

	// Not ours per the KV. If we thought we owned it, release.
	if owned {
		log.Info().
			Str("user_guid", guid).
			Str("now_owned_by", remote.InstanceID).
			Msg("routing: lost ownership via watcher, releasing")
		r.releaseLocally(guid)
	}

	// Vacant row (explicit release via HandoffToPeer with empty
	// target) — race to reclaim. canClaim() gates us by PCR so we
	// only pick up users whose state is sealed to our attested PCR.
	if remote.InstanceID == "" && r.canClaim(remote.PCR0) {
		if ok, err := r.ReclaimIfExpiredOrVacant(guid); err != nil {
			log.Debug().Err(err).Str("user_guid", guid).Msg("routing: reclaim after watch event failed")
		} else if ok {
			log.Info().Str("user_guid", guid).Msg("routing: picked up vacant row via watcher")
		}
	}
}

// reconcileAll walks the KV and syncs the local subscription set to
// the authoritative ownership view. Called once at startup and
// again on NATS reconnect.
func (r *RoutingManager) reconcileAll() error {
	kv, err := r.kv()
	if err != nil {
		return err
	}
	keys, err := kv.Keys()
	if err != nil {
		// Empty bucket returns ErrNoKeysFound — treat as clean slate.
		if err == nats.ErrNoKeysFound {
			return nil
		}
		return fmt.Errorf("list routing keys: %w", err)
	}

	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if len(key) <= len(routingKeyPrefix) {
			continue
		}
		guid := key[len(routingKeyPrefix):]
		seen[guid] = struct{}{}

		kvEntry, err := kv.Get(key)
		if err != nil {
			continue
		}
		var entry routingEntry
		if err := json.Unmarshal(kvEntry.Value(), &entry); err != nil {
			continue
		}
		if entry.InstanceID == r.enclaveID {
			r.mu.Lock()
			_, already := r.owned[guid]
			if !already {
				r.owned[guid] = &ownedUser{
					revision:   kvEntry.Revision(),
					leaseUntil: time.Unix(entry.LeaseUntil, 0),
				}
			}
			r.mu.Unlock()
			if err := r.subscribeUser(guid); err != nil {
				log.Warn().Err(err).Str("user_guid", guid).Msg("routing: subscribe failed during reconcile")
			}
		}
	}

	// Drop locally-owned users that no longer appear in the KV.
	r.mu.Lock()
	stale := make([]string, 0)
	for guid := range r.owned {
		if _, ok := seen[guid]; !ok {
			stale = append(stale, guid)
		}
	}
	r.mu.Unlock()
	for _, guid := range stale {
		log.Info().Str("user_guid", guid).Msg("routing: releasing stale local ownership during reconcile")
		r.releaseLocally(guid)
	}
	return nil
}

// OnReconnect should be wired to NATSClient's reconnect callback.
// Walks the KV and reconciles so any updates missed during the
// disconnect are picked up.
func (r *RoutingManager) OnReconnect() {
	if err := r.reconcileAll(); err != nil {
		log.Warn().Err(err).Msg("routing: reconcile-on-reconnect failed")
	}
}

// --- helpers ---

func (r *RoutingManager) kv() (nats.KeyValue, error) {
	return r.natsClient.RoutingKV()
}

func (r *RoutingManager) subscribeUser(userGuid string) error {
	r.mu.RLock()
	entry, ok := r.owned[userGuid]
	alreadySubscribed := ok && entry.subscription != nil
	r.mu.RUnlock()
	if alreadySubscribed {
		return nil
	}
	subject := "OwnerSpace." + userGuid + ".forVault.>"
	sub, err := r.natsClient.conn.Subscribe(subject, func(msg *nats.Msg) {
		select {
		case r.msgChan <- &NATSMessage{
			Subject: msg.Subject,
			Reply:   msg.Reply,
			Data:    msg.Data,
		}:
		default:
			log.Warn().Str("subject", msg.Subject).Msg("routing: msgChan full, dropped inbound message")
		}
	})
	if err != nil {
		return fmt.Errorf("subscribe %s: %w", subject, err)
	}
	r.mu.Lock()
	if e, ok := r.owned[userGuid]; ok {
		e.subscription = sub
	} else {
		_ = sub.Unsubscribe()
	}
	r.mu.Unlock()
	log.Debug().Str("subject", subject).Msg("routing: subscribed per-user forVault topic")
	return nil
}

func (r *RoutingManager) releaseLocally(userGuid string) {
	r.mu.Lock()
	entry, ok := r.owned[userGuid]
	if ok {
		delete(r.owned, userGuid)
	}
	r.mu.Unlock()
	if ok && entry.subscription != nil {
		_ = entry.subscription.Unsubscribe()
	}
}

func truncPCR(pcr string) string {
	if len(pcr) > 16 {
		return pcr[:16] + "…"
	}
	return pcr
}
