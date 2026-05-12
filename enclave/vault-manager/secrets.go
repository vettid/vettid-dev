package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// SecretsHandler manages "minor" secrets — stored in the vault's
// encrypted datastore (NOT in the credential blob). Values are
// retrievable in any authenticated session without a password
// re-prompt; that's the line between minor and critical.
//
//   - Critical secrets live in the sealed credential
//     (credential-secrets/_metadata + credential blob), require the
//     user to enter their password on every read.
//   - Minor secrets live in `secrets/<id>::<alias?>`, encrypted at
//     rest by the vault's storage DEK, retrievable while the vault
//     is unsealed.
//
// Both flow into the public secret_catalog when discoverability is
// public/cataloged. Peers see only metadata; values never leave the
// owner's vault for either tier.
type SecretsHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
	publisher  *VsockPublisher
	vaultState *VaultState
}

func NewSecretsHandler(ownerSpace string, storage *EncryptedStorage) *SecretsHandler {
	return &SecretsHandler{ownerSpace: ownerSpace, storage: storage}
}

// SetPublisher allows the handler to fan out RepublishProfile after
// any catalog-affecting mutation.
func (h *SecretsHandler) SetPublisher(p *VsockPublisher) { h.publisher = p }

// SetVaultState wires in the credential reference so RepublishProfile
// can include CryptoKeys in secret_catalog.
func (h *SecretsHandler) SetVaultState(s *VaultState) { h.vaultState = s }

// SecretRecord is the on-disk shape. Values are stored encrypted at
// rest by EncryptedStorage's DEK; the credential is not involved.
type SecretRecord struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Alias           string          `json:"alias,omitempty"`
	Value           string          `json:"value"`
	Category        string          `json:"category"`
	Type            string          `json:"type,omitempty"`
	Description     string          `json:"description,omitempty"`
	Discoverability Discoverability `json:"discoverability,omitempty"`
	CreatedAt       int64           `json:"created_at"`
	UpdatedAt       int64           `json:"updated_at"`
}

// secretFieldKey: <id>::<alias> when alias is set; otherwise just <id>.
// Same composite-key model personal-data uses, so two secrets with
// the same name/category but different aliases stay independent.
func secretFieldKey(id, alias string) string {
	if alias == "" {
		return id
	}
	return id + FieldKeySeparator + alias
}

// --- Request/Response types ---

type SecretAddRequest struct {
	Name            string          `json:"name"`
	Alias           string          `json:"alias,omitempty"`
	Value           string          `json:"value"`
	Category        string          `json:"category"`
	Type            string          `json:"type,omitempty"`
	Description     string          `json:"description,omitempty"`
	Discoverability Discoverability `json:"discoverability,omitempty"`
}

type SecretAddResponse struct {
	Success bool   `json:"success"`
	ID      string `json:"id"`
}

type SecretListResponse struct {
	Success bool                  `json:"success"`
	Secrets []SecretRecordSummary `json:"secrets"`
}

type SecretRecordSummary struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Alias           string          `json:"alias,omitempty"`
	Category        string          `json:"category"`
	Type            string          `json:"type,omitempty"`
	Description     string          `json:"description,omitempty"`
	Discoverability Discoverability `json:"discoverability,omitempty"`
	CreatedAt       string          `json:"created_at"`
	UpdatedAt       string          `json:"updated_at"`
}

type SecretGetRequest struct {
	ID string `json:"id"`
}

type SecretGetResponse struct {
	Success bool   `json:"success"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Value   string `json:"value"`
}

type SecretUpdateRequest struct {
	ID              string          `json:"id"`
	Name            string          `json:"name,omitempty"`
	Alias           *string         `json:"alias,omitempty"` // pointer so empty-string clears
	Value           string          `json:"value,omitempty"`
	Category        string          `json:"category,omitempty"`
	Type            string          `json:"type,omitempty"`
	Description     string          `json:"description,omitempty"`
	Discoverability Discoverability `json:"discoverability,omitempty"`
}

type SecretUpdateResponse struct {
	Success bool `json:"success"`
}

type SecretDeleteRequest struct {
	ID string `json:"id"`
}

type SecretDeleteResponse struct {
	Success bool `json:"success"`
}

type SecretSetDiscoverabilityRequest struct {
	ID              string          `json:"id"`
	Discoverability Discoverability `json:"discoverability"`
}

type SecretSetDiscoverabilityResponse struct {
	Success         bool            `json:"success"`
	Discoverability Discoverability `json:"discoverability"`
}

// --- Handlers ---

func (h *SecretsHandler) HandleAdd(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SecretAddRequest
	if err := unmarshalRequest(msg.Payload, &req, "Secrets.HandleAdd"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}
	if strings.TrimSpace(req.Name) == "" {
		return h.errorResponse(msg.GetID(), "name is required")
	}
	if req.Discoverability == "" {
		// Default-hidden (plans/data-request-grants.md Phase 3): a fresh
		// secret stays invisible to peers unless the user opts it into
		// the catalog. Existing records are unaffected — only secrets
		// created without an explicit discoverability land here.
		req.Discoverability = DiscoverabilityPrivate
	}

	now := time.Now().UTC()
	id := fmt.Sprintf("sec-%d", now.UnixNano())

	rec := SecretRecord{
		ID:              id,
		Name:            req.Name,
		Alias:           strings.TrimSpace(req.Alias),
		Value:           req.Value,
		Category:        req.Category,
		Type:            req.Type,
		Description:     req.Description,
		Discoverability: req.Discoverability,
		CreatedAt:       now.Unix(),
		UpdatedAt:       now.Unix(),
	}

	key := secretFieldKey(id, rec.Alias)
	if err := h.putRecord(key, &rec); err != nil {
		return h.errorResponse(msg.GetID(), err.Error())
	}
	if err := h.appendIndex(key); err != nil {
		log.Warn().Err(err).Str("id", id).Msg("Secrets: failed to update index")
	}

	go h.republish()

	resp := SecretAddResponse{Success: true, ID: id}
	out, _ := json.Marshal(resp)
	return &OutgoingMessage{RequestID: msg.GetID(), Type: MessageTypeResponse, Payload: out}, nil
}

func (h *SecretsHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	keys := h.indexKeys()
	out := make([]SecretRecordSummary, 0, len(keys))
	for _, k := range keys {
		var rec SecretRecord
		if err := h.getRecord(k, &rec); err != nil {
			continue
		}
		out = append(out, SecretRecordSummary{
			ID:              rec.ID,
			Name:            rec.Name,
			Alias:           rec.Alias,
			Category:        rec.Category,
			Type:            rec.Type,
			Description:     rec.Description,
			Discoverability: rec.Discoverability,
			CreatedAt:       time.Unix(rec.CreatedAt, 0).UTC().Format(time.RFC3339),
			UpdatedAt:       time.Unix(rec.UpdatedAt, 0).UTC().Format(time.RFC3339),
		})
	}
	resp := SecretListResponse{Success: true, Secrets: out}
	body, _ := json.Marshal(resp)
	return &OutgoingMessage{RequestID: msg.GetID(), Type: MessageTypeResponse, Payload: body}, nil
}

// HandleRetrieve is the legacy alias for the get path.
func (h *SecretsHandler) HandleRetrieve(msg *IncomingMessage) (*OutgoingMessage, error) {
	return h.HandleGet(msg)
}

func (h *SecretsHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SecretGetRequest
	if err := unmarshalRequest(msg.Payload, &req, "Secrets.HandleGet"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}
	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}
	_, rec, err := h.findByID(req.ID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "secret not found")
	}
	resp := SecretGetResponse{Success: true, ID: rec.ID, Name: rec.Name, Value: rec.Value}
	body, _ := json.Marshal(resp)
	return &OutgoingMessage{RequestID: msg.GetID(), Type: MessageTypeResponse, Payload: body}, nil
}

func (h *SecretsHandler) HandleUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SecretUpdateRequest
	if err := unmarshalRequest(msg.Payload, &req, "Secrets.HandleUpdate"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}
	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}
	oldKey, rec, err := h.findByID(req.ID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "secret not found")
	}
	if req.Name != "" {
		rec.Name = req.Name
	}
	if req.Alias != nil {
		rec.Alias = strings.TrimSpace(*req.Alias)
	}
	if req.Value != "" {
		rec.Value = req.Value
	}
	if req.Category != "" {
		rec.Category = req.Category
	}
	if req.Type != "" {
		rec.Type = req.Type
	}
	if req.Description != "" {
		rec.Description = req.Description
	}
	if req.Discoverability != "" {
		rec.Discoverability = req.Discoverability
	}
	rec.UpdatedAt = time.Now().UTC().Unix()

	newKey := secretFieldKey(rec.ID, rec.Alias)
	if err := h.putRecord(newKey, &rec); err != nil {
		return h.errorResponse(msg.GetID(), err.Error())
	}
	if newKey != oldKey {
		_ = h.storage.Delete("secrets/" + oldKey)
		h.removeFromIndex(oldKey)
		_ = h.appendIndex(newKey)
	}
	go h.republish()
	resp := SecretUpdateResponse{Success: true}
	body, _ := json.Marshal(resp)
	return &OutgoingMessage{RequestID: msg.GetID(), Type: MessageTypeResponse, Payload: body}, nil
}

func (h *SecretsHandler) HandleDelete(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SecretDeleteRequest
	if err := unmarshalRequest(msg.Payload, &req, "Secrets.HandleDelete"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}
	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}
	key, _, err := h.findByID(req.ID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "secret not found")
	}
	_ = h.storage.Delete("secrets/" + key)
	h.removeFromIndex(key)
	go h.republish()
	resp := SecretDeleteResponse{Success: true}
	body, _ := json.Marshal(resp)
	return &OutgoingMessage{RequestID: msg.GetID(), Type: MessageTypeResponse, Payload: body}, nil
}

func (h *SecretsHandler) HandleSetDiscoverability(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SecretSetDiscoverabilityRequest
	if err := unmarshalRequest(msg.Payload, &req, "Secrets.HandleSetDiscoverability"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}
	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}
	key, rec, err := h.findByID(req.ID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "secret not found")
	}
	switch req.Discoverability {
	case DiscoverabilityPublic, DiscoverabilityCataloged, DiscoverabilityPrivate:
	default:
		return h.errorResponse(msg.GetID(), "invalid discoverability")
	}
	rec.Discoverability = req.Discoverability
	rec.UpdatedAt = time.Now().UTC().Unix()
	if err := h.putRecord(key, &rec); err != nil {
		return h.errorResponse(msg.GetID(), err.Error())
	}
	go h.republish()
	resp := SecretSetDiscoverabilityResponse{Success: true, Discoverability: req.Discoverability}
	body, _ := json.Marshal(resp)
	return &OutgoingMessage{RequestID: msg.GetID(), Type: MessageTypeResponse, Payload: body}, nil
}

// MinorSecretRecords returns every record (with values stripped) so
// buildSecretCatalog can include minor secrets in the catalog
// alongside credential-secrets, wallets, and crypto keys.
func MinorSecretRecords(storage *EncryptedStorage) []SecretRecordSummary {
	if storage == nil {
		return nil
	}
	data, err := storage.Get("secrets/_index")
	if err != nil || len(data) == 0 {
		return nil
	}
	var keys []string
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil
	}
	out := make([]SecretRecordSummary, 0, len(keys))
	for _, k := range keys {
		raw, err := storage.Get("secrets/" + k)
		if err != nil {
			continue
		}
		var rec SecretRecord
		if json.Unmarshal(raw, &rec) != nil {
			continue
		}
		out = append(out, SecretRecordSummary{
			ID:              rec.ID,
			Name:            rec.Name,
			Alias:           rec.Alias,
			Category:        rec.Category,
			Type:            rec.Type,
			Description:     rec.Description,
			Discoverability: rec.Discoverability,
		})
	}
	return out
}

// --- Helpers ---

func (h *SecretsHandler) putRecord(key string, rec *SecretRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal secret: %w", err)
	}
	return h.storage.Put("secrets/"+key, data)
}

func (h *SecretsHandler) getRecord(key string, rec *SecretRecord) error {
	data, err := h.storage.Get("secrets/" + key)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, rec)
}

func (h *SecretsHandler) indexKeys() []string {
	data, err := h.storage.Get("secrets/_index")
	if err != nil || len(data) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

func (h *SecretsHandler) appendIndex(key string) error {
	keys := h.indexKeys()
	if containsString(keys, key) {
		return nil
	}
	keys = append(keys, key)
	body, _ := json.Marshal(keys)
	return h.storage.Put("secrets/_index", body)
}

func (h *SecretsHandler) removeFromIndex(key string) {
	keys := h.indexKeys()
	keys = removeString(keys, key)
	body, _ := json.Marshal(keys)
	_ = h.storage.Put("secrets/_index", body)
}

func (h *SecretsHandler) findByID(id string) (string, SecretRecord, error) {
	for _, k := range h.indexKeys() {
		var rec SecretRecord
		if err := h.getRecord(k, &rec); err != nil {
			continue
		}
		if rec.ID == id {
			return k, rec, nil
		}
	}
	return "", SecretRecord{}, fmt.Errorf("not found")
}

func (h *SecretsHandler) republish() {
	if h.publisher == nil {
		return
	}
	RepublishProfile(h.ownerSpace, h.storage, h.publisher, h.vaultState)
}

func (h *SecretsHandler) errorResponse(reqID, msg string) (*OutgoingMessage, error) {
	resp := map[string]interface{}{"success": false, "error": msg}
	body, _ := json.Marshal(resp)
	return &OutgoingMessage{RequestID: reqID, Type: MessageTypeResponse, Payload: body}, nil
}
