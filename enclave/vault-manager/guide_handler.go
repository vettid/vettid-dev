package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/rs/zerolog/log"
)

// GuideHandler manages welcome/tutorial guide events.
// The app owns the guide catalog; the vault is a dumb storage layer that
// creates feed events on demand and tracks what has already been created.
type GuideHandler struct {
	ownerSpace   string
	storage      *EncryptedStorage
	eventHandler *EventHandler
}

// NewGuideHandler creates a new guide handler
func NewGuideHandler(ownerSpace string, storage *EncryptedStorage, eventHandler *EventHandler) *GuideHandler {
	return &GuideHandler{
		ownerSpace:   ownerSpace,
		storage:      storage,
		eventHandler: eventHandler,
	}
}

// GuideSyncRequest is sent by the app with its full guide catalog
type GuideSyncRequest struct {
	Guides []GuideDef `json:"guides"`
}

// GuideDef defines a single guide the app wants to exist as a feed event
type GuideDef struct {
	GuideID  string `json:"guide_id"`
	Title    string `json:"title"`
	Message  string `json:"message"`
	Order    int    `json:"order"`
	Priority int    `json:"priority"`
	Version  int    `json:"version"`
	UserName string `json:"user_name"`
}

// GuideSyncResponse reports what happened during sync
type GuideSyncResponse struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
	Total   int `json:"total"`
}

// StoredGuideCatalog is persisted in vault storage at guides/_catalog
type StoredGuideCatalog struct {
	Guides map[string]StoredGuideEntry `json:"guides"`
}

// StoredGuideEntry tracks a single guide that has been created
type StoredGuideEntry struct {
	EventID string `json:"event_id"`
	Version int    `json:"version"`
}

const guideCatalogKey = "guides/_catalog"

// HandleSync processes a guide.sync request from the app.
// It is idempotent: calling with the same catalog is a no-op.
func (gh *GuideHandler) HandleSync(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GuideSyncRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return gh.errorResponse(msg.GetID(), "invalid guide sync request")
	}

	if len(req.Guides) == 0 {
		return gh.successResponse(msg.GetID(), GuideSyncResponse{})
	}

	// Load existing catalog
	catalog := gh.loadCatalog()

	created := 0
	updated := 0

	for _, guide := range req.Guides {
		existing, exists := catalog.Guides[guide.GuideID]

		if !exists {
			// New guide - create feed event
			eventID, err := gh.createGuideEvent(ctx, guide, false)
			if err != nil {
				log.Error().Err(err).Str("guide_id", guide.GuideID).Msg("Failed to create guide event")
				continue
			}
			catalog.Guides[guide.GuideID] = StoredGuideEntry{
				EventID: eventID,
				Version: guide.Version,
			}
			created++
			log.Info().Str("guide_id", guide.GuideID).Str("event_id", eventID).Msg("Created guide event")

		} else if guide.Version > existing.Version {
			// Updated guide - create a NEW feed event (old one stays as-is)
			eventID, err := gh.createGuideEvent(ctx, guide, true)
			if err != nil {
				log.Error().Err(err).Str("guide_id", guide.GuideID).Msg("Failed to create updated guide event")
				continue
			}
			catalog.Guides[guide.GuideID] = StoredGuideEntry{
				EventID: eventID,
				Version: guide.Version,
			}
			updated++
			log.Info().Str("guide_id", guide.GuideID).Str("event_id", eventID).Int("version", guide.Version).Msg("Created updated guide event")

		}
		// else: same version, skip entirely
	}

	// Save updated catalog
	if created > 0 || updated > 0 {
		if err := gh.saveCatalog(catalog); err != nil {
			log.Error().Err(err).Msg("Failed to save guide catalog")
		}
	}

	resp := GuideSyncResponse{
		Created: created,
		Updated: updated,
		Total:   len(catalog.Guides),
	}

	return gh.successResponse(msg.GetID(), resp)
}

// createGuideEvent creates a feed event for a guide
func (gh *GuideHandler) createGuideEvent(ctx context.Context, guide GuideDef, isUpdate bool) (string, error) {
	// Map priority from request (-1, 0, 1, 2) to Priority type
	priority := Priority(guide.Priority)

	title := guide.Title
	if isUpdate {
		title = "Updated: " + title
	}

	metadata := map[string]string{
		"guide_id":    guide.GuideID,
		"guide_order": strconv.Itoa(guide.Order),
	}
	if guide.UserName != "" {
		metadata["user_name"] = guide.UserName
	}
	if isUpdate {
		metadata["is_update"] = "true"
	}

	event := &Event{
		EventType:      EventTypeGuide,
		SourceType:     "system",
		Title:          title,
		Message:        guide.Message,
		Metadata:       metadata,
		FeedStatus:     FeedStatusActive,
		ActionType:     ActionTypeView,
		Priority:       priority,
		RetentionClass: RetentionPermanent,
	}

	if err := gh.eventHandler.LogEvent(ctx, event); err != nil {
		return "", fmt.Errorf("failed to log guide event: %w", err)
	}

	return event.EventID, nil
}

// loadCatalog loads the stored guide catalog from storage
func (gh *GuideHandler) loadCatalog() *StoredGuideCatalog {
	data, err := gh.storage.Get(guideCatalogKey)
	if err != nil {
		// Not found or error - return empty catalog
		return &StoredGuideCatalog{
			Guides: make(map[string]StoredGuideEntry),
		}
	}

	var catalog StoredGuideCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		log.Warn().Err(err).Msg("Failed to unmarshal guide catalog, starting fresh")
		return &StoredGuideCatalog{
			Guides: make(map[string]StoredGuideEntry),
		}
	}

	if catalog.Guides == nil {
		catalog.Guides = make(map[string]StoredGuideEntry)
	}

	return &catalog
}

// saveCatalog persists the guide catalog to storage
func (gh *GuideHandler) saveCatalog(catalog *StoredGuideCatalog) error {
	data, err := json.Marshal(catalog)
	if err != nil {
		return fmt.Errorf("failed to marshal guide catalog: %w", err)
	}
	return gh.storage.Put(guideCatalogKey, data)
}

// errorResponse creates an error response
func (gh *GuideHandler) errorResponse(requestID string, message string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		ID:    requestID,
		Type:  MessageTypeResponse,
		Error: message,
	}, nil
}

// successResponse creates a success response with JSON payload
func (gh *GuideHandler) successResponse(requestID string, data interface{}) (*OutgoingMessage, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return gh.errorResponse(requestID, "failed to marshal response")
	}
	return &OutgoingMessage{
		ID:      requestID,
		Type:    MessageTypeResponse,
		Payload: payload,
	}, nil
}
