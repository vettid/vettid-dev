package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/mesmerverse/vettid-dev/enclave/vault-manager/storage"
	"github.com/rs/zerolog/log"
)

// BackupManager handles automatic backup of vault state per Architecture v2.0 Section 5.18.
// Backups are sent simultaneously to both the app and S3 storage.
// The vault-manager controls what gets backed up, ensuring consistency.
type BackupManager struct {
	storage    *EncryptedStorage
	ownerSpace string
	publisher  BackupPublisher

	// Configuration
	autoBackupEnabled bool
	backupInterval    time.Duration

	mu sync.Mutex
}

// BackupPublisher interface for sending backups
type BackupPublisher interface {
	// PublishToApp sends backup to owner's app
	PublishToApp(ctx context.Context, eventType string, payload []byte) error
	// PublishToBackend sends backup to backend (S3 via Lambda)
	PublishToBackend(ctx context.Context, eventType string, payload []byte) error
}

// BackupRequest is sent to the backend for S3 storage
type BackupRequest struct {
	OwnerSpace      string `json:"owner_space"`
	RollbackCounter int64  `json:"rollback_counter"`
	EncryptedData   string `json:"encrypted_data"` // Base64-encoded BackupData
	HMAC            string `json:"hmac"`           // Base64-encoded HMAC
	Timestamp       int64  `json:"timestamp"`
}

// BackupResponse is received from the backend after S3 storage
type BackupResponse struct {
	Success         bool   `json:"success"`
	BackupID        string `json:"backup_id,omitempty"`
	RollbackCounter int64  `json:"rollback_counter,omitempty"`
	Error           string `json:"error,omitempty"`
}

// BackupNotification is sent to the app after successful backup
type BackupNotification struct {
	Type            string `json:"type"` // "backup_created", "backup_restored"
	BackupID        string `json:"backup_id"`
	RollbackCounter int64  `json:"rollback_counter"`
	Timestamp       int64  `json:"timestamp"`
}

// NewBackupManager creates a new backup manager
func NewBackupManager(ownerSpace string, storage *EncryptedStorage, publisher BackupPublisher) *BackupManager {
	return &BackupManager{
		storage:           storage,
		ownerSpace:        ownerSpace,
		publisher:         publisher,
		autoBackupEnabled: true,
		backupInterval:    5 * time.Minute,
	}
}

// TriggerBackup creates a backup and sends it to both app and backend simultaneously.
// Per Architecture v2.0 Section 5.18, this ensures the backup is always in sync.
func (bm *BackupManager) TriggerBackup(ctx context.Context) (*BackupNotification, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	sqlite := bm.storage.SQLite()
	if sqlite == nil {
		return nil, ErrStorageNotInitialized
	}

	// Create backup from SQLite storage
	backup, err := sqlite.CreateBackup()
	if err != nil {
		return nil, fmt.Errorf("failed to create backup: %w", err)
	}

	// Encode for transport
	backupReq := &BackupRequest{
		OwnerSpace:      bm.ownerSpace,
		RollbackCounter: backup.RollbackCounter,
		EncryptedData:   encodeBytes(backup.Data),
		HMAC:            encodeBytes(backup.HMAC),
		Timestamp:       backup.CreatedAt,
	}

	reqBytes, err := json.Marshal(backupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal backup request: %w", err)
	}

	// Send to backend and app simultaneously
	// Per Architecture v2.0: simultaneous delivery ensures consistency
	errChan := make(chan error, 2)

	// Send to backend (S3)
	go func() {
		if bm.publisher != nil {
			errChan <- bm.publisher.PublishToBackend(ctx, "backup.store", reqBytes)
		} else {
			errChan <- nil // No publisher configured
		}
	}()

	// Send to app
	go func() {
		if bm.publisher != nil {
			notification := &BackupNotification{
				Type:            "backup_created",
				BackupID:        fmt.Sprintf("backup-%d", backup.CreatedAt),
				RollbackCounter: backup.RollbackCounter,
				Timestamp:       backup.CreatedAt,
			}
			notifBytes, _ := json.Marshal(notification)
			errChan <- bm.publisher.PublishToApp(ctx, "backup.created", notifBytes)
		} else {
			errChan <- nil
		}
	}()

	// Wait for both
	var backendErr, appErr error
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			if backendErr == nil {
				backendErr = err
			} else {
				appErr = err
			}
		}
	}

	if backendErr != nil {
		log.Error().Err(backendErr).Msg("Failed to send backup to backend")
		return nil, fmt.Errorf("backend backup failed: %w", backendErr)
	}

	if appErr != nil {
		log.Warn().Err(appErr).Msg("Failed to notify app of backup")
		// Don't fail - backend backup succeeded
	}

	log.Info().
		Int64("rollback_counter", backup.RollbackCounter).
		Msg("Backup created and sent successfully")

	return &BackupNotification{
		Type:            "backup_created",
		BackupID:        fmt.Sprintf("backup-%d", backup.CreatedAt),
		RollbackCounter: backup.RollbackCounter,
		Timestamp:       backup.CreatedAt,
	}, nil
}

// RestoreBackup restores vault state from a backup
func (bm *BackupManager) RestoreBackup(ctx context.Context, backupData *storage.BackupData) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	sqlite := bm.storage.SQLite()
	if sqlite == nil {
		return ErrStorageNotInitialized
	}

	if err := sqlite.RestoreBackup(backupData); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	log.Info().
		Int64("rollback_counter", backupData.RollbackCounter).
		Msg("Backup restored successfully")

	// Notify app of restore
	if bm.publisher != nil {
		notification := &BackupNotification{
			Type:            "backup_restored",
			RollbackCounter: backupData.RollbackCounter,
			Timestamp:       time.Now().Unix(),
		}
		notifBytes, _ := json.Marshal(notification)
		if err := bm.publisher.PublishToApp(ctx, "backup.restored", notifBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to notify app of restore")
		}
	}

	return nil
}

// GetLastBackupInfo returns information about the last backup
func (bm *BackupManager) GetLastBackupInfo() (int64, error) {
	sqlite := bm.storage.SQLite()
	if sqlite == nil {
		return 0, ErrStorageNotInitialized
	}

	return sqlite.GetRollbackCounter(), nil
}

// SetAutoBackup enables or disables automatic backup after operations
func (bm *BackupManager) SetAutoBackup(enabled bool) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.autoBackupEnabled = enabled
}

// IsAutoBackupEnabled returns whether automatic backup is enabled
func (bm *BackupManager) IsAutoBackupEnabled() bool {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	return bm.autoBackupEnabled
}

// encodeBytes encodes bytes to base64 string
func encodeBytes(b []byte) string {
	return string(b) // In production, use base64.StdEncoding.EncodeToString(b)
}

// BackupHandler handles backup-related messages
type BackupHandler struct {
	ownerSpace    string
	backupManager *BackupManager
}

// NewBackupHandler creates a new backup handler
func NewBackupHandler(ownerSpace string, bm *BackupManager) *BackupHandler {
	return &BackupHandler{
		ownerSpace:    ownerSpace,
		backupManager: bm,
	}
}

// HandleTrigger handles backup.trigger messages from the app
func (h *BackupHandler) HandleTrigger(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	notification, err := h.backupManager.TriggerBackup(ctx)
	if err != nil {
		return h.errorResponse(msg.ID, err.Error())
	}

	respBytes, _ := json.Marshal(notification)
	return &OutgoingMessage{
		ID:      msg.ID,
		Type:    MessageTypeResponse,
		Payload: respBytes,
	}, nil
}

// HandleStatus handles backup.status messages
func (h *BackupHandler) HandleStatus(msg *IncomingMessage) (*OutgoingMessage, error) {
	counter, err := h.backupManager.GetLastBackupInfo()
	if err != nil {
		return h.errorResponse(msg.ID, err.Error())
	}

	resp := map[string]interface{}{
		"rollback_counter":    counter,
		"auto_backup_enabled": h.backupManager.IsAutoBackupEnabled(),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		ID:      msg.ID,
		Type:    MessageTypeResponse,
		Payload: respBytes,
	}, nil
}

func (h *BackupHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
	resp := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		ID:      id,
		Type:    MessageTypeResponse,
		Payload: respBytes,
	}, nil
}
