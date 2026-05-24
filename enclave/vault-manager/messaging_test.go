package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

// setupMessagingHandler builds a MessagingHandler against an in-memory
// SQLite-backed EncryptedStorage. No publisher / event handler needed
// for the read-side tests.
func setupMessagingHandler(t *testing.T) (*MessagingHandler, *EncryptedStorage, func()) {
	t.Helper()

	dek := make([]byte, 32)
	rand.Read(dek)

	store, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	encStorage := &EncryptedStorage{sqlite: store, ownerSpace: "test-owner"}

	h := NewMessagingHandler("test-owner", encStorage, nil, nil)

	cleanup := func() { store.Close() }
	return h, encStorage, cleanup
}

// seedMessages writes n messages to the given connection at one-second
// intervals starting at base, plus a matching index. The connection
// record has no shared secret, so HandleList skips decryption and
// returns rows with empty Content — fine, we only assert on
// message_id / sent_at here.
func seedMessages(t *testing.T, store *EncryptedStorage, connID string, n int, base time.Time) []string {
	t.Helper()

	conn := ConnectionRecord{ConnectionID: connID}
	connBytes, _ := json.Marshal(conn)
	if err := store.Put("connections/"+connID, connBytes); err != nil {
		t.Fatalf("put connection: %v", err)
	}

	ids := make([]string, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("msg-%03d", i)
		ids[i] = id
		rec := MessageRecord{
			MessageID:    id,
			ConnectionID: connID,
			Direction:    MessageDirectionOutgoing,
			ContentType:  "text",
			Status:       MessageStatusSent,
			CreatedAt:    base.Add(time.Duration(i) * time.Second),
		}
		data, _ := json.Marshal(rec)
		if err := store.Put(fmt.Sprintf("messages/%s/%s", connID, id), data); err != nil {
			t.Fatalf("put message %s: %v", id, err)
		}
	}
	indexBytes, _ := json.Marshal(ids)
	if err := store.Put(fmt.Sprintf("messages/%s/_index", connID), indexBytes); err != nil {
		t.Fatalf("put index: %v", err)
	}
	return ids
}

// callList exercises HandleList and returns the parsed message_id list,
// in the order the handler returned them (oldest → newest after the
// handler's sort).
func callList(t *testing.T, h *MessagingHandler, connID string, limit int, before string) []string {
	t.Helper()

	req := map[string]interface{}{"connection_id": connID}
	if limit > 0 {
		req["limit"] = limit
	}
	if before != "" {
		req["before"] = before
	}
	payload, _ := json.Marshal(req)
	resp, err := h.HandleList(&IncomingMessage{ID: "test-req", Payload: payload})
	if err != nil {
		t.Fatalf("HandleList err: %v", err)
	}
	if resp == nil {
		t.Fatalf("HandleList nil response")
	}
	var body struct {
		Success  bool `json:"success"`
		Messages []struct {
			MessageID string `json:"message_id"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(resp.Payload, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !body.Success {
		t.Fatalf("HandleList not success: %s", string(resp.Payload))
	}
	out := make([]string, len(body.Messages))
	for i, m := range body.Messages {
		out[i] = m.MessageID
	}
	return out
}

// Regression: the previous HandleList parsed `before` but never applied
// it, so loadOlder on the desktop returned the same page forever. This
// asserts the cursor is honored and is strictly exclusive.
func TestHandleList_BeforeCursor(t *testing.T) {
	h, store, cleanup := setupMessagingHandler(t)
	defer cleanup()

	connID := "conn-test"
	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	seedMessages(t, store, connID, 5, base) // msg-000 … msg-004

	t.Run("no cursor returns latest N in oldest-first order", func(t *testing.T) {
		got := callList(t, h, connID, 50, "")
		want := []string{"msg-000", "msg-001", "msg-002", "msg-003", "msg-004"}
		if !equalStrings(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("before=msg-003 returns only strictly older messages", func(t *testing.T) {
		got := callList(t, h, connID, 50, "msg-003")
		want := []string{"msg-000", "msg-001", "msg-002"}
		if !equalStrings(got, want) {
			t.Fatalf("got %v, want %v (cursor must be exclusive)", got, want)
		}
	})

	t.Run("before=msg-000 (oldest) returns empty page", func(t *testing.T) {
		got := callList(t, h, connID, 50, "msg-000")
		if len(got) != 0 {
			t.Fatalf("expected empty page, got %v", got)
		}
	})

	t.Run("limit caps the page from the newest end after filtering", func(t *testing.T) {
		// before=msg-004 (newest) leaves msg-000..msg-003; limit 2 should
		// return the two newest of that set.
		got := callList(t, h, connID, 2, "msg-004")
		want := []string{"msg-002", "msg-003"}
		if !equalStrings(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("unknown before cursor surfaces an error", func(t *testing.T) {
		req, _ := json.Marshal(map[string]string{
			"connection_id": connID,
			"before":        "msg-nonexistent",
		})
		resp, err := h.HandleList(&IncomingMessage{ID: "x", Payload: req})
		if err != nil {
			t.Fatalf("HandleList err: %v", err)
		}
		var body struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		json.Unmarshal(resp.Payload, &body)
		if body.Success || body.Error == "" {
			t.Fatalf("expected error for unknown cursor, got %s", string(resp.Payload))
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
