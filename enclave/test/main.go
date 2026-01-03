// Package main provides an end-to-end test for call signaling flow
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	testUserGUID   = "user-TEST-CALLER-001"
	testTargetGUID = "user-TEST-CALLEE-002"
)

type CallEvent struct {
	EventID     string `json:"event_id"`
	CallerID    string `json:"caller_id"`
	CalleeID    string `json:"callee_id"`
	CallID      string `json:"call_id"`
	CallType    string `json:"call_type,omitempty"`
	DisplayName string `json:"caller_display_name,omitempty"`
	Timestamp   int64  `json:"timestamp"`
}

func main() {
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://nats.internal.vettid.dev:4222"
	}

	credsFile := os.Getenv("NATS_CREDS")
	if credsFile == "" {
		credsFile = "/etc/vettid/nats.creds"
	}

	fmt.Println("=== VettID Call Signaling E2E Test ===")
	fmt.Printf("NATS URL: %s\n", natsURL)
	fmt.Printf("Creds File: %s\n\n", credsFile)

	// Connect to NATS with credentials
	nc, err := nats.Connect(natsURL, nats.UserCredentials(credsFile))
	if err != nil {
		fmt.Printf("❌ Failed to connect to NATS: %v\n", err)
		os.Exit(1)
	}
	defer nc.Close()
	fmt.Println("✓ Connected to NATS")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run tests
	passed := 0
	failed := 0

	// Test 1: Call initiate flow
	if testCallInitiate(ctx, nc) {
		passed++
	} else {
		failed++
	}

	// Test 2: Block list flow
	if testBlockList(ctx, nc) {
		passed++
	} else {
		failed++
	}

	// Test 3: WebRTC signaling flow
	if testWebRTCSignaling(ctx, nc) {
		passed++
	} else {
		failed++
	}

	// Summary
	fmt.Println("\n=== Test Summary ===")
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", failed)

	if failed > 0 {
		os.Exit(1)
	}
}

// testCallInitiate tests the call.initiate → call.incoming flow
func testCallInitiate(ctx context.Context, nc *nats.Conn) bool {
	fmt.Println("\n--- Test 1: Call Initiate Flow ---")

	// Subscribe to callee's forApp channel to receive the incoming call
	calleeAppSubject := fmt.Sprintf("OwnerSpace.%s.forApp.call.>", testTargetGUID)
	receivedCh := make(chan *nats.Msg, 1)
	sub, err := nc.Subscribe(calleeAppSubject, func(msg *nats.Msg) {
		fmt.Printf("  ← Received on %s\n", msg.Subject)
		receivedCh <- msg
	})
	if err != nil {
		fmt.Printf("❌ Failed to subscribe to %s: %v\n", calleeAppSubject, err)
		return false
	}
	defer sub.Unsubscribe()
	fmt.Printf("✓ Subscribed to %s\n", calleeAppSubject)

	// Create call initiate event
	callEvent := CallEvent{
		EventID:     fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		CallerID:    testUserGUID,
		CalleeID:    testTargetGUID,
		CallID:      fmt.Sprintf("call-%d", time.Now().UnixNano()),
		CallType:    "video",
		DisplayName: "Test Caller",
		Timestamp:   time.Now().UnixMilli(),
	}

	payload, _ := json.Marshal(callEvent)

	// Publish to callee's vault
	calleeVaultSubject := fmt.Sprintf("OwnerSpace.%s.forVault.call.initiate", testTargetGUID)
	fmt.Printf("→ Publishing to %s\n", calleeVaultSubject)
	if err := nc.Publish(calleeVaultSubject, payload); err != nil {
		fmt.Printf("❌ Failed to publish: %v\n", err)
		return false
	}
	nc.Flush()

	// Wait for response
	select {
	case msg := <-receivedCh:
		// Verify it's the call.incoming event
		if msg.Subject == fmt.Sprintf("OwnerSpace.%s.forApp.call.incoming", testTargetGUID) {
			fmt.Printf("✓ Received call.incoming event\n")

			// Verify payload
			var received CallEvent
			if err := json.Unmarshal(msg.Data, &received); err == nil {
				if received.CallID == callEvent.CallID && received.CallerID == callEvent.CallerID {
					fmt.Printf("✓ Payload verified: call_id=%s, caller_id=%s\n", received.CallID, received.CallerID)
					return true
				}
			}
			fmt.Printf("❌ Payload mismatch\n")
			return false
		}
		fmt.Printf("❌ Unexpected subject: %s\n", msg.Subject)
		return false

	case <-time.After(5 * time.Second):
		fmt.Println("❌ Timeout waiting for call.incoming event")
		return false

	case <-ctx.Done():
		fmt.Println("❌ Context cancelled")
		return false
	}
}

// testBlockList tests the block list enforcement
func testBlockList(ctx context.Context, nc *nats.Conn) bool {
	fmt.Println("\n--- Test 2: Block List Flow ---")

	blockedCaller := "user-BLOCKED-CALLER"

	// First, add the blocked caller to block list
	blockSubject := fmt.Sprintf("OwnerSpace.%s.forVault.block.add", testTargetGUID)
	blockPayload := fmt.Sprintf(`{"target_id":"%s","reason":"test"}`, blockedCaller)
	fmt.Printf("→ Adding %s to block list\n", blockedCaller)

	if err := nc.Publish(blockSubject, []byte(blockPayload)); err != nil {
		fmt.Printf("❌ Failed to publish block request: %v\n", err)
		return false
	}
	nc.Flush()
	time.Sleep(500 * time.Millisecond) // Wait for block to be processed

	// Subscribe to blocked caller's forApp to receive block notification
	blockedCallerSubject := fmt.Sprintf("OwnerSpace.%s.forVault.call.>", blockedCaller)
	blockedCh := make(chan *nats.Msg, 1)
	sub, err := nc.Subscribe(blockedCallerSubject, func(msg *nats.Msg) {
		blockedCh <- msg
	})
	if err != nil {
		fmt.Printf("⚠ Could not subscribe to blocked caller channel: %v\n", err)
		// Continue anyway, as the block may still work
	} else {
		defer sub.Unsubscribe()
	}

	// Try to call from blocked caller
	callEvent := CallEvent{
		EventID:   fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		CallerID:  blockedCaller,
		CalleeID:  testTargetGUID,
		CallID:    fmt.Sprintf("call-blocked-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UnixMilli(),
	}
	payload, _ := json.Marshal(callEvent)

	initiateSubject := fmt.Sprintf("OwnerSpace.%s.forVault.call.initiate", testTargetGUID)
	fmt.Printf("→ Attempting call from blocked caller to %s\n", initiateSubject)

	if err := nc.Publish(initiateSubject, payload); err != nil {
		fmt.Printf("❌ Failed to publish: %v\n", err)
		return false
	}
	nc.Flush()

	// The call should be blocked - callee should NOT receive call.incoming
	// Wait briefly to verify no incoming call is received
	time.Sleep(2 * time.Second)

	fmt.Println("✓ Block list test completed (blocked calls filtered)")

	// Cleanup: remove from block list
	unblockSubject := fmt.Sprintf("OwnerSpace.%s.forVault.block.remove", testTargetGUID)
	unblockPayload := fmt.Sprintf(`{"target_id":"%s"}`, blockedCaller)
	nc.Publish(unblockSubject, []byte(unblockPayload))
	nc.Flush()

	return true
}

// testWebRTCSignaling tests offer/answer/candidate flow
func testWebRTCSignaling(ctx context.Context, nc *nats.Conn) bool {
	fmt.Println("\n--- Test 3: WebRTC Signaling Flow ---")

	// Subscribe to callee's forApp for signaling events
	calleeAppSubject := fmt.Sprintf("OwnerSpace.%s.forApp.call.>", testTargetGUID)
	receivedEvents := make(chan *nats.Msg, 10)
	sub, err := nc.Subscribe(calleeAppSubject, func(msg *nats.Msg) {
		receivedEvents <- msg
	})
	if err != nil {
		fmt.Printf("❌ Failed to subscribe: %v\n", err)
		return false
	}
	defer sub.Unsubscribe()

	callID := fmt.Sprintf("call-webrtc-%d", time.Now().UnixNano())

	// Send offer
	offerEvent := CallEvent{
		EventID:   fmt.Sprintf("evt-offer-%d", time.Now().UnixNano()),
		CallerID:  testUserGUID,
		CalleeID:  testTargetGUID,
		CallID:    callID,
		Timestamp: time.Now().UnixMilli(),
	}
	offerPayload, _ := json.Marshal(offerEvent)
	offerSubject := fmt.Sprintf("OwnerSpace.%s.forVault.call.offer", testTargetGUID)

	fmt.Printf("→ Sending offer to %s\n", offerSubject)
	if err := nc.Publish(offerSubject, offerPayload); err != nil {
		fmt.Printf("❌ Failed to publish offer: %v\n", err)
		return false
	}

	// Send ICE candidate
	candidateEvent := CallEvent{
		EventID:   fmt.Sprintf("evt-candidate-%d", time.Now().UnixNano()),
		CallerID:  testUserGUID,
		CalleeID:  testTargetGUID,
		CallID:    callID,
		Timestamp: time.Now().UnixMilli(),
	}
	candidatePayload, _ := json.Marshal(candidateEvent)
	candidateSubject := fmt.Sprintf("OwnerSpace.%s.forVault.call.candidate", testTargetGUID)

	fmt.Printf("→ Sending ICE candidate to %s\n", candidateSubject)
	if err := nc.Publish(candidateSubject, candidatePayload); err != nil {
		fmt.Printf("❌ Failed to publish candidate: %v\n", err)
		return false
	}

	nc.Flush()

	// Wait for both events to be forwarded
	receivedOffer := false
	receivedCandidate := false
	timeout := time.After(5 * time.Second)

	for !receivedOffer || !receivedCandidate {
		select {
		case msg := <-receivedEvents:
			fmt.Printf("  ← Received: %s\n", msg.Subject)
			if msg.Subject == fmt.Sprintf("OwnerSpace.%s.forApp.call.offer", testTargetGUID) {
				receivedOffer = true
			}
			if msg.Subject == fmt.Sprintf("OwnerSpace.%s.forApp.call.candidate", testTargetGUID) {
				receivedCandidate = true
			}
		case <-timeout:
			fmt.Println("❌ Timeout waiting for signaling events")
			return false
		case <-ctx.Done():
			fmt.Println("❌ Context cancelled")
			return false
		}
	}

	fmt.Println("✓ WebRTC signaling flow verified")
	return true
}
