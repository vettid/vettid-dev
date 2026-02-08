package main

import "testing"

func TestIsForOwnerSubject(t *testing.T) {
	tests := []struct {
		subject string
		want    bool
	}{
		{"MessageSpace.abc-123.forOwner.agent", true},
		{"MessageSpace.abc-123.forOwner.agent.conn-1", true},
		{"OwnerSpace.abc-123.forVault.pin-setup", false},
		{"OwnerSpace.abc-123.forVault.agent-secrets.share", false},
		{"MessageSpace.abc-123.fromService.svc1.data", false},
		{"Control.global.health", false},
		{"", false},
		{"forOwner", false},  // No dots around it
		{".forOwner.", true}, // Minimal match
	}

	for _, tt := range tests {
		got := isForOwnerSubject(tt.subject)
		if got != tt.want {
			t.Errorf("isForOwnerSubject(%q) = %v, want %v", tt.subject, got, tt.want)
		}
	}
}

func TestBuildAppResponseSubjectForOwner(t *testing.T) {
	// forOwner subjects should NOT generate app response subjects
	result := buildAppResponseSubject("MessageSpace.abc-123.forOwner.agent", "abc-123")
	if result != "" {
		t.Errorf("Expected empty response subject for forOwner, got %q", result)
	}
}

func TestExtractOwnerSpaceForOwner(t *testing.T) {
	ownerSpace, err := extractOwnerSpace("MessageSpace.abc-123.forOwner.agent")
	if err != nil {
		t.Fatalf("extractOwnerSpace failed: %v", err)
	}
	if ownerSpace != "abc-123" {
		t.Errorf("Expected owner space 'abc-123', got %q", ownerSpace)
	}
}
