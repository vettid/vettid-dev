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

// TestValidateUserGuid pins the #22 NATS-subject-injection guard.
// Crafted guids containing NATS wildcards or dots must be rejected
// BEFORE they reach a Subscribe/Publish call.
func TestValidateUserGuid(t *testing.T) {
	tests := []struct {
		name  string
		guid  string
		valid bool
	}{
		{"valid lowercase uuid", "4011a46f-6eef-45ae-af9d-7a8f3461f54f", true},
		{"empty", "", false},
		{"uppercase rejected", "4011A46F-6EEF-45AE-AF9D-7A8F3461F54F", false},
		{"missing dashes", "4011a46f6eef45aeaf9d7a8f3461f54f", false},
		{"nats greater-wildcard", "abc.foo>", false},
		{"nats star-wildcard", "abc.*.foo", false},
		{"dot injection in body", "4011a46f-6eef.45ae-af9d-7a8f3461f54f", false},
		{"trailing space", "4011a46f-6eef-45ae-af9d-7a8f3461f54f ", false},
		{"non-hex char", "4011a46g-6eef-45ae-af9d-7a8f3461f54f", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUserGuid(tt.guid)
			if tt.valid && err != nil {
				t.Errorf("expected valid for %q, got error: %v", tt.guid, err)
			}
			if !tt.valid && err == nil {
				t.Errorf("expected invalid for %q, got nil error", tt.guid)
			}
		})
	}
}
