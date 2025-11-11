package models

import (
	"testing"
)

func TestIsValidSlug(t *testing.T) {
	tests := []struct {
		name     string
		slug     string
		expected bool
	}{
		{"valid lowercase", "my-tracker", true},
		{"valid numbers", "tracker123", true},
		{"valid with hyphens", "my-tracker-123", true},
		{"invalid uppercase", "MyTracker", false},
		{"invalid underscore", "my_tracker", false},
		{"invalid special chars", "my@tracker", false},
		{"invalid empty", "", false},
		{"invalid too long", "a123456789012345678901234567890123456789012345678901", false},
		{"valid max length", "a1234567890123456789012345678901234567890123456789", true},
		{"valid single char", "a", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidSlug(tt.slug)
			if result != tt.expected {
				t.Errorf("IsValidSlug(%q) = %v, want %v", tt.slug, result, tt.expected)
			}
		})
	}
}

func TestGenerateID(t *testing.T) {
	// Test that GenerateID creates a non-empty string
	id := GenerateID()
	if id == "" {
		t.Error("GenerateID() returned empty string")
	}

	// Test that GenerateID creates unique IDs
	id2 := GenerateID()
	if id == id2 {
		t.Error("GenerateID() returned duplicate IDs")
	}

	// Test that GenerateID creates hex strings of expected length (16 bytes = 32 hex chars)
	if len(id) != 32 {
		t.Errorf("GenerateID() returned ID of length %d, expected 32", len(id))
	}
}

func TestEventTypes(t *testing.T) {
	if EventManual != "manual" {
		t.Errorf("EventManual = %q, want %q", EventManual, "manual")
	}
	if EventMetadata != "metadata" {
		t.Errorf("EventMetadata = %q, want %q", EventMetadata, "metadata")
	}
}
