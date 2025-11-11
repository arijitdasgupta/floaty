package storage

import (
	"floaty/models"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetLogFile(t *testing.T) {
	tests := []struct {
		slug     string
		expected string
	}{
		{"test-tracker", filepath.Join("data", "test-tracker.log")},
		{"my-tracker-123", filepath.Join("data", "my-tracker-123.log")},
		{"a", filepath.Join("data", "a.log")},
	}

	for _, tt := range tests {
		t.Run(tt.slug, func(t *testing.T) {
			result := GetLogFile(tt.slug)
			if result != tt.expected {
				t.Errorf("GetLogFile(%q) = %q, want %q", tt.slug, result, tt.expected)
			}
		})
	}
}

func TestCalculateTotal(t *testing.T) {
	tests := []struct {
		name     string
		events   []models.Event
		expected float64
	}{
		{
			name:     "empty events",
			events:   []models.Event{},
			expected: 0.0,
		},
		{
			name: "single positive value",
			events: []models.Event{
				{Value: 10.5},
			},
			expected: 10.5,
		},
		{
			name: "single negative value",
			events: []models.Event{
				{Value: -5.5},
			},
			expected: -5.5,
		},
		{
			name: "multiple positive values",
			events: []models.Event{
				{Value: 10.0},
				{Value: 20.0},
				{Value: 30.0},
			},
			expected: 60.0,
		},
		{
			name: "mixed positive and negative values",
			events: []models.Event{
				{Value: 100.0},
				{Value: -25.5},
				{Value: 50.0},
				{Value: -10.5},
			},
			expected: 114.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateTotal(tt.events)
			if result != tt.expected {
				t.Errorf("CalculateTotal() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAppendEventAndLoadEvents(t *testing.T) {
	// Create a temporary directory for test data
	tempDir := filepath.Join(os.TempDir(), "floaty-test-storage")
	defer os.RemoveAll(tempDir)

	// Override the data directory by using a test slug in a temp location
	slug := "test-append-load"
	testDataDir := filepath.Join(tempDir, "data")
	os.MkdirAll(testDataDir, 0755)

	// Save original working directory
	originalWd, _ := os.Getwd()
	defer os.Chdir(originalWd)

	// Change to temp directory so GetLogFile uses it
	os.Chdir(tempDir)

	// Create a metadata event
	metadata := models.Event{
		ID:        "metadata-id",
		Timestamp: time.Now().UTC(),
		Type:      models.EventMetadata,
		Note:      "Test Tracker",
	}

	err := AppendEvent(slug, metadata)
	if err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}

	// Create a manual event
	event1 := models.Event{
		ID:        "event-1",
		Timestamp: time.Now().UTC(),
		Type:      models.EventManual,
		Value:     10.5,
		Note:      "First event",
	}

	err = AppendEvent(slug, event1)
	if err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}

	// Create another manual event
	event2 := models.Event{
		ID:        "event-2",
		Timestamp: time.Now().UTC(),
		Type:      models.EventManual,
		Value:     -5.5,
		Note:      "Second event",
	}

	err = AppendEvent(slug, event2)
	if err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}

	// Load events and verify
	events, err := LoadEvents(slug)
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}

	// Should only have manual events (metadata filtered out)
	if len(events) != 2 {
		t.Errorf("LoadEvents() returned %d events, want 2", len(events))
	}

	// Verify the events
	if events[0].ID != "event-1" || events[0].Value != 10.5 {
		t.Errorf("First event mismatch: got %+v", events[0])
	}

	if events[1].ID != "event-2" || events[1].Value != -5.5 {
		t.Errorf("Second event mismatch: got %+v", events[1])
	}
}

func TestLoadEventsWithDeletions(t *testing.T) {
	// Create a temporary directory for test data
	tempDir := filepath.Join(os.TempDir(), "floaty-test-deletions")
	defer os.RemoveAll(tempDir)

	slug := "test-deletions"
	testDataDir := filepath.Join(tempDir, "data")
	os.MkdirAll(testDataDir, 0755)

	// Save original working directory
	originalWd, _ := os.Getwd()
	defer os.Chdir(originalWd)

	// Change to temp directory
	os.Chdir(tempDir)

	// Create metadata
	metadata := models.Event{
		ID:        "metadata-id",
		Timestamp: time.Now().UTC(),
		Type:      models.EventMetadata,
		Note:      "Test Tracker",
	}
	AppendEvent(slug, metadata)

	// Create events
	event1 := models.Event{
		ID:        "event-1",
		Timestamp: time.Now().UTC(),
		Type:      models.EventManual,
		Value:     10.0,
	}
	AppendEvent(slug, event1)

	event2 := models.Event{
		ID:        "event-2",
		Timestamp: time.Now().UTC(),
		Type:      models.EventManual,
		Value:     20.0,
	}
	AppendEvent(slug, event2)

	// Delete event-1
	deleteEvent := models.Event{
		ID:        "event-1",
		Timestamp: time.Now().UTC(),
		Deleted:   true,
	}
	AppendEvent(slug, deleteEvent)

	// Load events
	events, err := LoadEvents(slug)
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}

	// Should only have event-2 (event-1 deleted)
	if len(events) != 1 {
		t.Errorf("LoadEvents() returned %d events, want 1", len(events))
	}

	if len(events) > 0 && events[0].ID != "event-2" {
		t.Errorf("Expected event-2, got %s", events[0].ID)
	}
}

func TestLoadEventsWithEdits(t *testing.T) {
	// Create a temporary directory for test data
	tempDir := filepath.Join(os.TempDir(), "floaty-test-edits")
	defer os.RemoveAll(tempDir)

	slug := "test-edits"
	testDataDir := filepath.Join(tempDir, "data")
	os.MkdirAll(testDataDir, 0755)

	// Save original working directory
	originalWd, _ := os.Getwd()
	defer os.Chdir(originalWd)

	// Change to temp directory
	os.Chdir(tempDir)

	// Create metadata
	metadata := models.Event{
		ID:        "metadata-id",
		Timestamp: time.Now().UTC(),
		Type:      models.EventMetadata,
		Note:      "Test Tracker",
	}
	AppendEvent(slug, metadata)

	// Create original event with specific timestamp
	originalTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	event1 := models.Event{
		ID:        "event-1",
		Timestamp: originalTime,
		Type:      models.EventManual,
		Value:     10.0,
		Note:      "Original note",
	}
	AppendEvent(slug, event1)

	// Edit the event
	editTime := time.Now().UTC()
	editEvent := models.Event{
		ID:        "edit-1",
		Timestamp: editTime,
		Type:      models.EventManual,
		Value:     15.0,
		Note:      "Edited note",
		EditedID:  "event-1",
	}
	AppendEvent(slug, editEvent)

	// Load events
	events, err := LoadEvents(slug)
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}

	// Should only have one event (the edited version)
	if len(events) != 1 {
		t.Errorf("LoadEvents() returned %d events, want 1", len(events))
	}

	if len(events) > 0 {
		// Should have the edited value and note
		if events[0].Value != 15.0 {
			t.Errorf("Expected value 15.0, got %v", events[0].Value)
		}
		if events[0].Note != "Edited note" {
			t.Errorf("Expected note 'Edited note', got %q", events[0].Note)
		}
		// Should preserve the original timestamp
		if !events[0].Timestamp.Equal(originalTime) {
			t.Errorf("Expected timestamp %v, got %v", originalTime, events[0].Timestamp)
		}
	}
}

func TestLoadEventsNonExistent(t *testing.T) {
	// Test loading events from a non-existent tracker
	events, err := LoadEvents("non-existent-slug-xyz")
	if err != nil {
		t.Errorf("LoadEvents() for non-existent slug should not error, got %v", err)
	}

	if len(events) != 0 {
		t.Errorf("LoadEvents() for non-existent slug returned %d events, want 0", len(events))
	}
}
