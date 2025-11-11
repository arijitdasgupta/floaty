package handlers

import (
	"bytes"
	"encoding/json"
	"floaty/auth"
	"floaty/models"
	"floaty/storage"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestEnvironment(t *testing.T) (string, func()) {
	// Create a temporary directory for test data
	tempDir := filepath.Join(os.TempDir(), "floaty-test-handlers-"+time.Now().Format("20060102150405"))
	testDataDir := filepath.Join(tempDir, "data")
	os.MkdirAll(testDataDir, 0755)

	// Save original working directory
	originalWd, _ := os.Getwd()

	// Change to temp directory
	os.Chdir(tempDir)

	// Initialize auth and handlers
	auth.InitSessions()
	InitHandlers(Config{
		Username:     "testuser",
		Password:     "testpass",
		CookieMaxAge: 3600,
		NoAuth:       false,
	})

	cleanup := func() {
		os.Chdir(originalWd)
		os.RemoveAll(tempDir)
	}

	return tempDir, cleanup
}

func TestHandleLogin(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	tests := []struct {
		name           string
		username       string
		password       string
		expectedStatus int
	}{
		{"valid credentials", "testuser", "testpass", http.StatusOK},
		{"invalid username", "wronguser", "testpass", http.StatusUnauthorized},
		{"invalid password", "testuser", "wrongpass", http.StatusUnauthorized},
		{"empty credentials", "", "", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(map[string]string{
				"username": tt.username,
				"password": tt.password,
			})

			req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(reqBody))
			w := httptest.NewRecorder()

			HandleLogin(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("HandleLogin() status = %d, want %d", w.Code, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusOK {
				// Check that a cookie was set
				cookies := w.Result().Cookies()
				found := false
				for _, cookie := range cookies {
					if cookie.Name == "floaty_session" {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected floaty_session cookie to be set")
				}
			}
		})
	}
}

func TestCreateTracker(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	tests := []struct {
		name           string
		title          string
		slug           string
		expectedStatus int
	}{
		{"valid tracker", "My Tracker", "my-tracker", http.StatusCreated},
		{"invalid slug uppercase", "My Tracker", "My-Tracker", http.StatusBadRequest},
		{"invalid slug special chars", "My Tracker", "my@tracker", http.StatusBadRequest},
		{"empty title", "", "my-tracker", http.StatusBadRequest},
		{"empty slug", "My Tracker", "", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(map[string]string{
				"title": tt.title,
				"slug":  tt.slug,
			})

			req := httptest.NewRequest(http.MethodPost, "/api/trackers/create", bytes.NewBuffer(reqBody))
			w := httptest.NewRecorder()

			CreateTracker(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("CreateTracker() status = %d, want %d", w.Code, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusCreated {
				var response models.Tracker
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Errorf("Failed to decode response: %v", err)
				}
				if response.Title != tt.title || response.Slug != tt.slug {
					t.Errorf("CreateTracker() response = %+v, want title=%s slug=%s", response, tt.title, tt.slug)
				}
			}
		})
	}
}

func TestCreateTrackerDuplicate(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create a tracker
	reqBody, _ := json.Marshal(map[string]string{
		"title": "My Tracker",
		"slug":  "my-tracker",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/trackers/create", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()
	CreateTracker(w, req)

	// Try to create the same tracker again
	req = httptest.NewRequest(http.MethodPost, "/api/trackers/create", bytes.NewBuffer(reqBody))
	w = httptest.NewRecorder()
	CreateTracker(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("CreateTracker() duplicate status = %d, want %d", w.Code, http.StatusConflict)
	}
}

func TestAddValue(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create a tracker first
	metadata := models.Event{
		ID:        "metadata-id",
		Timestamp: time.Now().UTC(),
		Type:      models.EventMetadata,
		Note:      "Test Tracker",
	}
	storage.AppendEvent("test-tracker", metadata)

	tests := []struct {
		name           string
		value          float64
		note           string
		expectedStatus int
	}{
		{"positive value", 10.5, "Test note", http.StatusCreated},
		{"negative value", -5.5, "Test note", http.StatusCreated},
		{"zero value", 0.0, "", http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(map[string]interface{}{
				"value": tt.value,
				"note":  tt.note,
			})

			req := httptest.NewRequest(http.MethodPost, "/api/test-tracker/add", bytes.NewBuffer(reqBody))
			req.SetPathValue("slug", "test-tracker")
			w := httptest.NewRecorder()

			AddValue(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("AddValue() status = %d, want %d", w.Code, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusCreated {
				var response models.Event
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Errorf("Failed to decode response: %v", err)
				}
				if response.Value != tt.value {
					t.Errorf("AddValue() value = %v, want %v", response.Value, tt.value)
				}
				if response.Note != tt.note {
					t.Errorf("AddValue() note = %q, want %q", response.Note, tt.note)
				}
			}
		})
	}
}

func TestSubtractValue(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create a tracker first
	metadata := models.Event{
		ID:        "metadata-id",
		Timestamp: time.Now().UTC(),
		Type:      models.EventMetadata,
		Note:      "Test Tracker",
	}
	storage.AppendEvent("test-tracker", metadata)

	reqBody, _ := json.Marshal(map[string]interface{}{
		"value": 10.5,
		"note":  "Subtract test",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/test-tracker/subtract", bytes.NewBuffer(reqBody))
	req.SetPathValue("slug", "test-tracker")
	w := httptest.NewRecorder()

	SubtractValue(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("SubtractValue() status = %d, want %d", w.Code, http.StatusCreated)
	}

	var response models.Event
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	// Subtract should make the value negative
	if response.Value != -10.5 {
		t.Errorf("SubtractValue() value = %v, want %v", response.Value, -10.5)
	}
}

func TestGetTotal(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create a tracker and add some events
	metadata := models.Event{
		ID:        "metadata-id",
		Timestamp: time.Now().UTC(),
		Type:      models.EventMetadata,
		Note:      "Test Tracker",
	}
	storage.AppendEvent("test-tracker", metadata)

	event1 := models.Event{
		ID:        "event-1",
		Timestamp: time.Now().UTC(),
		Type:      models.EventManual,
		Value:     10.0,
	}
	storage.AppendEvent("test-tracker", event1)

	event2 := models.Event{
		ID:        "event-2",
		Timestamp: time.Now().UTC(),
		Type:      models.EventManual,
		Value:     20.5,
	}
	storage.AppendEvent("test-tracker", event2)

	req := httptest.NewRequest(http.MethodGet, "/api/test-tracker/total", nil)
	req.SetPathValue("slug", "test-tracker")
	w := httptest.NewRecorder()

	GetTotal(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GetTotal() status = %d, want %d", w.Code, http.StatusOK)
	}

	var response map[string]float64
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	expectedTotal := 30.5
	if response["total"] != expectedTotal {
		t.Errorf("GetTotal() total = %v, want %v", response["total"], expectedTotal)
	}
}

func TestGetEvents(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create a tracker and add some events
	metadata := models.Event{
		ID:        "metadata-id",
		Timestamp: time.Now().UTC(),
		Type:      models.EventMetadata,
		Note:      "Test Tracker",
	}
	storage.AppendEvent("test-tracker", metadata)

	event1 := models.Event{
		ID:        "event-1",
		Timestamp: time.Now().UTC(),
		Type:      models.EventManual,
		Value:     10.0,
	}
	storage.AppendEvent("test-tracker", event1)

	event2 := models.Event{
		ID:        "event-2",
		Timestamp: time.Now().UTC(),
		Type:      models.EventManual,
		Value:     20.5,
	}
	storage.AppendEvent("test-tracker", event2)

	req := httptest.NewRequest(http.MethodGet, "/api/test-tracker/events", nil)
	req.SetPathValue("slug", "test-tracker")
	w := httptest.NewRecorder()

	GetEvents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GetEvents() status = %d, want %d", w.Code, http.StatusOK)
	}

	var response []models.Event
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if len(response) != 2 {
		t.Errorf("GetEvents() returned %d events, want 2", len(response))
	}
}

func TestDeleteEvent(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create a tracker and add an event
	metadata := models.Event{
		ID:        "metadata-id",
		Timestamp: time.Now().UTC(),
		Type:      models.EventMetadata,
		Note:      "Test Tracker",
	}
	storage.AppendEvent("test-tracker", metadata)

	event1 := models.Event{
		ID:        "event-1",
		Timestamp: time.Now().UTC(),
		Type:      models.EventManual,
		Value:     10.0,
	}
	storage.AppendEvent("test-tracker", event1)

	// Delete the event
	reqBody, _ := json.Marshal(map[string]string{
		"id": "event-1",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/test-tracker/delete", bytes.NewBuffer(reqBody))
	req.SetPathValue("slug", "test-tracker")
	w := httptest.NewRecorder()

	DeleteEvent(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("DeleteEvent() status = %d, want %d", w.Code, http.StatusOK)
	}

	// Verify the event is deleted
	events, _ := storage.LoadEvents("test-tracker")
	if len(events) != 0 {
		t.Errorf("After deletion, expected 0 events, got %d", len(events))
	}
}

func TestEditEvent(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create a tracker and add an event
	metadata := models.Event{
		ID:        "metadata-id",
		Timestamp: time.Now().UTC(),
		Type:      models.EventMetadata,
		Note:      "Test Tracker",
	}
	storage.AppendEvent("test-tracker", metadata)

	originalTime := time.Now().UTC()
	event1 := models.Event{
		ID:        "event-1",
		Timestamp: originalTime,
		Type:      models.EventManual,
		Value:     10.0,
		Note:      "Original note",
	}
	storage.AppendEvent("test-tracker", event1)

	// Edit the event
	reqBody, _ := json.Marshal(map[string]interface{}{
		"id":    "event-1",
		"value": 15.5,
		"note":  "Edited note",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/test-tracker/edit", bytes.NewBuffer(reqBody))
	req.SetPathValue("slug", "test-tracker")
	w := httptest.NewRecorder()

	EditEvent(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("EditEvent() status = %d, want %d", w.Code, http.StatusOK)
	}

	// Verify the event is edited
	events, _ := storage.LoadEvents("test-tracker")
	if len(events) != 1 {
		t.Errorf("After editing, expected 1 event, got %d", len(events))
	}

	if len(events) > 0 {
		if events[0].Value != 15.5 {
			t.Errorf("After editing, expected value 15.5, got %v", events[0].Value)
		}
		if events[0].Note != "Edited note" {
			t.Errorf("After editing, expected note 'Edited note', got %q", events[0].Note)
		}
	}
}

func TestDeleteTrackerInvalidSlug(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	tests := []struct {
		name           string
		slug           string
		expectedStatus int
	}{
		{"invalid uppercase", "MyTracker", http.StatusBadRequest},
		{"invalid special chars", "../../../etc/passwd", http.StatusBadRequest},
		{"invalid path traversal", "../../test", http.StatusBadRequest},
		{"empty slug", "", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(map[string]string{
				"slug": tt.slug,
			})

			req := httptest.NewRequest(http.MethodPost, "/api/trackers/delete", bytes.NewBuffer(reqBody))
			w := httptest.NewRecorder()

			DeleteTracker(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("DeleteTracker() with invalid slug status = %d, want %d", w.Code, tt.expectedStatus)
			}
		})
	}
}

func TestInitHandlers(t *testing.T) {
	// Test configuration initialization
	InitHandlers(Config{
		Username:     "testuser",
		Password:     "testpass",
		CookieMaxAge: 7200,
		NoAuth:       false,
	})

	if GetAppUsername() != "testuser" {
		t.Errorf("Expected username 'testuser', got %q", GetAppUsername())
	}

	if GetCookieMaxAge() != 7200 {
		t.Errorf("Expected cookie max age 7200, got %d", GetCookieMaxAge())
	}
}
