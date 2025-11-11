package handlers

import (
	"encoding/json"
	"floaty/auth"
	"floaty/models"
	"floaty/storage"
	"html/template"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	mu              sync.RWMutex
	appPassword     string
	appUsername     string
	cookieMaxAge    int
	noAuth          bool
)

// Config holds the handler configuration
type Config struct {
	Username     string
	Password     string
	CookieMaxAge int
	NoAuth       bool
}

// InitHandlers initializes the handlers with configuration
func InitHandlers(cfg Config) {
	appUsername = cfg.Username
	appPassword = cfg.Password
	cookieMaxAge = cfg.CookieMaxAge
	noAuth = cfg.NoAuth
}

// ServeLogin serves the login page
func ServeLogin(w http.ResponseWriter, r *http.Request) {
	// If already logged in, redirect to home
	cookie, err := r.Cookie("floaty_session")
	if err == nil {
		if auth.IsValidSession(cookie.Value) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		http.Error(w, "Could not load template", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, nil)
}

// HandleLogin handles the login POST request
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Username != appUsername || req.Password != appPassword {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate new session token for this login
	sessionToken := auth.GenerateSessionToken()

	// Store session token
	auth.AddSession(sessionToken)

	// Set cookie with session token
	http.SetCookie(w, &http.Cookie{
		Name:     "floaty_session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   cookieMaxAge,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// ServeIndex serves the main index page
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()

	trackers, err := storage.LoadTrackers()
	if err != nil {
		http.Error(w, "Failed to load trackers", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Could not load template", http.StatusInternalServerError)
		return
	}

	data := struct {
		Trackers []models.Tracker
	}{
		Trackers: trackers,
	}

	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, data)
}

// ServeTracker serves the tracker page
func ServeTracker(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	tracker, err := storage.GetTracker(slug)
	if err != nil {
		http.Error(w, "Tracker not found", http.StatusNotFound)
		return
	}

	tmpl, err := template.ParseFiles("templates/tracker.html")
	if err != nil {
		http.Error(w, "Could not load template", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, tracker)
}

// CreateTracker creates a new tracker
func CreateTracker(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Title string `json:"title"`
		Slug  string `json:"slug"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Slug == "" {
		http.Error(w, "Title and slug are required", http.StatusBadRequest)
		return
	}

	if !models.IsValidSlug(req.Slug) {
		http.Error(w, "Invalid slug format (lowercase letters, numbers, hyphens only)", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	logFile := storage.GetLogFile(req.Slug)
	if _, err := os.Stat(logFile); err == nil {
		http.Error(w, "Tracker already exists", http.StatusConflict)
		return
	}

	// Create metadata event as first line
	metadata := models.Event{
		ID:        models.GenerateID(),
		Timestamp: time.Now().UTC(),
		Type:      models.EventMetadata,
		Note:      req.Title,
	}

	if err := storage.AppendEvent(req.Slug, metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.Tracker{
		Title:   req.Title,
		Slug:    req.Slug,
		Created: metadata.Timestamp,
	})
}

// DeleteTracker deletes a tracker
func DeleteTracker(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Slug string `json:"slug"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate slug to prevent path injection
	if !models.IsValidSlug(req.Slug) {
		http.Error(w, "Invalid slug format", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	logFile := storage.GetLogFile(req.Slug)
	if err := os.Remove(logFile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// GetTotal gets the total for a tracker
func GetTotal(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	mu.RLock()
	defer mu.RUnlock()

	events, err := storage.LoadEvents(slug)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	total := storage.CalculateTotal(events)
	json.NewEncoder(w).Encode(map[string]float64{"total": total})
}

// GetEvents gets all events for a tracker
func GetEvents(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	mu.RLock()
	defer mu.RUnlock()

	events, err := storage.LoadEvents(slug)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(events)
}

// AddValue adds a value to a tracker
func AddValue(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Value float64 `json:"value"`
		Note  string  `json:"note"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	event := models.Event{
		ID:        models.GenerateID(),
		Timestamp: time.Now().UTC(),
		Type:      models.EventManual,
		Value:     req.Value,
		Note:      req.Note,
	}

	mu.Lock()
	defer mu.Unlock()

	if err := storage.AppendEvent(slug, event); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(event)
}

// SubtractValue subtracts a value from a tracker
func SubtractValue(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Value float64 `json:"value"`
		Note  string  `json:"note"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	event := models.Event{
		ID:        models.GenerateID(),
		Timestamp: time.Now().UTC(),
		Type:      models.EventManual,
		Value:     -req.Value,
		Note:      req.Note,
	}

	mu.Lock()
	defer mu.Unlock()

	if err := storage.AppendEvent(slug, event); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(event)
}

// DeleteEvent deletes an event from a tracker
func DeleteEvent(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	event := models.Event{
		ID:        req.ID,
		Timestamp: time.Now().UTC(),
		Deleted:   true,
	}

	if err := storage.AppendEvent(slug, event); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// EditEvent edits an event in a tracker
func EditEvent(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID    string  `json:"id"`
		Value float64 `json:"value"`
		Note  string  `json:"note"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	// Create an edit event that references the original event
	event := models.Event{
		ID:        models.GenerateID(),
		Timestamp: time.Now().UTC(),
		Type:      models.EventManual,
		Value:     req.Value,
		Note:      req.Note,
		EditedID:  req.ID, // Reference to the original event being edited
	}

	if err := storage.AppendEvent(slug, event); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(event)
}

// GetCookieMaxAge returns the cookie max age configuration (for testing)
func GetCookieMaxAge() int {
	return cookieMaxAge
}

// GetAppUsername returns the username configuration (for testing)
func GetAppUsername() string {
	return appUsername
}
