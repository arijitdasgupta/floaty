package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type EventType string

const (
	EventManual   EventType = "manual"
	EventMetadata EventType = "metadata"
)

type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Type      EventType `json:"type"`
	Value     float64   `json:"value"`
	Note      string    `json:"note,omitempty"`
	Deleted   bool      `json:"deleted,omitempty"`
}

type Tracker struct {
	Title   string    `json:"title"`
	Slug    string    `json:"slug"`
	Created time.Time `json:"created,omitempty"`
}

var (
	mu              sync.RWMutex
	activeSessions  map[string]bool
	appPassword     string
	appUsername     string
)

func main() {
	// Initialize session storage
	activeSessions = make(map[string]bool)
	
	// Load credentials from environment or use defaults
	appUsername = os.Getenv("FLOATY_USERNAME")
	if appUsername == "" {
		appUsername = "admin"
		log.Println("Warning: Using default username 'admin'. Set FLOATY_USERNAME environment variable for production.")
	}
	
	appPassword = os.Getenv("FLOATY_PASSWORD")
	if appPassword == "" {
		appPassword = "floaty"
		log.Println("Warning: Using default password 'floaty'. Set FLOATY_PASSWORD environment variable for production.")
	}
	
	r := chi.NewRouter()
	
	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	
	// Static files (no auth required)
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	
	// Login routes (no auth required)
	r.Get("/login", serveLogin)
	r.Post("/login", handleLogin)
	
	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(requireAuth)
		
		// Homepage
		r.Get("/", serveIndex)
		
		// Tracker management
		r.Post("/api/trackers/create", createTracker)
		r.Post("/api/trackers/delete", deleteTracker)
		
		// Tracker routes
		r.Route("/{slug}", func(r chi.Router) {
			r.Use(validateSlug)
			r.Get("/", serveTracker)
		})
		
		// API routes
		r.Route("/api/{slug}", func(r chi.Router) {
			r.Use(validateSlug)
			r.Get("/total", getTotal)
			r.Get("/events", getEvents)
			r.Post("/add", addValue)
			r.Post("/subtract", subtractValue)
			r.Post("/delete", deleteEvent)
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}

func loadTrackers() ([]Tracker, error) {
	mu.RLock()
	defer mu.RUnlock()
	
	os.MkdirAll("data", 0755)
	
	files, err := filepath.Glob("data/*.log")
	if err != nil {
		return nil, err
	}
	
	var trackers []Tracker
	for _, filePath := range files {
		slug := strings.TrimSuffix(filepath.Base(filePath), ".log")
		
		// Read first line to get metadata
		file, err := os.Open(filePath)
		if err != nil {
			continue
		}
		
		scanner := bufio.NewScanner(file)
		if scanner.Scan() {
			var event Event
			if err := json.Unmarshal(scanner.Bytes(), &event); err == nil {
				if event.Type == EventMetadata {
					trackers = append(trackers, Tracker{
						Title:   event.Note,
						Slug:    slug,
						Created: event.Timestamp,
					})
				}
			}
		}
		file.Close()
	}
	
	// Sort by creation time
	sort.Slice(trackers, func(i, j int) bool {
		return trackers[i].Created.Before(trackers[j].Created)
	})
	
	return trackers, nil
}

func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("floaty_session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		
		mu.RLock()
		valid := activeSessions[cookie.Value]
		mu.RUnlock()
		
		if !valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func serveLogin(w http.ResponseWriter, r *http.Request) {
	// If already logged in, redirect to home
	cookie, err := r.Cookie("floaty_session")
	if err == nil {
		mu.RLock()
		valid := activeSessions[cookie.Value]
		mu.RUnlock()
		
		if valid {
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

func handleLogin(w http.ResponseWriter, r *http.Request) {
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
	sessionToken := generateSessionToken()
	
	// Store session token
	mu.Lock()
	activeSessions[sessionToken] = true
	mu.Unlock()
	
	// Set cookie with session token
	http.SetCookie(w, &http.Cookie{
		Name:     "floaty_session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400 * 30, // 30 days
	})
	
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}


func validateSlug(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "slug")
		
		if !isValidSlug(slug) {
			http.Error(w, "Invalid slug format", http.StatusBadRequest)
			return
		}
		
		logFile := getLogFile(slug)
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			serve404(w)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func isValidSlug(slug string) bool {
	match, _ := regexp.MatchString("^[a-z0-9-]+$", slug)
	return match && len(slug) > 0 && len(slug) <= 50
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		serve404(w)
		return
	}
	
	trackers, err := loadTrackers()
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
		Trackers []Tracker
	}{
		Trackers: trackers,
	}
	
	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, data)
}

func serveTracker(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	
	tracker, err := getTracker(slug)
	if err != nil {
		serve404(w)
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

func serve404(w http.ResponseWriter) {
	file, err := os.Open("templates/404.html")
	if err != nil {
		http.Error(w, "404 - Page Not Found", http.StatusNotFound)
		return
	}
	defer file.Close()

	w.WriteHeader(http.StatusNotFound)
	w.Header().Set("Content-Type", "text/html")
	io.Copy(w, file)
}

func getTracker(slug string) (*Tracker, error) {
	logFile := getLogFile(slug)
	file, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err == nil {
			if event.Type == EventMetadata {
				return &Tracker{
					Title:   event.Note,
					Slug:    slug,
					Created: event.Timestamp,
				}, nil
			}
		}
	}
	
	return &Tracker{Title: slug, Slug: slug}, nil
}

func getLogFile(slug string) string {
	return filepath.Join("data", slug+".log")
}

func createTracker(w http.ResponseWriter, r *http.Request) {
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
	
	if !isValidSlug(req.Slug) {
		http.Error(w, "Invalid slug format (lowercase letters, numbers, hyphens only)", http.StatusBadRequest)
		return
	}
	
	mu.Lock()
	defer mu.Unlock()
	
	logFile := getLogFile(req.Slug)
	if _, err := os.Stat(logFile); err == nil {
		http.Error(w, "Tracker already exists", http.StatusConflict)
		return
	}
	
	// Create metadata event as first line
	metadata := Event{
		ID:        generateID(),
		Timestamp: time.Now().UTC(),
		Type:      EventMetadata,
		Note:      req.Title,
	}
	
	if err := appendEvent(req.Slug, metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(Tracker{
		Title:   req.Title,
		Slug:    req.Slug,
		Created: metadata.Timestamp,
	})
}

func deleteTracker(w http.ResponseWriter, r *http.Request) {
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
	
	mu.Lock()
	defer mu.Unlock()
	
	logFile := getLogFile(req.Slug)
	if err := os.Remove(logFile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func getTotal(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	
	mu.RLock()
	defer mu.RUnlock()

	events, err := loadEvents(slug)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	total := calculateTotal(events)
	json.NewEncoder(w).Encode(map[string]float64{"total": total})
}

func getEvents(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	
	mu.RLock()
	defer mu.RUnlock()

	events, err := loadEvents(slug)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(events)
}

func addValue(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	
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

	event := Event{
		ID:        generateID(),
		Timestamp: time.Now().UTC(),
		Type:      EventManual,
		Value:     req.Value,
		Note:      req.Note,
	}

	mu.Lock()
	defer mu.Unlock()

	if err := appendEvent(slug, event); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(event)
}

func subtractValue(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	
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

	event := Event{
		ID:        generateID(),
		Timestamp: time.Now().UTC(),
		Type:      EventManual,
		Value:     -req.Value,
		Note:      req.Note,
	}

	mu.Lock()
	defer mu.Unlock()

	if err := appendEvent(slug, event); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(event)
}

func deleteEvent(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	
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

	event := Event{
		ID:        req.ID,
		Timestamp: time.Now().UTC(),
		Deleted:   true,
	}

	if err := appendEvent(slug, event); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func loadEvents(slug string) ([]Event, error) {
	logFile := getLogFile(slug)
	file, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []Event{}, nil
		}
		return nil, err
	}
	defer file.Close()

	var allEvents []Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			log.Printf("Failed to parse event: %v", err)
			continue
		}
		// Skip metadata events
		if event.Type != EventMetadata {
			allEvents = append(allEvents, event)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Apply deletions
	deletedIDs := make(map[string]bool)
	for _, event := range allEvents {
		if event.Deleted {
			deletedIDs[event.ID] = true
		}
	}

	// Filter out deleted events and deletion markers
	var events []Event
	for _, event := range allEvents {
		if !event.Deleted && !deletedIDs[event.ID] {
			events = append(events, event)
		}
	}

	return events, nil
}

func appendEvent(slug string, event Event) error {
	logFile := getLogFile(slug)
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	_, err = file.Write(append(data, '\n'))
	return err
}

func calculateTotal(events []Event) float64 {
	total := 0.0
	for _, event := range events {
		total += event.Value
	}
	return total
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
