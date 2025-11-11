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
"strconv"
"strings"
"sync"
"time"
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
EditedID  string    `json:"edited_id,omitempty"` // ID of event being edited
}

type Tracker struct {
Title   string    `json:"title"`
Slug    string    `json:"slug"`
Created time.Time `json:"created,omitempty"`
Total   float64   `json:"total,omitempty"`
}

var (
mu              sync.RWMutex
activeSessions  map[string]bool
appPassword     string
appUsername     string
cookieMaxAge    int
noAuth          bool
)

// loggingMiddleware logs HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
start := time.Now()
next.ServeHTTP(w, r)
log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
})
}

// withAuth wraps a handler with authentication check
func withAuth(handler http.HandlerFunc) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
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

handler(w, r)
}
}

// wrapWithSlugValidation wraps a handler with slug validation
func wrapWithSlugValidation(handler http.HandlerFunc) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
slug := r.PathValue("slug")

if !isValidSlug(slug) {
http.Error(w, "Invalid slug format", http.StatusBadRequest)
return
}

logFile := getLogFile(slug)
if _, err := os.Stat(logFile); os.IsNotExist(err) {
serve404(w)
return
}

handler(w, r)
}
}

func main() {
// Initialize session storage
activeSessions = make(map[string]bool)

// Check if running in no-auth mode
noAuth = os.Getenv("FLOATY_NO_AUTH") == "true"
if noAuth {
log.Println("Warning: Running in NO AUTH mode. Application is publicly accessible!")
}

// Load credentials from environment or use defaults
appUsername = os.Getenv("FLOATY_USERNAME")
if appUsername == "" {
appUsername = "admin"
if !noAuth {
log.Println("Warning: Using default username 'admin'. Set FLOATY_USERNAME environment variable for production.")
}
}

appPassword = os.Getenv("FLOATY_PASSWORD")
if appPassword == "" {
appPassword = "floaty"
if !noAuth {
log.Println("Warning: Using default password 'floaty'. Set FLOATY_PASSWORD environment variable for production.")
}
}

// Load cookie max age from environment or use default (3 days)
cookieMaxAge = 86400 * 3 // 3 days in seconds
if maxAgeStr := os.Getenv("FLOATY_COOKIE_MAX_AGE"); maxAgeStr != "" {
if maxAge, err := strconv.Atoi(maxAgeStr); err == nil && maxAge > 0 {
cookieMaxAge = maxAge
log.Printf("Using cookie max age: %d seconds", cookieMaxAge)
} else {
log.Printf("Warning: Invalid FLOATY_COOKIE_MAX_AGE value '%s', using default 3 days", maxAgeStr)
}
}

mux := http.NewServeMux()

// Static files (no auth required)
mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

if noAuth {
// No authentication - all routes are public
mux.HandleFunc("GET /{$}", serveIndex)
mux.HandleFunc("POST /api/trackers/create", createTracker)
mux.HandleFunc("POST /api/trackers/delete", deleteTracker)

// Tracker routes with slug validation
mux.HandleFunc("GET /{slug}", wrapWithSlugValidation(serveTracker))

// API routes with slug validation
mux.HandleFunc("GET /api/{slug}/total", wrapWithSlugValidation(getTotal))
mux.HandleFunc("GET /api/{slug}/events", wrapWithSlugValidation(getEvents))
mux.HandleFunc("POST /api/{slug}/add", wrapWithSlugValidation(addValue))
mux.HandleFunc("POST /api/{slug}/subtract", wrapWithSlugValidation(subtractValue))
mux.HandleFunc("POST /api/{slug}/delete", wrapWithSlugValidation(deleteEvent))
mux.HandleFunc("POST /api/{slug}/edit", wrapWithSlugValidation(editEvent))
} else {
// Authentication enabled
mux.HandleFunc("GET /login", serveLogin)
mux.HandleFunc("POST /login", handleLogin)

// Protected routes
mux.HandleFunc("GET /{$}", withAuth(serveIndex))
mux.HandleFunc("POST /api/trackers/create", withAuth(createTracker))
mux.HandleFunc("POST /api/trackers/delete", withAuth(deleteTracker))

// Tracker routes with slug validation and auth
mux.HandleFunc("GET /{slug}", withAuth(wrapWithSlugValidation(serveTracker)))

// API routes with slug validation and auth
mux.HandleFunc("GET /api/{slug}/total", withAuth(wrapWithSlugValidation(getTotal)))
mux.HandleFunc("GET /api/{slug}/events", withAuth(wrapWithSlugValidation(getEvents)))
mux.HandleFunc("POST /api/{slug}/add", withAuth(wrapWithSlugValidation(addValue)))
mux.HandleFunc("POST /api/{slug}/subtract", withAuth(wrapWithSlugValidation(subtractValue)))
mux.HandleFunc("POST /api/{slug}/delete", withAuth(wrapWithSlugValidation(deleteEvent)))
mux.HandleFunc("POST /api/{slug}/edit", withAuth(wrapWithSlugValidation(editEvent)))
}

// Wrap with logging middleware
handler := loggingMiddleware(mux)

port := os.Getenv("PORT")
if port == "" {
port = "8080"
}

log.Printf("Server starting on port %s", port)
if err := http.ListenAndServe(":"+port, handler); err != nil {
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
tracker := Tracker{
Title:   event.Note,
Slug:    slug,
Created: event.Timestamp,
}

// Calculate total for this tracker
file.Close()
events, err := loadEvents(slug)
if err == nil {
tracker.Total = calculateTotal(events)
}

trackers = append(trackers, tracker)
}
}
} else {
file.Close()
}
}

// Sort by creation time
sort.Slice(trackers, func(i, j int) bool {
return trackers[i].Created.Before(trackers[j].Created)
})

return trackers, nil
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
MaxAge:   cookieMaxAge,
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

func isValidSlug(slug string) bool {
match, _ := regexp.MatchString("^[a-z0-9-]+$", slug)
return match && len(slug) > 0 && len(slug) <= 50
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
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
slug := r.PathValue("slug")

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
slug := r.PathValue("slug")

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
slug := r.PathValue("slug")

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

func editEvent(w http.ResponseWriter, r *http.Request) {
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
event := Event{
ID:        generateID(),
Timestamp: time.Now().UTC(),
Type:      EventManual,
Value:     req.Value,
Note:      req.Note,
EditedID:  req.ID, // Reference to the original event being edited
}

if err := appendEvent(slug, event); err != nil {
http.Error(w, err.Error(), http.StatusInternalServerError)
return
}

w.WriteHeader(http.StatusOK)
json.NewEncoder(w).Encode(event)
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

// Apply deletions and edits
deletedIDs := make(map[string]bool)
editMap := make(map[string]string) // Map old ID to new ID
originalTimestamps := make(map[string]time.Time) // Map to preserve original timestamps

// First pass: collect all events and their timestamps
eventMap := make(map[string]Event)
for _, event := range allEvents {
eventMap[event.ID] = event
if event.Deleted {
deletedIDs[event.ID] = true
}
if event.EditedID != "" {
// This event is an edit of another event
editMap[event.EditedID] = event.ID
}
}

// Find original timestamps by following chains backwards
for _, event := range allEvents {
if event.EditedID == "" && !event.Deleted {
// This is an original event, record its timestamp
originalTimestamps[event.ID] = event.Timestamp
}
}

// For edited events, find and preserve the original timestamp
for originalID, firstEditID := range editMap {
var originalTimestamp time.Time

// Get the original event's timestamp
if origEvent, exists := eventMap[originalID]; exists {
originalTimestamp = origEvent.Timestamp
}

// Follow the chain and set the original timestamp for all in the chain
currentID := firstEditID
for {
originalTimestamps[currentID] = originalTimestamp
if nextID, hasNext := editMap[currentID]; hasNext {
currentID = nextID
} else {
break
}
}
}

// Build final event map by following edit chains to get the latest version
finalEvents := make(map[string]Event)
for _, event := range allEvents {
if event.Deleted || event.EditedID != "" {
// Skip deletion markers and edit events (we'll add final versions below)
continue
}
finalEvents[event.ID] = event
}

// For each original event that was edited, find the latest version in the chain
for originalID, firstEditID := range editMap {
// Follow the chain to find the final version
currentID := firstEditID
for {
if nextID, hasNext := editMap[currentID]; hasNext {
currentID = nextID
} else {
break
}
}

// Find the final event and preserve original timestamp
for _, event := range allEvents {
if event.ID == currentID {
// Preserve the original timestamp
if origTimestamp, exists := originalTimestamps[currentID]; exists {
event.Timestamp = origTimestamp
}
// Remove the original event and add the final edited version
delete(finalEvents, originalID)
finalEvents[currentID] = event
break
}
}
}

// Convert map to slice and filter out deleted events
var events []Event
for id, event := range finalEvents {
if !deletedIDs[id] {
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
