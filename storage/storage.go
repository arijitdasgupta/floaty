package storage

import (
	"bufio"
	"encoding/json"
	"github.com/arijitdasgupta/floaty/models"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// GetLogFile returns the path to the log file for a slug
func GetLogFile(slug string) string {
	return filepath.Join("data", slug+".log")
}

// LoadEvents loads all events for a tracker, applying deletions and edits
func LoadEvents(slug string) ([]models.Event, error) {
	logFile := GetLogFile(slug)
	file, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []models.Event{}, nil
		}
		return nil, err
	}
	defer file.Close()

	var allEvents []models.Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event models.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			log.Printf("Failed to parse event: %v", err)
			continue
		}
		// Skip metadata events
		if event.Type != models.EventMetadata {
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
	eventMap := make(map[string]models.Event)
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
	finalEvents := make(map[string]models.Event)
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
	var events []models.Event
	for id, event := range finalEvents {
		if !deletedIDs[id] {
			events = append(events, event)
		}
	}

	return events, nil
}

// AppendEvent appends an event to the log file
func AppendEvent(slug string, event models.Event) error {
	logFile := GetLogFile(slug)
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

// CalculateTotal calculates the total value from a list of events
func CalculateTotal(events []models.Event) float64 {
	total := 0.0
	for _, event := range events {
		total += event.Value
	}
	return total
}

// LoadTrackers loads all trackers from the data directory
func LoadTrackers() ([]models.Tracker, error) {
	os.MkdirAll("data", 0755)

	files, err := filepath.Glob("data/*.log")
	if err != nil {
		return nil, err
	}

	var trackers []models.Tracker
	for _, filePath := range files {
		slug := strings.TrimSuffix(filepath.Base(filePath), ".log")

		// Read first line to get metadata
		file, err := os.Open(filePath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(file)
		if scanner.Scan() {
			var event models.Event
			if err := json.Unmarshal(scanner.Bytes(), &event); err == nil {
				if event.Type == models.EventMetadata {
					tracker := models.Tracker{
						Title:   event.Note,
						Slug:    slug,
						Created: event.Timestamp,
					}

					// Calculate total for this tracker
					file.Close()
					events, err := LoadEvents(slug)
					if err == nil {
						tracker.Total = CalculateTotal(events)
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

// GetTracker gets a single tracker by slug
func GetTracker(slug string) (*models.Tracker, error) {
	logFile := GetLogFile(slug)
	file, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		var event models.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err == nil {
			if event.Type == models.EventMetadata {
				return &models.Tracker{
					Title:   event.Note,
					Slug:    slug,
					Created: event.Timestamp,
				}, nil
			}
		}
	}

	return &models.Tracker{Title: slug, Slug: slug}, nil
}
