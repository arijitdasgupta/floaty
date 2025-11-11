package models

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
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

// IsValidSlug checks if a slug is valid
func IsValidSlug(slug string) bool {
	match, _ := regexp.MatchString("^[a-z0-9-]+$", slug)
	return match && len(slug) > 0 && len(slug) <= 50
}

// GenerateID generates a random ID
func GenerateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
