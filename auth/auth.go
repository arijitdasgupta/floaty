package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

var (
	mu              sync.RWMutex
	activeSessions  map[string]bool
)

// InitSessions initializes the session storage
func InitSessions() {
	activeSessions = make(map[string]bool)
}

// GenerateSessionToken generates a new session token
func GenerateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

// AddSession adds a session to the active sessions
func AddSession(token string) {
	mu.Lock()
	defer mu.Unlock()
	activeSessions[token] = true
}

// IsValidSession checks if a session token is valid
func IsValidSession(token string) bool {
	mu.RLock()
	defer mu.RUnlock()
	return activeSessions[token]
}
