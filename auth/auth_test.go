package auth

import (
	"testing"
)

func TestGenerateSessionToken(t *testing.T) {
	// Test that GenerateSessionToken creates a non-empty string
	token := GenerateSessionToken()
	if token == "" {
		t.Error("GenerateSessionToken() returned empty string")
	}

	// Test that GenerateSessionToken creates unique tokens
	token2 := GenerateSessionToken()
	if token == token2 {
		t.Error("GenerateSessionToken() returned duplicate tokens")
	}

	// Test that GenerateSessionToken creates hex strings of expected length (32 bytes hashed = 64 hex chars)
	if len(token) != 64 {
		t.Errorf("GenerateSessionToken() returned token of length %d, expected 64", len(token))
	}
}

func TestSessionManagement(t *testing.T) {
	// Initialize sessions
	InitSessions()

	// Test that a new session is not valid
	token := "test-token-123"
	if IsValidSession(token) {
		t.Error("IsValidSession() returned true for non-existent session")
	}

	// Add session and test that it's now valid
	AddSession(token)
	if !IsValidSession(token) {
		t.Error("IsValidSession() returned false for existing session")
	}

	// Test with another token
	token2 := "test-token-456"
	if IsValidSession(token2) {
		t.Error("IsValidSession() returned true for different non-existent session")
	}

	// Add second session
	AddSession(token2)
	if !IsValidSession(token2) {
		t.Error("IsValidSession() returned false for second existing session")
	}

	// Verify first session is still valid
	if !IsValidSession(token) {
		t.Error("IsValidSession() returned false for first session after adding second")
	}
}

func TestInitSessions(t *testing.T) {
	// Initialize sessions
	InitSessions()

	// Add a session
	token := "test-init-token"
	AddSession(token)

	if !IsValidSession(token) {
		t.Error("Session should be valid after adding")
	}

	// Re-initialize sessions (should clear previous sessions)
	InitSessions()

	// The token should no longer be valid after re-initialization
	if IsValidSession(token) {
		t.Error("Session should be invalid after re-initialization")
	}
}
