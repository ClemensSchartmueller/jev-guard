package session

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupTestJevguardDir(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	t.Setenv("JEV_GUARD_HOME", tempDir)
	return tempDir
}

func TestSession_SaveAndLoad(t *testing.T) {
	setupTestJevguardDir(t)

	sessionID := "test-session-123"
	state := &SessionState{
		SessionID: sessionID,
		TurnID:    2,
		Prompt:    "Delete the build directory",
		UpdatedAt: time.Now().UTC(),
	}

	if err := SaveSession(state); err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	loaded, err := LoadSession(sessionID)
	if err != nil {
		t.Fatalf("LoadSession failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected loaded session, got nil")
	}

	if loaded.SessionID != sessionID {
		t.Errorf("expected session ID %s, got %s", sessionID, loaded.SessionID)
	}
	if loaded.TurnID != 2 {
		t.Errorf("expected turn ID 2, got %d", loaded.TurnID)
	}
	if loaded.Prompt != "Delete the build directory" {
		t.Errorf("expected prompt 'Delete the build directory', got '%s'", loaded.Prompt)
	}
	if loaded.Aborted {
		t.Error("expected session not to be aborted")
	}
}

func TestSession_NegativeIntentAbort(t *testing.T) {
	setupTestJevguardDir(t)

	sessionID := "abort-session"
	state := &SessionState{
		SessionID: sessionID,
		TurnID:    1,
		Prompt:    "Stop! Do not run that command",
	}

	if err := SaveSession(state); err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	loaded, err := LoadSession(sessionID)
	if err != nil {
		t.Fatalf("LoadSession failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected loaded session, got nil")
	}

	if !loaded.Aborted {
		t.Error("expected session to be marked as aborted")
	}
	if loaded.Prompt != "" {
		t.Errorf("expected prompt to be cleared upon abort, got '%s'", loaded.Prompt)
	}
}

func TestSession_NonAbortInstructions(t *testing.T) {
	nonAborts := []string{
		"don't forget to run unit tests",
		"dont modify package.json",
		"wait for the build to finish before committing",
		"stop the docker container named my-app",
		"quit the background daemon and restart",
		"halt if you see compiler warnings",
	}

	for _, prompt := range nonAborts {
		if IsNegativeIntent(prompt) {
			t.Errorf("expected prompt %q NOT to be classified as negative abort intent", prompt)
		}
	}
}

func TestSession_Clear(t *testing.T) {
	setupTestJevguardDir(t)

	sessionID := "to-clear"
	state := &SessionState{
		SessionID: sessionID,
		TurnID:    1,
		Prompt:    "Clean dist",
	}

	if err := SaveSession(state); err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	if err := ClearSession(sessionID); err != nil {
		t.Fatalf("ClearSession failed: %v", err)
	}

	loaded, err := LoadSession(sessionID)
	if err != nil {
		t.Fatalf("LoadSession failed: %v", err)
	}
	if loaded != nil {
		t.Errorf("expected nil after clear, got %+v", loaded)
	}
}

func TestSession_ClearAll(t *testing.T) {
	setupTestJevguardDir(t)

	for _, id := range []string{"sess-1", "sess-2", "sess-3"} {
		_ = SaveSession(&SessionState{SessionID: id, Prompt: "test"})
	}

	list, err := ListSessions()
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(list))
	}

	if err := ClearAllSessions(); err != nil {
		t.Fatalf("ClearAllSessions failed: %v", err)
	}

	listAfter, err := ListSessions()
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	if len(listAfter) != 0 {
		t.Fatalf("expected 0 sessions after ClearAll, got %d", len(listAfter))
	}
}

func TestSession_TTLExpiration(t *testing.T) {
	setupTestJevguardDir(t)

	sessionID := "expired-session"
	state := &SessionState{
		SessionID: sessionID,
		TurnID:    1,
		Prompt:    "old prompt",
		UpdatedAt: time.Now().UTC().Add(-2 * time.Hour),
	}

	if err := SaveSession(state); err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	loaded, err := LoadSession(sessionID)
	if err != nil {
		t.Fatalf("LoadSession failed: %v", err)
	}
	if loaded != nil {
		t.Errorf("expected expired session to return nil, got %+v", loaded)
	}
}

func TestIsJevguardPath(t *testing.T) {
	tempHome := setupTestJevguardDir(t)

	// Absolute path inside JEV_GUARD_HOME
	inside := filepath.Join(tempHome, "sessions", "abc.json")
	if !IsJevguardPath(inside) {
		t.Errorf("expected %s to be recognized as jevguard path", inside)
	}

	// Relative path containing .jevguard
	relInside := filepath.Join(".jevguard", "sessions", "abc.json")
	if !IsJevguardPath(relInside) {
		t.Errorf("expected relative path %s to be recognized as jevguard path", relInside)
	}

	// Tilde path
	tildePath := "~/.jevguard/sessions/xyz.json"
	if !IsJevguardPath(tildePath) {
		t.Errorf("expected tilde path %s to be recognized as jevguard path", tildePath)
	}

	// Outside path
	outside := filepath.Join(filepath.Dir(tempHome), "workspace", "file.go")
	if IsJevguardPath(outside) {
		t.Errorf("expected %s NOT to be recognized as jevguard path", outside)
	}

	// Normal workspace relative path
	relOutside := "pkg/session/session.go"
	if IsJevguardPath(relOutside) {
		t.Errorf("expected relative workspace file %s NOT to be recognized as jevguard path", relOutside)
	}

	// Configuration and log files
	for _, cfgFile := range []string{".jevguard.json", "jevguard.json", ".jevguard.log", "sub/.jevguard.json"} {
		if !IsJevguardPath(cfgFile) {
			t.Errorf("expected config file %s to be recognized as jevguard path", cfgFile)
		}
	}
}

func TestSafeSessionFileName(t *testing.T) {
	// Standard safe IDs should keep their name
	if got := SafeSessionFileName("my-session_123"); got != "my-session_123.json" {
		t.Errorf("expected my-session_123.json, got %s", got)
	}

	// Empty string defaults to default.json
	if got := SafeSessionFileName(""); got != "default.json" {
		t.Errorf("expected default.json, got %s", got)
	}

	// Windows reserved device names must NOT use direct name
	reserved := []string{"con", "CON", "prn", "PRN", "aux", "AUX", "nul", "NUL", "com1", "COM1", "lpt9", "LPT9"}
	for _, name := range reserved {
		got := SafeSessionFileName(name)
		if strings.EqualFold(got, name+".json") {
			t.Errorf("vulnerability: Windows reserved device name %q resulted in unsafe file %q", name, got)
		}
		if !strings.HasSuffix(got, ".json") {
			t.Errorf("expected .json suffix, got %q", got)
		}
	}

	// Unsafe characters should be hashed
	got := SafeSessionFileName("session/with/slashes")
	if strings.Contains(got, "/") || strings.Contains(got, "\\") {
		t.Errorf("expected slashes to be stripped or hashed, got %s", got)
	}
}
