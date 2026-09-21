package session

import (
	"path/filepath"
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

	inside := filepath.Join(tempHome, "sessions", "abc.json")
	if !IsJevguardPath(inside) {
		t.Errorf("expected %s to be recognized as jevguard path", inside)
	}

	outside := filepath.Join(filepath.Dir(tempHome), "workspace", "file.go")
	if IsJevguardPath(outside) {
		t.Errorf("expected %s NOT to be recognized as jevguard path", outside)
	}
}
