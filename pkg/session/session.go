package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"jev-guard/pkg/boundary"
)

// DefaultSessionTTL defines how long an inactive session intent remains valid.
const DefaultSessionTTL = 60 * time.Minute

var (
	abortPattern       = regexp.MustCompile(`(?i)^\s*((stop|cancel|abort|halt|quit)\s*([!.]|$|\b(that|it|now|all|everything|execution|operation)\b)|(stop|cancel|abort|halt)!\s*.*|(don'?t|do\s+not)\s+(do\s+that|run\s+that|proceed|continue)\b)`)
	safeSessionIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)
)

// SessionState records the active user prompt and turn context for a session.
type SessionState struct {
	SessionID string    `json:"session_id"`
	TurnID    int       `json:"turn_id"`
	Prompt    string    `json:"prompt"`
	UpdatedAt time.Time `json:"updated_at"`
	Aborted   bool      `json:"aborted,omitempty"`
}

// GetJevguardDir returns the unified ~/.jevguard home directory.
func GetJevguardDir() string {
	if custom := os.Getenv("JEV_GUARD_HOME"); custom != "" {
		return filepath.Clean(custom)
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.TempDir()
	}
	return filepath.Join(home, ".jevguard")
}

// GetSessionsDir returns the directory where session intent cache files reside.
func GetSessionsDir() string {
	return filepath.Join(GetJevguardDir(), "sessions")
}

// SafeSessionFileName generates a sanitized filename for a session ID.
func SafeSessionFileName(sessionID string) string {
	cleaned := strings.TrimSpace(sessionID)
	if cleaned == "" {
		cleaned = "default"
	}

	// If the session ID has safe chars (alphanumeric, dash, underscore), use it directly with prefix.
	if safeSessionIDRegex.MatchString(cleaned) && len(cleaned) <= 64 {
		return cleaned + ".json"
	}

	// Otherwise hash the session ID to prevent path traversal or filesystem issues.
	h := sha256.Sum256([]byte(cleaned))
	return hex.EncodeToString(h[:16]) + ".json"
}

// SessionFilePath returns the absolute file path for a session's cache file.
func SessionFilePath(sessionID string) string {
	return filepath.Join(GetSessionsDir(), SafeSessionFileName(sessionID))
}

// IsNegativeIntent checks if a prompt expresses an explicit command to abort, cancel, or stop.
func IsNegativeIntent(prompt string) bool {
	return abortPattern.MatchString(prompt)
}

// SaveSession atomically writes the session state to disk.
func SaveSession(state *SessionState) error {
	if state == nil {
		return fmt.Errorf("session state cannot be nil")
	}

	sessionsDir := GetSessionsDir()
	if err := os.MkdirAll(sessionsDir, 0700); err != nil {
		return fmt.Errorf("failed to create sessions directory: %w", err)
	}

	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}

	// If prompt is an abort command, flag session as aborted and clear positive prompt
	if IsNegativeIntent(state.Prompt) {
		state.Aborted = true
		state.Prompt = ""
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize session state: %w", err)
	}

	targetPath := SessionFilePath(state.SessionID)
	tempPath := fmt.Sprintf("%s.tmp.%d", targetPath, time.Now().UnixNano())

	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temporary session file: %w", err)
	}

	if err := os.Rename(tempPath, targetPath); err != nil {
		// Fallback for systems/filesystems where rename fails across handles
		_ = os.Remove(targetPath)
		if retryErr := os.Rename(tempPath, targetPath); retryErr != nil {
			_ = os.Remove(tempPath)
			return fmt.Errorf("failed to commit session file: %w", retryErr)
		}
	}

	return nil
}

// LoadSession reads the session state from disk. Returns nil, nil if session does not exist.
func LoadSession(sessionID string) (*SessionState, error) {
	targetPath := SessionFilePath(sessionID)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse session file: %w", err)
	}

	// Verify TTL
	if !state.UpdatedAt.IsZero() && time.Since(state.UpdatedAt) > DefaultSessionTTL {
		_ = os.Remove(targetPath)
		return nil, nil
	}

	return &state, nil
}

// ClearSession deletes the session cache file for a specific session ID.
func ClearSession(sessionID string) error {
	targetPath := SessionFilePath(sessionID)
	err := os.Remove(targetPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove session file: %w", err)
	}
	return nil
}

// ClearAllSessions deletes all cached session files.
func ClearAllSessions() error {
	sessionsDir := GetSessionsDir()
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read sessions directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			_ = os.Remove(filepath.Join(sessionsDir, entry.Name()))
		}
	}
	return nil
}

// ListSessions returns all active, non-expired sessions.
func ListSessions() ([]*SessionState, error) {
	sessionsDir := GetSessionsDir()
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read sessions directory: %w", err)
	}

	var sessions []*SessionState
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		fullPath := filepath.Join(sessionsDir, entry.Name())
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}

		var state SessionState
		if err := json.Unmarshal(data, &state); err != nil {
			continue
		}

		if !state.UpdatedAt.IsZero() && time.Since(state.UpdatedAt) > DefaultSessionTTL {
			_ = os.Remove(fullPath)
			continue
		}

		sessions = append(sessions, &state)
	}

	return sessions, nil
}

// IsJevguardPath checks if a given file path is located inside ~/.jevguard or targets the security cache.
func IsJevguardPath(targetPath string) bool {
	trimmed := strings.TrimSpace(targetPath)
	if trimmed == "" {
		return false
	}

	// Expand ~ to user home directory
	if strings.HasPrefix(trimmed, "~") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			trimmed = filepath.Join(home, strings.TrimPrefix(trimmed, "~"))
		}
	}

	// Check if the path lexically contains .jevguard directory segment
	normalized := strings.ToLower(filepath.ToSlash(filepath.Clean(trimmed)))
	for _, segment := range strings.Split(normalized, "/") {
		if segment == ".jevguard" {
			return true
		}
	}

	cleanHome := GetJevguardDir()
	if canonHome, err := boundary.CanonicalizePath(cleanHome); err == nil && canonHome != "" {
		cleanHome = canonHome
	}

	absTarget := trimmed
	if !filepath.IsAbs(absTarget) {
		if abs, err := filepath.Abs(absTarget); err == nil {
			absTarget = abs
		}
	}
	if canonTarget, err := boundary.CanonicalizePath(absTarget); err == nil && canonTarget != "" {
		absTarget = canonTarget
	}

	return boundary.IsSubPath(cleanHome, absTarget)
}
