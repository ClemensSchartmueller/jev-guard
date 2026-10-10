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
	"sync/atomic"
	"time"

	"jev-guard/pkg/boundary"
)

// DefaultSessionTTL defines how long an inactive session intent remains valid.
const DefaultSessionTTL = 60 * time.Minute

// Named sub-patterns for abort detection; combined into abortPattern.
const (
	// abortAffirmative matches imperatives such as "stop", "please cancel the build", "wait, abort!".
	abortAffirmative = `(?i)^\s*(?:please\s+|wait[!,.]*\s*|hey[!,.]*\s*)?(?:stop|cancel|abort|halt|terminate|kill|quit)(?:!(?:\s+.*)?|(?:\s+(?:please|now|immediately|right\s+now|that|it|all|everything|running|execution|operation|(?:the|this)\s+(?:build|task|run|process|command|execution|operation)))?\s*(?:[!.]|$|\bplease\b))`

	// abortNegatedLegacy matches "don't/do not" + proceed-like verbs; any trailing text is accepted\n	// (e.g. "don't proceed with the migration").\n	abortNegatedLegacy = `(?i)^\s*(?:don'?t|do\s+not)\s+(?:do\s+that|run\s+that|proceed|continue|execute|go\s+ahead)\b`\n\n	// abortNegatedLegacy matches "don't/do not" + proceed-like verbs; any trailing text is accepted
	// (e.g. "don't proceed with the migration").
	abortNegatedLegacy = `(?i)^\s*(?:don'?t|do\s+not)\s+(?:do\s+that|run\s+that|proceed|continue|execute|go\s+ahead)\b`

	// abortNegatedImperative matches "don't/do not/never" + verb + optional vague object,
	// e.g. "do not run this", "don't push anything", "never delete that".
	// A specific object ("dont modify package.json") is a scoped instruction, not an abort.
	abortNegatedImperative = `(?i)^\s*(?:(?:don'?t|do\s+not|never)\s+(?:run|execute|delete|remove|rm|drop|push|commit|deploy|overwrite|change|modify|touch|do|proceed|continue)(?:\s+(?:this|that|it|these|those|anything|everything)(?:\s+(?:command|task|build|process|operation|change|changes))?)?\s*(?:[!.,]|$|\bplease\b))`

	// abortNeverMind matches "never mind" / "nevermind", optionally followed by more text.
	abortNeverMind = `(?i)^\s*never\s*mind\b`
)

var (
	abortPattern       = regexp.MustCompile(abortAffirmative + `|` + abortNegatedLegacy + `|` + abortNegatedImperative + `|` + abortNeverMind)
	safeSessionIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)

	reservedWindowsNames = map[string]bool{
		"CON": true, "PRN": true, "AUX": true, "NUL": true,
		"COM1": true, "COM2": true, "COM3": true, "COM4": true,
		"COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
		"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true,
		"LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	}
)

func isReservedWindowsName(name string) bool {
	return reservedWindowsNames[strings.ToUpper(name)]
}

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

	// If the session ID has safe chars (alphanumeric, dash, underscore) and is not a Windows reserved device name, use it directly.
	if safeSessionIDRegex.MatchString(cleaned) && len(cleaned) <= 64 && !isReservedWindowsName(cleaned) {
		return cleaned + ".json"
	}

	// Otherwise hash the session ID to prevent path traversal, filesystem issues, or Windows reserved device collisions.
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
	tempPath := fmt.Sprintf("%s.tmp.%d.%d.%d", targetPath, os.Getpid(), time.Now().UnixNano(), tempSeq.Add(1))

	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temporary session file: %w", err)
	}

	if err := renameWithRetry(tempPath, targetPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to commit session file: %w", err)
	}
	return nil
}

// tempSeq guarantees unique temp file names across concurrent saves.
var tempSeq atomic.Uint64

// renameAttempts and renameBackoff bound the retry of os.Rename. Variables so tests can shrink them.
var (
	renameAttempts = 10
	renameBackoff  = 5 * time.Millisecond
	renameMaxSleep = 50 * time.Millisecond
	renameSleep    = time.Sleep
	renameFunc     = os.Rename
)

// renameWithRetry replaces dst with src. The target is never removed first, so
// concurrent readers always see either the old or the new file. Transient
// failures (e.g. Windows sharing violations while a reader has dst open) are
// retried with a short bounded backoff.
func renameWithRetry(src, dst string) error {
	var err error
	delay := renameBackoff
	for attempt := 0; attempt < renameAttempts; attempt++ {
		if err = renameFunc(src, dst); err == nil {
			return nil
		}
		if attempt == renameAttempts-1 {
			break
		}
		renameSleep(delay)
		delay *= 2
		if delay > renameMaxSleep {
			delay = renameMaxSleep
		}
	}
	return err
}

// readFileWithRetry reads path, retrying transient errors (e.g. a Windows
// sharing violation while a concurrent save is renaming over the file).
// A missing file is returned immediately.
func readFileWithRetry(path string) ([]byte, error) {
	var data []byte
	var err error
	delay := renameBackoff
	for attempt := 0; attempt < renameAttempts; attempt++ {
		data, err = os.ReadFile(path)
		if err == nil || os.IsNotExist(err) {
			return data, err
		}
		if attempt == renameAttempts-1 {
			break
		}
		renameSleep(delay)
		delay *= 2
		if delay > renameMaxSleep {
			delay = renameMaxSleep
		}
	}
	return data, err
}

// LoadSession reads the session state from disk. Returns nil, nil if session does not exist.
func LoadSession(sessionID string) (*SessionState, error) {
	targetPath := SessionFilePath(sessionID)
	data, err := readFileWithRetry(targetPath)
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
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".json") || strings.Contains(entry.Name(), ".tmp.")) {
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
		if entry.IsDir() {
			continue
		}
		if strings.Contains(entry.Name(), ".tmp.") {
			if info, err := entry.Info(); err == nil {
				if time.Since(info.ModTime()) > 5*time.Minute {
					_ = os.Remove(filepath.Join(sessionsDir, entry.Name()))
				}
			}
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
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

	// Check if the path lexically contains .jevguard directory or configuration segment
	normalized := strings.ToLower(filepath.ToSlash(filepath.Clean(trimmed)))
	for _, segment := range strings.Split(normalized, "/") {
		if segment == ".jevguard" || segment == ".jevguard.json" || segment == "jevguard.json" || segment == ".jevguard.log" {
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
