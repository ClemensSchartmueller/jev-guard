package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
// It is the fallback used when no TTL has been configured via SetSessionTTL.
const DefaultSessionTTL = 30 * time.Minute

var sessionTTL = DefaultSessionTTL

// SetSessionTTL overrides the intent TTL used by LoadSession and ListSessions.
// Non-positive values restore DefaultSessionTTL.
func SetSessionTTL(ttl time.Duration) {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	sessionTTL = ttl
}

// SessionTTL returns the intent TTL currently in effect.
func SessionTTL() time.Duration {
	return sessionTTL
}

// Named sub-patterns for abort detection; combined into abortPattern.
const (
	// abortAffirmative matches imperatives such as "stop", "please cancel the build", "wait, abort!".
	abortAffirmative = `(?i)^\s*(?:please\s+|wait[!,.]*\s*|hey[!,.]*\s*)?(?:stop|cancel|abort|halt|terminate|kill|quit)(?:!(?:\s+.*)?|(?:\s+(?:please|now|immediately|right\s+now|that|it|all|everything|running|execution|operation|(?:the|this)\s+(?:build|task|run|process|command|execution|operation)))?\s*(?:[!.]|$|\bplease\b))`

	// abortLeadIn matches optional interjections before a negated imperative,
	// e.g. "No, don't run this", "Wait, don't do that", "Stop, don't run this".
	abortLeadIn = `(?:(?:no|wait|stop|hey)(?:[!,.]+\s*|\s+))*`

	// abortNegatedLegacy matches "don't/do not" + proceed-like verbs; any trailing text is accepted
	// (e.g. "don't proceed with the migration").
	abortNegatedLegacy = `(?i)^\s*` + abortLeadIn + `(?:don['’]?t|do\s+not)\s+(?:do\s+that|run\s+that|proceed|continue|execute|go\s+ahead)\b`

	// abortNegatedImperative matches "don't/do not/never" + verb + optional vague object,
	// e.g. "do not run this", "don't push anything", "never delete that".
	// A specific object ("dont modify package.json") is a scoped instruction, not an abort.
	// An optional lead-in ("no,", "wait,") and trailing adverb ("yet", "again") are accepted; apostrophes may be ' or ’ (U+2019) or omitted.
	abortNegatedImperative = `(?i)^\s*` + abortLeadIn + `(?:(?:don['’]?t|do\s+not|never)\s+(?:run|execute|delete|remove|rm|drop|push|commit|deploy|overwrite|change|modify|touch|do|proceed|continue)(?:\s+(?:this|that|it|these|those|anything|everything)(?:\s+(?:command|task|build|process|operation|change|changes))?)?(?:\s+(?:yet|again|now|anymore|for\s+now))?\s*(?:[!.,]|$|\bplease\b))`

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
	// Tainted is set by a PostToolUse hook after an untrusted tool (WebFetch,
	// WebSearch, MCP) returned content into the agent's context. It lasts until
	// end-turn clears the session or ingest records the next prompt.
	Tainted     bool         `json:"tainted,omitempty"`
	TaintSource *TaintSource `json:"taint_source,omitempty"`
}

// TaintSource records which untrusted tool tainted a session and when.
type TaintSource struct {
	ToolName string    `json:"tool_name"`
	At       time.Time `json:"at"`
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

// SaveSession atomically replaces the session state on disk. It holds the
// session lock so it cannot interleave with MarkTainted or EndTurn, and it
// retires the taint and abort markers published before it, as far as the new
// state no longer carries them (see the invariants in marker.go). If an abort
// prompt cannot be saved (for example on a lock timeout), it writes an abort
// marker so the gate still holds, and returns the error.
func SaveSession(state *SessionState) error {
	if state == nil {
		return fmt.Errorf("session state cannot be nil")
	}
	abort := state.Aborted || IsNegativeIntent(state.Prompt)
	err := withSessionLock(state.SessionID, func() error {
		markers, err := markersFor(state.SessionID)
		if err != nil {
			return err
		}
		if err := saveSessionLocked(state); err != nil {
			return err
		}
		return markers.retire(state)
	})
	if err != nil && abort {
		path := abortMarkerPath(state.SessionID)
		if markerErr := writeMarkerFunc(path, markerRecord{SessionID: state.SessionID}); markerErr != nil {
			return fmt.Errorf("%w; abort marker also failed: %v", err, markerErr)
		}
		return fmt.Errorf("%w; abort recorded in marker %s", err, path)
	}
	return err
}

func saveSessionLocked(state *SessionState) error {
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

// Retry parameters for transient filesystem errors. Variables so tests can
// override them. Worst case: 9 sleeps of 5+10+20+40+50*5 = 325ms.
var (
	retryAttempts = 10
	retryBackoff  = 5 * time.Millisecond
	retryMaxSleep = 50 * time.Millisecond
	retrySleep    = time.Sleep
	retryable     = isTransientFSError
	renameFunc    = os.Rename
	readFileFunc  = os.ReadFile
)

// retryTransient runs fn until it succeeds, returns a non-transient error, or
// retryAttempts is exhausted, sleeping with capped exponential backoff between
// attempts. Only errors accepted by retryable are retried.
func retryTransient(fn func() error) error {
	delay := retryBackoff
	for attempt := 1; ; attempt++ {
		err := fn()
		if err == nil || attempt >= retryAttempts || !retryable(err) {
			return err
		}
		retrySleep(delay)
		delay *= 2
		if delay > retryMaxSleep {
			delay = retryMaxSleep
		}
	}
}

// renameWithRetry replaces dst with src. The target is never removed first, so
// concurrent readers always see either the old or the new file. Transient
// failures (Windows sharing violations while a reader has dst open) are
// retried with a short bounded backoff; other errors return immediately.
func renameWithRetry(src, dst string) error {
	return retryTransient(func() error { return renameFunc(src, dst) })
}

// readFileWithRetry reads path, retrying transient errors (a Windows sharing
// violation while a concurrent save is renaming over the file). Missing files
// and other permanent errors are returned immediately.
func readFileWithRetry(path string) ([]byte, error) {
	var data []byte
	err := retryTransient(func() error {
		var err error
		data, err = readFileFunc(path)
		return err
	})
	return data, err
}

// LoadSession reads the session state from disk, folding in fresh taint and
// abort markers. Returns nil, nil if neither the session nor a marker exists.
// An expired session is removed, under the session lock and only if it is
// still expired, so a concurrent ingest is never deleted.
func LoadSession(sessionID string) (*SessionState, error) {
	state, err := loadSessionFile(sessionID)
	if err != nil {
		return nil, err
	}
	markers, err := markersFor(sessionID)
	if err != nil {
		return nil, err
	}
	return markers.fold(state, sessionID)
}

func loadSessionFile(sessionID string) (*SessionState, error) {
	state, expired, err := readSession(sessionID)
	if err != nil || !expired {
		return state, err
	}
	_ = withSessionLock(sessionID, func() error {
		if _, stillExpired, err := readSession(sessionID); err == nil && stillExpired {
			_ = os.Remove(SessionFilePath(sessionID))
		}
		return nil
	})
	return nil, nil
}

// readSession reads and decodes a session file without taking the lock. It
// returns nil state for an absent or expired session; expired reports the latter.
func readSession(sessionID string) (*SessionState, bool, error) {
	data, err := readFileWithRetry(SessionFilePath(sessionID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to read session file: %w", err)
	}

	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, false, fmt.Errorf("failed to parse session file: %w", err)
	}

	if !state.UpdatedAt.IsZero() && time.Since(state.UpdatedAt) > sessionTTL {
		return nil, true, nil
	}
	return &state, false, nil
}

// ErrTaintNotRecorded marks a MarkTainted failure in which neither the taint
// marker nor the session state could be written.
var ErrTaintNotRecorded = errors.New("taint not recorded")

// MarkTainted records that toolName returned untrusted content into the
// session. It first writes its own taint marker without the lock, so a lock
// timeout or a failed state write still leaves the session tainted for the
// gate. It then merges the taint into the state under the session lock: it
// re-reads the current state and only adds the taint, so it never clears an
// abort flag or replaces a newer prompt. The merge is skipped when a later
// prompt or end-turn already retired the marker (invariant 3 in marker.go). A
// missing or expired session is created with an empty prompt. An unreadable
// session file is left untouched and reported as an error. The error wraps
// ErrTaintNotRecorded only when both writes failed.
func MarkTainted(sessionID, toolName string, at time.Time) error {
	if strings.TrimSpace(sessionID) == "" {
		sessionID = "default"
	}
	src := TaintSource{ToolName: toolName, At: at.UTC()}
	marker := taintMarkerPath(sessionID)
	markerErr := writeMarkerFunc(marker, markerRecord{SessionID: sessionID, ToolName: src.ToolName, At: src.At})
	requiredMarker := marker
	if markerErr != nil {
		requiredMarker = ""
	}
	err := mergeTaint(sessionID, src, requiredMarker)
	switch {
	case err == nil:
		return nil
	case markerErr == nil:
		return fmt.Errorf("session state not updated, taint kept in marker %s: %w", marker, err)
	default:
		return fmt.Errorf("%w: marker: %v; session state: %v", ErrTaintNotRecorded, markerErr, err)
	}
}

// mergeTaint adds the taint to the session file. With a non-empty marker it
// merges only while that marker exists, then removes it, since the session
// file now carries the taint.
func mergeTaint(sessionID string, src TaintSource, marker string) error {
	return withSessionLock(sessionID, func() error {
		if marker != "" {
			if _, err := os.Stat(marker); err != nil {
				if os.IsNotExist(err) {
					return nil // retired by a later prompt or end-turn
				}
				return fmt.Errorf("failed to check marker %s: %w", marker, err)
			}
		}
		state, _, err := readSession(sessionID)
		if err != nil {
			return err
		}
		if state == nil {
			state = &SessionState{SessionID: sessionID}
		}
		state.Tainted = true
		state.TaintSource = &src
		if err := saveSessionLocked(state); err != nil {
			return err
		}
		if marker != "" {
			_ = removeMarker(marker)
		}
		return nil
	})
}

// EndTurn clears a session's prompt and taint at the end of a reply. An
// aborted session is kept (aborted is true) so background work stays held.
// The check and the removal happen under the session lock, so an abort
// recorded concurrently by ingest is never deleted.
func EndTurn(sessionID string) (aborted bool, err error) {
	err = withSessionLock(sessionID, func() error {
		state, _, err := readSession(sessionID)
		if err != nil {
			return err
		}
		markers, err := markersFor(sessionID)
		if err != nil {
			return err
		}
		markerAbort, err := markers.hasFreshAbort()
		if err != nil {
			return err
		}
		if (state != nil && state.Aborted) || markerAbort {
			aborted = true
			return nil
		}
		return removeSessionFile(sessionID, markers)
	})
	return aborted, err
}

// ClearSession deletes the session cache file and markers for a specific session ID.
func ClearSession(sessionID string) error {
	return withSessionLock(sessionID, func() error {
		markers, err := markersFor(sessionID)
		if err != nil {
			return err
		}
		return removeSessionFile(sessionID, markers)
	})
}

// removeSessionFile deletes the session file and the listed markers; markers
// published after the listing survive (see marker.go). The lock file is kept
// (see withSessionLock).
func removeSessionFile(sessionID string, markers *sessionMarkers) error {
	err := os.Remove(SessionFilePath(sessionID))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove session file: %w", err)
	}
	return removeMarkers(markers.Paths)
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
		name := entry.Name()
		_, _, isMarker := parseMarkerName(name)
		if !entry.IsDir() && (strings.HasSuffix(name, ".json") || isMarker || strings.Contains(name, ".tmp.")) {
			_ = os.Remove(filepath.Join(sessionsDir, entry.Name()))
		}
	}
	return nil
}

// UnreadableSession describes a session file that exists but could not be
// read or decoded. The gate fails closed for such sessions, so callers that
// list sessions should report them rather than skip them.
type UnreadableSession struct {
	// FileName is the session file's base name (a sanitized or hashed session ID plus ".json").
	FileName string
	Err      error
}

// SessionScan is the result of ScanSessions.
type SessionScan struct {
	Active     []*SessionState
	Unreadable []UnreadableSession
}

// ListSessions returns all active, non-expired sessions. Unreadable session
// files are omitted; use ScanSessions to see them.
func ListSessions() ([]*SessionState, error) {
	scan, err := ScanSessions()
	if err != nil {
		return nil, err
	}
	return scan.Active, nil
}

// ScanSessions reads every session file and folds in its taint and abort
// markers with the same semantics as LoadSession, so a session that exists
// only as a marker is listed too. Valid, non-expired sessions are returned in
// Active; expired sessions and stale temp files are removed; files that
// cannot be read or decoded are returned in Unreadable and left in place.
func ScanSessions() (*SessionScan, error) {
	scan := &SessionScan{}
	sessionsDir := GetSessionsDir()
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return scan, nil
		}
		return nil, fmt.Errorf("failed to read sessions directory: %w", err)
	}
	markers := groupMarkers(entries)
	addFolded := func(name string, state *SessionState) {
		m := markers[name]
		delete(markers, name)
		if m != nil {
			var err error
			if state, err = m.fold(state, strings.TrimSuffix(name, ".json")); err != nil {
				scan.Unreadable = append(scan.Unreadable, UnreadableSession{FileName: name, Err: err})
				return
			}
		}
		if state != nil {
			scan.Active = append(scan.Active, state)
		}
	}

	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp.") {
			if entry.IsDir() {
				continue
			}
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
		data, err := readFileWithRetry(fullPath)
		if err != nil {
			if os.IsNotExist(err) {
				addFolded(entry.Name(), nil)
				continue
			}
			delete(markers, entry.Name())
			scan.Unreadable = append(scan.Unreadable, UnreadableSession{FileName: entry.Name(), Err: fmt.Errorf("failed to read session file: %w", err)})
			continue
		}

		var state SessionState
		if err := json.Unmarshal(data, &state); err != nil {
			delete(markers, entry.Name())
			scan.Unreadable = append(scan.Unreadable, UnreadableSession{FileName: entry.Name(), Err: fmt.Errorf("failed to parse session file: %w", err)})
			continue
		}

		if !state.UpdatedAt.IsZero() && time.Since(state.UpdatedAt) > sessionTTL {
			_ = os.Remove(fullPath)
			addFolded(entry.Name(), nil)
			continue
		}

		addFolded(entry.Name(), &state)
	}

	// Sessions recorded only by markers.
	for _, name := range sortedBases(markers) {
		addFolded(name, nil)
	}
	return scan, nil
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
