package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Marker files make taint and abort signals durable when the session lock or
// the session file cannot be updated. They are written without the lock
// (O_CREATE, so a held or wedged lock cannot block them) before the locked
// merge is attempted, and LoadSession folds them into the state it returns.
// Existence is the signal: an empty or undecodable marker still counts. A
// marker expires with the session TTL, measured from its modification time,
// and is removed under the lock by the writer that clears the signal (an
// ingested prompt, end-turn, clear-intent).
func taintMarkerPath(sessionID string) string { return SessionFilePath(sessionID) + ".taint" }
func abortMarkerPath(sessionID string) string { return SessionFilePath(sessionID) + ".abort" }

// writeMarkerFunc writes a marker file. A variable so tests can make it fail.
var writeMarkerFunc = writeMarker

func writeMarker(path string, v interface{}) error {
	if err := os.MkdirAll(GetSessionsDir(), 0700); err != nil {
		return fmt.Errorf("failed to create sessions directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create marker %s: %w", path, err)
	}
	data, _ := json.Marshal(v)
	_, writeErr := f.Write(data)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		// The file exists, which already records the signal.
		return fmt.Errorf("marker %s created but not fully written: %w", path, writeErr)
	}
	return nil
}

// statMarker reports whether a fresh marker exists at path. A stat failure
// other than a missing file is returned so the gate fails closed.
func statMarker(path string) (os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to check marker %s: %w", path, err)
	}
	if time.Since(info.ModTime()) > sessionTTL {
		return nil, nil
	}
	return info, nil
}

// readTaintMarker returns the taint recorded by a fresh taint marker, or nil.
func readTaintMarker(sessionID string) (*TaintSource, error) {
	path := taintMarkerPath(sessionID)
	info, err := statMarker(path)
	if err != nil || info == nil {
		return nil, err
	}
	var src TaintSource
	if data, readErr := readFileWithRetry(path); readErr != nil || json.Unmarshal(data, &src) != nil || src.ToolName == "" {
		src = TaintSource{ToolName: "unknown tool", At: info.ModTime().UTC()}
	}
	return &src, nil
}

// hasAbortMarker reports whether a fresh abort marker exists.
func hasAbortMarker(sessionID string) (bool, error) {
	info, err := statMarker(abortMarkerPath(sessionID))
	return info != nil, err
}

// applyMarkers folds fresh taint and abort markers into state, creating an
// empty state when only a marker exists.
func applyMarkers(sessionID string, state *SessionState) (*SessionState, error) {
	taint, err := readTaintMarker(sessionID)
	if err != nil {
		return nil, err
	}
	aborted, err := hasAbortMarker(sessionID)
	if err != nil {
		return nil, err
	}
	if taint == nil && !aborted {
		return state, nil
	}
	if state == nil {
		state = &SessionState{SessionID: sessionID}
	}
	if taint != nil && !state.Tainted {
		state.Tainted = true
		state.TaintSource = taint
	}
	if aborted {
		state.Aborted = true
		state.Prompt = ""
	}
	return state, nil
}

func removeMarker(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove marker %s: %w", path, err)
	}
	return nil
}

// clearResolvedMarkers removes the markers whose signal the just-saved state
// no longer carries. A marker that cannot be removed keeps its signal active,
// which is the conservative failure.
func clearResolvedMarkers(state *SessionState) error {
	var errs []error
	if !state.Tainted {
		errs = append(errs, removeMarker(taintMarkerPath(state.SessionID)))
	}
	if !state.Aborted {
		errs = append(errs, removeMarker(abortMarkerPath(state.SessionID)))
	}
	return errors.Join(errs...)
}
