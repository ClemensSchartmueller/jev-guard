package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Marker files make taint and abort signals durable when the session lock or
// the session file cannot be updated. Each signal event writes its own marker
// file, named <session file>.taint.<event id> or <session file>.abort.<event
// id>, without the lock (O_CREATE|O_EXCL, so a held or wedged lock cannot
// block it). Existence is the signal: an empty or undecodable marker still
// counts. A marker expires with the session TTL, measured from its
// modification time.
//
// Ordering invariants. Markers are created outside the lock, so the lock does
// not order them against writers that clear signals; event identity does:
//
//  1. A clearing writer (an ingested prompt, end-turn, clear-intent) lists
//     the session's markers under the lock before it commits and removes only
//     the markers it listed. A marker created after that listing is a newer
//     event and survives, so an older clear never deletes a newer signal (an
//     abort from a timed-out stop, a taint from a timed-out PostToolUse).
//  2. A listed marker was published before the clear committed, so the clear
//     retires it: the next prompt clears the taint of the previous turn, and a
//     positive prompt after a stop resumes work, as without markers.
//  3. MarkTainted merges its taint into the session file under the lock only
//     while its own marker still exists. A missing marker means a later clear
//     retired the event, so a delayed merge cannot re-taint the next prompt or
//     recreate an ended session. If the marker could not be written at all,
//     the merge runs unconditionally (fail closed).
//  4. Abort is never cleared by a taint merge, and a session is reported
//     aborted while any fresh abort marker exists, whatever its JSON says.
//  5. Readers (LoadSession, ScanSessions) take no lock. They list and read the
//     markers first and read the session file second. Every writer that
//     removes a marker first commits a session file that carries the signal
//     (the taint merge) or that no longer should (a clear), by an atomic
//     rename or a deletion that completes before the marker removal starts. A reader that missed a
//     marker therefore reads a session file at least as new as the removal: a
//     signal that is active throughout a read, moving from marker to file, is
//     never lost. Reading the file first would let a merge commit and remove
//     the marker in between, so the reader would see neither. A failed removal
//     keeps the marker, and a marker that vanishes between its stat and its
//     read still counts, so both failures are conservative.
//
// A signal published concurrently with a clear can therefore survive it,
// which is the conservative outcome; no interleaving loses a signal that was
// published after the clear began.
const (
	taintMarkerKind = "taint"
	abortMarkerKind = "abort"
)

// markerSeq makes event IDs unique within a process.
var markerSeq atomic.Uint64

// newMarkerPath returns a fresh, unique marker path for one signal event.
func newMarkerPath(sessionID, kind string) string {
	id := strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatUint(markerSeq.Add(1), 36)
	return SessionFilePath(sessionID) + "." + kind + "." + id
}

func taintMarkerPath(sessionID string) string { return newMarkerPath(sessionID, taintMarkerKind) }
func abortMarkerPath(sessionID string) string { return newMarkerPath(sessionID, abortMarkerKind) }

// markerRecord is the content of a marker file. SessionID lets status report
// a marker-only session whose file name is a hash.
type markerRecord struct {
	SessionID string    `json:"session_id,omitempty"`
	ToolName  string    `json:"tool_name,omitempty"`
	At        time.Time `json:"at,omitempty"`
}

// writeMarkerFunc writes a marker file and statMarkerFunc checks one.
// Variables so tests can make them fail or interleave a competing writer.
var (
	writeMarkerFunc = writeMarker
	statMarkerFunc  = os.Stat
)

func writeMarker(path string, v interface{}) error {
	if err := os.MkdirAll(GetSessionsDir(), 0700); err != nil {
		return fmt.Errorf("failed to create sessions directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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

// parseMarkerName splits a marker file name into its session file base name
// and kind. ok is false for any other file.
func parseMarkerName(name string) (base, kind string, ok bool) {
	for _, k := range []string{taintMarkerKind, abortMarkerKind} {
		sep := ".json." + k
		if i := strings.Index(name, sep); i > 0 {
			rest := name[i+len(sep):]
			if rest == "" || strings.HasPrefix(rest, ".") {
				return name[:i+len(".json")], k, true
			}
		}
	}
	return "", "", false
}

// sessionMarkers is every marker file of one session file, as listed at one
// moment. Paths includes expired markers so a clear retires them too.
type sessionMarkers struct {
	Paths []string
	taint []string
	abort []string
}

// listMarkers groups the marker files in the sessions directory by session
// file base name.
func listMarkers() (map[string]*sessionMarkers, error) {
	entries, err := os.ReadDir(GetSessionsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]*sessionMarkers{}, nil
		}
		return nil, fmt.Errorf("failed to read sessions directory: %w", err)
	}
	return groupMarkers(entries), nil
}

func groupMarkers(entries []os.DirEntry) map[string]*sessionMarkers {
	groups := map[string]*sessionMarkers{}
	dir := GetSessionsDir()
	for _, entry := range entries {
		base, kind, ok := parseMarkerName(entry.Name())
		if !ok || entry.IsDir() {
			continue
		}
		m := groups[base]
		if m == nil {
			m = &sessionMarkers{}
			groups[base] = m
		}
		path := filepath.Join(dir, entry.Name())
		m.Paths = append(m.Paths, path)
		if kind == taintMarkerKind {
			m.taint = append(m.taint, path)
		} else {
			m.abort = append(m.abort, path)
		}
	}
	return groups
}

// markersFor lists the markers of one session.
func markersFor(sessionID string) (*sessionMarkers, error) {
	groups, err := listMarkers()
	if err != nil {
		return nil, err
	}
	if m := groups[SafeSessionFileName(sessionID)]; m != nil {
		return m, nil
	}
	return &sessionMarkers{}, nil
}

// statMarker reports whether a fresh marker exists at path. A stat failure
// other than a missing file is returned so the gate fails closed.
func statMarker(path string) (os.FileInfo, error) {
	info, err := statMarkerFunc(path)
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

// readMarker returns the record of a fresh marker, or nil when it is missing
// or expired. An undecodable fresh marker yields an empty record.
func readMarker(path string) (*markerRecord, os.FileInfo, error) {
	info, err := statMarker(path)
	if err != nil || info == nil {
		return nil, nil, err
	}
	var rec markerRecord
	if data, readErr := readFileWithRetry(path); readErr != nil || json.Unmarshal(data, &rec) != nil {
		rec = markerRecord{}
	}
	return &rec, info, nil
}

// markerSignals is what a session's fresh markers say, read at one moment.
type markerSignals struct {
	taint      *TaintSource
	aborted    bool
	recordedID string
}

// read reads the listed fresh markers. This and apply are the single
// definition of marker semantics, shared by LoadSession (the gate) and
// ScanSessions (status). The newest fresh taint marker supplies the taint
// source. A nil m has no markers.
func (m *sessionMarkers) read() (*markerSignals, error) {
	sig := &markerSignals{}
	if m == nil {
		return sig, nil
	}
	var newest time.Time
	for _, path := range m.taint {
		rec, info, err := readMarker(path)
		if err != nil {
			return nil, err
		}
		if rec == nil || (sig.taint != nil && !info.ModTime().After(newest)) {
			continue
		}
		newest = info.ModTime()
		sig.taint = &TaintSource{ToolName: rec.ToolName, At: rec.At}
		if sig.taint.ToolName == "" {
			sig.taint = &TaintSource{ToolName: "unknown tool", At: info.ModTime().UTC()}
		}
		if rec.SessionID != "" {
			sig.recordedID = rec.SessionID
		}
	}
	for _, path := range m.abort {
		rec, _, err := readMarker(path)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			sig.aborted = true
			if rec.SessionID != "" {
				sig.recordedID = rec.SessionID
			}
		}
	}
	return sig, nil
}

// apply folds the signals into state, which must have been read after the
// signals (invariant 5). state may be nil; a state is created when only a
// marker exists, with fallbackID unless a marker records the session ID.
func (sig *markerSignals) apply(state *SessionState, fallbackID string) *SessionState {
	if sig.taint == nil && !sig.aborted {
		return state
	}
	if state == nil {
		id := sig.recordedID
		if id == "" {
			id = fallbackID
		}
		state = &SessionState{SessionID: id}
	}
	if sig.taint != nil && !state.Tainted {
		state.Tainted = true
		state.TaintSource = sig.taint
	}
	if sig.aborted {
		state.Aborted = true
		state.Prompt = ""
	}
	return state
}

// hasFreshAbort reports whether any listed abort marker is fresh.
func (m *sessionMarkers) hasFreshAbort() (bool, error) {
	for _, path := range m.abort {
		info, err := statMarker(path)
		if err != nil {
			return false, err
		}
		if info != nil {
			return true, nil
		}
	}
	return false, nil
}

// retire removes the listed markers whose signal the just-saved state no
// longer carries (invariant 1). A marker that cannot be removed keeps its
// signal active, which is the conservative failure.
func (m *sessionMarkers) retire(state *SessionState) error {
	var errs []error
	if !state.Tainted {
		errs = append(errs, removeMarkers(m.taint))
	}
	if !state.Aborted {
		errs = append(errs, removeMarkers(m.abort))
	}
	return errors.Join(errs...)
}

func removeMarkers(paths []string) error {
	var errs []error
	for _, p := range paths {
		errs = append(errs, removeMarker(p))
	}
	return errors.Join(errs...)
}

func removeMarker(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove marker %s: %w", path, err)
	}
	return nil
}

// sortedBases returns the keys of groups in order, for deterministic scans.
func sortedBases(groups map[string]*sessionMarkers) []string {
	bases := make([]string, 0, len(groups))
	for b := range groups {
		bases = append(bases, b)
	}
	sort.Strings(bases)
	return bases
}
