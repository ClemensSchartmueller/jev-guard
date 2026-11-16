package session

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The sweep removes what abandoned sessions leave behind: lock files, which
// are created once per session ID and otherwise never deleted, taint and abort
// markers that expired without a clear, and session files that expired long
// ago (an aborted session is kept by end-turn and is only reaped when it is
// read again).
//
// Safety rules:
//
//   - Every removal happens under the session's lock, taken without waiting.
//     A session whose lock is held is skipped until a later sweep.
//   - Markers and session files are removed only when they are older than
//     sweepStaleAge, which is longer than any configurable intent TTL. They
//     are therefore expired whatever TTL the current project configures, and
//     their age is checked again under the lock.
//   - A lock file is removed only while its session file is absent, every
//     marker the sweep listed for the session is gone, and the lock file has
//     been idle for sweepLockIdle (holders refresh its modification time, see
//     verifyLock). Acquisition verifies that the path still names the locked
//     file and retries otherwise, so removing it never lets two processes
//     hold locks on different files at the same path (lock.go).
//   - Errors are ignored. A file the sweep cannot remove stays, which is
//     harmless, and a sweep never fails the hook that runs it.
//
// MaybeSweep runs at most once per sweepInterval (tracked by the modification
// time of a stamp file) and visits at most sweepMaxSessions sessions, so
// hooks pay for it rarely and boundedly.

// Sweep parameters. Variables so tests can change them.
var (
	sweepInterval    = time.Hour
	sweepStaleAge    = 48 * time.Hour     // more than the 24 h maximum intent TTL
	sweepLockIdle    = 7 * 24 * time.Hour // much longer than any intent TTL
	sweepMaxSessions = 128
)

// sweepStampName is the stamp file whose modification time records the last
// sweep. It is not a session, marker, lock, or temp file name.
const sweepStampName = ".sweep"

// MaybeSweep runs Sweep when no sweep has started within sweepInterval. It
// never creates the sessions directory and never reports an error.
func MaybeSweep() {
	stamp := filepath.Join(GetSessionsDir(), sweepStampName)
	if info, err := os.Stat(stamp); err == nil {
		if age := time.Since(info.ModTime()); age >= 0 && age < sweepInterval {
			return
		}
	} else if !os.IsNotExist(err) {
		return
	}
	if _, err := os.Stat(GetSessionsDir()); err != nil {
		return
	}
	// Record the start first, so concurrent hooks do not all sweep.
	f, err := os.OpenFile(stamp, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	_ = f.Close()
	now := time.Now()
	if err := os.Chtimes(stamp, now, now); err != nil {
		return
	}
	Sweep()
}

// sweepCandidate is one session the sweep visits: its session file base name
// and the marker files listed for it.
type sweepCandidate struct {
	base    string
	markers []string
}

// Sweep removes stale files of abandoned sessions (see the rules above). It
// returns the number of sessions it visited under their lock.
func Sweep() int {
	dir := GetSessionsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	staleAge := maxDuration(sweepStaleAge, 2*sessionTTL)
	lockIdle := maxDuration(sweepLockIdle, 4*sessionTTL)

	ages := map[string]time.Duration{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			ages[e.Name()] = time.Since(info.ModTime())
		}
	}
	markers := groupMarkers(entries)
	candidates := map[string]*sweepCandidate{}
	add := func(base string) {
		if candidates[base] == nil {
			c := &sweepCandidate{base: base}
			if m := markers[base]; m != nil {
				c.markers = m.Paths
			}
			candidates[base] = c
		}
	}
	for base, m := range markers {
		for _, p := range m.Paths {
			if age, ok := ages[filepath.Base(p)]; ok && age > staleAge {
				add(base)
				break
			}
		}
	}
	for name, age := range ages {
		switch {
		case strings.HasSuffix(name, ".json") && age > staleAge:
			// The modification time bounds UpdatedAt from above; the
			// recorded UpdatedAt is checked under the lock.
			add(name)
		case strings.HasSuffix(name, ".json.lock") && age > lockIdle:
			base := strings.TrimSuffix(name, ".lock")
			if _, hasSession := ages[base]; !hasSession {
				add(base)
			}
		}
	}

	bases := make([]string, 0, len(candidates))
	for b := range candidates {
		bases = append(bases, b)
	}
	sort.Strings(bases)
	if len(bases) > sweepMaxSessions {
		// Start at a varying offset, so candidates that are kept (an
		// unreadable session file, a held lock) cannot starve the rest.
		start := int(time.Now().UnixNano() % int64(len(bases)))
		bases = append(append([]string{}, bases[start:]...), bases[:start]...)[:sweepMaxSessions]
	}
	visited := 0
	for _, b := range bases {
		if sweepSession(dir, candidates[b], staleAge, lockIdle) {
			visited++
		}
	}
	return visited
}

// sweepSession cleans one session under its lock, taken without waiting. It
// reports whether it got the lock.
func sweepSession(dir string, c *sweepCandidate, staleAge, lockIdle time.Duration) bool {
	l, err := acquireLock(filepath.Join(dir, c.base+".lock"), false, false)
	if err != nil || l == nil {
		return false
	}
	remaining := 0
	for _, p := range c.markers {
		if !removeIfOlder(p, staleAge) {
			remaining++
		}
	}
	sessionPath := filepath.Join(dir, c.base)
	sessionGone := reapStaleSessionFile(sessionPath, staleAge)
	idle := time.Since(l.info.ModTime()) > lockIdle
	// Markers created after the listing are fresh signals; they survive
	// (they are not touched) and do not need this lock file to exist.
	l.release(remaining == 0 && sessionGone && idle)
	return true
}

// removeIfOlder removes the regular file at path if it is older than age. It
// reports whether the file is gone afterwards.
func removeIfOlder(path string, age time.Duration) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	if !info.Mode().IsRegular() || time.Since(info.ModTime()) <= age {
		return false
	}
	err = os.Remove(path)
	return err == nil || os.IsNotExist(err)
}

// reapStaleSessionFile removes the session file at path, called under its
// lock, when both its modification time and its recorded UpdatedAt are older
// than age. An unreadable file is kept: the gate fails closed on it and status
// reports it. It reports whether no session file exists afterwards.
func reapStaleSessionFile(path string, age time.Duration) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	if !info.Mode().IsRegular() || time.Since(info.ModTime()) <= age {
		return false
	}
	data, err := readFileWithRetry(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	state, err := decodeSession(data)
	if err != nil || state.UpdatedAt.IsZero() || time.Since(state.UpdatedAt) <= age {
		return false
	}
	err = os.Remove(path)
	return err == nil || os.IsNotExist(err)
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
