package session

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
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
//     A session whose lock is held, or whose lock cannot be taken at once for
//     any other reason, is skipped until a later sweep.
//   - Markers and session files are removed only when they are older than
//     sweepStaleAge, which is longer than any configurable intent TTL. They
//     are therefore expired whatever TTL the current project configures, and
//     their age is checked again under the lock.
//   - A lock file is removed only while its session file is absent, every
//     marker the sweep listed for the session is gone (and it listed no more
//     than one run handles), and the lock file has
//     been idle for sweepLockIdle (holders refresh its modification time, see
//     verifyLock). Acquisition verifies that the path still names the locked
//     file and retries otherwise, so removing it never lets two processes
//     hold locks on different files at the same path (lock.go). A marker the
//     sweep did not list (outside this run's window, or written later) does
//     not need the lock file to exist.
//   - Errors are ignored. A file the sweep cannot remove stays, which is
//     harmless, and a sweep never fails the hook that runs it.
//
// Bounded work: hooks run the sweep synchronously, so one run inspects at
// most sweepMaxEntries directory entries, visits at most sweepMaxSessions
// sessions, performs at most sweepMaxOps filesystem operations while visiting
// them, and stops at a shared deadline of sweepBudget, checked before each
// filesystem operation. A run that stops early keeps everything it has not
// checked. Each run continues where the previous one stopped: the position
// in the directory listing is persisted as a cursor, and the next run starts
// at the first session it did not finish. At the end of the listing the
// cursor wraps to the start.
//
// MaybeSweep runs at most once per sweepInterval, tracked by the modification
// time of a permanent coordination file that also stores the cursor. A sweep
// holds a non-blocking lock on that file for its whole run, so concurrent
// hooks never sweep at the same time: a hook that finds it locked skips.

// Sweep parameters. Variables so tests can change them.
var (
	sweepInterval    = time.Hour
	sweepStaleAge    = 48 * time.Hour     // more than the 24 h maximum intent TTL
	sweepLockIdle    = 7 * 24 * time.Hour // much longer than any intent TTL
	sweepMaxSessions = 128
	sweepMaxEntries  = 1024 // directory entries inspected (stat) per run
	sweepMaxMarkers  = 64   // markers handled per session per run
	sweepMaxOps      = 1024 // filesystem operations on sessions per run
	sweepBudget      = 150 * time.Millisecond
	sweepReadChunk   = 128 // directory entries read per ReadDir call

	sweepNow = time.Now

	// sweepLockedHook runs after MaybeSweep takes the coordination lock.
	// Tests use it to hold the lock while another MaybeSweep runs.
	sweepLockedHook func()
)

// sweepStampName is the permanent coordination file: its lock excludes
// concurrent sweeps, its modification time records the last sweep, and its
// content is the cursor. It is never deleted. It is not a session, marker,
// lock, or temp file name.
const sweepStampName = ".sweep"

// MaybeSweep runs a sweep when no sweep has started within sweepInterval and
// no other sweep is running. It never creates the sessions directory and
// never reports an error.
func MaybeSweep() {
	dir := GetSessionsDir()
	stamp := filepath.Join(dir, sweepStampName)
	if info, err := os.Stat(stamp); err == nil {
		if recentSweep(info) {
			return
		}
	} else if !os.IsNotExist(err) {
		return
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return
	}
	f, err := os.OpenFile(stamp, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	if locked, err := tryLockFile(f); !locked || err != nil {
		return // another hook is sweeping
	}
	defer func() { _ = unlockFile(f) }()
	if sweepLockedHook != nil {
		sweepLockedHook()
	}
	// Recheck under the lock: a sweep may have finished since the first stat.
	if info, err := f.Stat(); err != nil || recentSweep(info) {
		return
	}
	// Claim the interval: a claimed stamp is recent and never empty.
	start := readCursor(f)
	if err := touchLockFile(f); err != nil || !writeCursor(f, start) {
		return
	}
	_, next := sweepFrom(start)
	writeCursor(f, next)
}

// recentSweep reports whether the stamp records a sweep within sweepInterval.
// A sweep always leaves the stamp non-empty, so an empty stamp (just created
// by this or a concurrent hook, which then failed to claim it) is not one.
func recentSweep(info os.FileInfo) bool {
	age := time.Since(info.ModTime())
	return info.Size() > 0 && age >= 0 && age < sweepInterval
}

// readCursor reads the cursor stored in the coordination file; anything
// unparseable reads as 0.
func readCursor(f *os.File) int {
	buf := make([]byte, 32)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// writeCursor stores the cursor and, by writing, refreshes the stamp's
// modification time. It reports success.
func writeCursor(f *os.File, cursor int) bool {
	if err := f.Truncate(0); err != nil {
		return false
	}
	_, err := f.WriteAt([]byte(strconv.Itoa(cursor)), 0)
	return err == nil
}

// Sweep runs one bounded sweep from the start of the directory listing. It
// returns the number of sessions it visited under their lock.
func Sweep() int {
	visited, _ := sweepFrom(0)
	return visited
}

// sweepBudgetState bounds one run: a shared deadline and an operation count.
type sweepBudgetState struct {
	deadline time.Time
	ops      int
}

// take reports whether one more filesystem operation fits the budget and
// accounts for it.
func (b *sweepBudgetState) take() bool {
	if b.ops <= 0 || !sweepNow().Before(b.deadline) {
		return false
	}
	b.ops--
	return true
}

func (b *sweepBudgetState) expired() bool {
	return !sweepNow().Before(b.deadline)
}

// sweepCandidate is one session the sweep visits: its session file base name,
// the marker files listed for it, and the position of its first entry in the
// run's window.
type sweepCandidate struct {
	base      string
	markers   []string
	truncated bool // more markers were listed than this run handles
	first     int
}

// sweepFrom runs one bounded sweep over the directory entries starting at
// position start of the listing. It returns the number of sessions visited
// under their lock and the cursor for the next run.
func sweepFrom(start int) (visited, next int) {
	dir := GetSessionsDir()
	begin := sweepNow()
	budget := &sweepBudgetState{deadline: begin.Add(sweepBudget), ops: sweepMaxOps}
	// Listing gets half the time, so visiting sessions always has some left.
	listBudget := &sweepBudgetState{deadline: begin.Add(sweepBudget / 2), ops: sweepMaxEntries}

	window, start, eof, ok := readWindow(dir, start, listBudget)
	if !ok {
		return 0, start
	}
	staleAge := maxDuration(sweepStaleAge, 2*sessionTTL)
	lockIdle := maxDuration(sweepLockIdle, 4*sessionTTL)

	// Window positions of each entry's session, and ages of regular files.
	ages := map[string]time.Duration{}
	firsts := map[string]int{}
	markers := map[string][]string{}
	for i, e := range window {
		name := e.entry.Name()
		base := ""
		if b, _, isMarker := parseMarkerName(name); isMarker {
			base = b
			markers[b] = append(markers[b], filepath.Join(dir, name))
		} else if strings.HasSuffix(name, ".json.lock") {
			base = strings.TrimSuffix(name, ".lock")
		} else if strings.HasSuffix(name, ".json") {
			base = name
		}
		if base == "" {
			continue
		}
		if _, seen := firsts[base]; !seen {
			firsts[base] = i
		}
		if e.regular {
			ages[name] = e.age
		}
	}
	candidates := map[string]bool{}
	for base, paths := range markers {
		for _, p := range paths {
			if age, ok := ages[filepath.Base(p)]; ok && age > staleAge {
				candidates[base] = true
				break
			}
		}
	}
	for name, age := range ages {
		switch {
		case strings.HasSuffix(name, ".json") && age > staleAge:
			// The modification time bounds UpdatedAt from above; the
			// recorded UpdatedAt is checked under the lock.
			candidates[name] = true
		case strings.HasSuffix(name, ".json.lock") && age > lockIdle:
			// A session file outside the window is found under the lock.
			base := strings.TrimSuffix(name, ".lock")
			if _, hasSession := ages[base]; !hasSession {
				candidates[base] = true
			}
		}
	}
	// Visit in listing order, so a run that stops early can resume at the
	// first session it did not finish: every entry before that session's
	// first entry belongs to a finished session or to none.
	ordered := make([]*sweepCandidate, len(window))
	for base := range candidates {
		c := &sweepCandidate{base: base, markers: markers[base], first: firsts[base]}
		if len(c.markers) > sweepMaxMarkers {
			// The rest stay for the next pass over this part of the listing.
			c.markers = c.markers[:sweepMaxMarkers]
			c.truncated = true
		}
		ordered[c.first] = c
	}

	// Removing an entry shifts the later ones up in the listing, so the
	// cursor counts only the entries before the cut that are still there.
	index := make(map[string]int, len(window))
	for i, e := range window {
		index[e.entry.Name()] = i
	}
	removed := make([]bool, len(window))
	gone := func(path string) {
		if i, ok := index[filepath.Base(path)]; ok {
			removed[i] = true
		}
	}
	cursor := func(cut int) int {
		n := start
		for i := 0; i < cut; i++ {
			if !removed[i] {
				n++
			}
		}
		return n
	}
	for _, c := range ordered {
		if c == nil {
			continue
		}
		if visited >= sweepMaxSessions || budget.expired() {
			return visited, cursor(c.first)
		}
		got, done := sweepSession(dir, c, staleAge, lockIdle, budget, gone)
		if got {
			visited++
		}
		if !done {
			return visited, cursor(c.first)
		}
	}
	if eof {
		return visited, 0
	}
	return visited, cursor(len(window))
}

// windowEntry is one inspected directory entry.
type windowEntry struct {
	entry   os.DirEntry
	regular bool
	age     time.Duration
}

// readWindow skips the first start entries of dir and inspects at most
// budget.ops entries after them, within the budget's deadline. It returns the
// window's actual start, which is 0 when the listing has shrunk below start.
// eof reports that the listing ended within the window. ok is false when the
// directory cannot be read or the deadline passed before the window was
// reached.
func readWindow(dir string, start int, budget *sweepBudgetState) (window []windowEntry, at int, eof, ok bool) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, start, false, false
	}
	defer f.Close()
	skipped := 0
	for skipped < start {
		if budget.expired() {
			return nil, start, false, false
		}
		n := sweepReadChunk
		if start-skipped < n {
			n = start - skipped
		}
		entries, err := f.ReadDir(n)
		skipped += len(entries)
		if err != nil {
			if errors.Is(err, io.EOF) && start > 0 {
				// The listing shrank below the cursor: wrap to the start.
				return readWindow(dir, 0, budget)
			}
			return nil, start, false, false
		}
	}
	for {
		n := sweepReadChunk
		if budget.ops < n {
			n = budget.ops
		}
		if n <= 0 || budget.expired() {
			return window, start, false, true
		}
		entries, err := f.ReadDir(n)
		for _, e := range entries {
			if !budget.take() {
				// Entries read but not inspected are revisited next run;
				// the cursor counts only inspected entries.
				return window, start, false, true
			}
			we := windowEntry{entry: e}
			if !e.IsDir() {
				if info, infoErr := e.Info(); infoErr == nil && info.Mode().IsRegular() {
					we.regular = true
					we.age = time.Since(info.ModTime())
				}
			}
			window = append(window, we)
		}
		if err != nil {
			return window, start, errors.Is(err, io.EOF), true
		}
	}
}

// sweepSession cleans one session under its lock, taken without waiting. It
// reports whether it got the lock and whether it finished within the budget;
// an unfinished session keeps everything it did not check. It calls gone for
// each file it found absent or removed.
func sweepSession(dir string, c *sweepCandidate, staleAge, lockIdle time.Duration, budget *sweepBudgetState, gone func(path string)) (got, done bool) {
	if !budget.take() {
		return false, false
	}
	l, err := acquireLock(filepath.Join(dir, c.base+".lock"), false, false)
	if err != nil || l == nil {
		return false, true
	}
	remaining := 0
	for _, p := range c.markers {
		if !budget.take() {
			l.release(false)
			return true, false
		}
		if removeIfOlder(p, staleAge) {
			gone(p)
		} else {
			remaining++
		}
	}
	if !budget.take() {
		l.release(false)
		return true, false
	}
	sessionPath := filepath.Join(dir, c.base)
	sessionGone := reapStaleSessionFile(sessionPath, staleAge)
	if sessionGone {
		gone(sessionPath)
	}
	idle := time.Since(l.info.ModTime()) > lockIdle
	// Markers created after the listing are fresh signals; they survive
	// (they are not touched) and do not need this lock file to exist.
	remove := remaining == 0 && !c.truncated && sessionGone && idle
	l.release(remove)
	if remove {
		// Windows may refuse the deletion (an open handle); only a lock
		// file that is really gone shifts the listing.
		if _, err := os.Lstat(l.path); os.IsNotExist(err) {
			gone(l.path)
		}
	}
	return true, true
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
// reports it. It reads once, without the transient-error backoff, so the sweep
// stays bounded; a file it cannot read now is kept until a later sweep. It
// reports whether no session file exists afterwards.
func reapStaleSessionFile(path string, age time.Duration) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	if !info.Mode().IsRegular() || time.Since(info.ModTime()) <= age {
		return false
	}
	data, err := readFileFunc(path)
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
