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
// Bounded work: hooks run the sweep synchronously, so every run is bounded
// in time and in filesystem calls, and the bounds are checked before each
// individual call:
//
//   - Listing reads names only (no stat per name), at most sweepMaxNames of
//     them in chunks of sweepReadChunk, and lstats only the session, lock,
//     and marker names in its window of at most sweepMaxEntries entries. It
//     stops at the listing deadline, half of sweepBudget, checked before
//     opening the directory, before each chunk, and before each lstat.
//   - Visiting sessions charges one unit of a sweepMaxOps budget before each
//     filesystem call (open, lock, stat, read, remove) and checks the shared
//     sweepBudget deadline at the same point. Closing or unlocking a file the
//     sweep holds is never skipped and is not charged. At most
//     sweepMaxSessions sessions and sweepMaxMarkers markers per session are
//     visited. A session file larger than sweepMaxSessionFile is kept without
//     being read, and reading one is capped at that size as well.
//   - The coordination file adds a fixed handful of calls per run.
//
// A run that stops early keeps everything it has not checked.
//
// Progress: the position in the directory listing is persisted as a cursor,
// and each run reads the names before the cursor (names only) to get there.
// Every run ends in one of three ways:
//
//  1. It read entries at the cursor and processed some of them: the next
//     cursor is past the first entry it started at, or that entry was
//     removed and the listing shrank. A run never returns its own start
//     unchanged with nothing removed.
//  2. It reached the end of the listing: the cursor wraps to 0.
//  3. It could not reach the cursor (the name budget or the listing deadline
//     ran out while skipping, or the listing shrank below it), or could not
//     inspect any entry at it: it falls back to the start of the listing,
//     processes the names it already read there if time allows, and returns
//     a cursor counted from 0.
//
// The cursor therefore never repeats the same failed skip: after an
// unreachable cursor the next run starts at (or near) 0, where skipping is
// free, and advances from there. Between two resets the cursor only grows or
// the directory shrinks, so every entry that one run can reach (within
// sweepMaxNames names and the listing deadline, which bounds what any single
// run can read) is visited within a bounded number of runs. Entries beyond
// that horizon cannot be reached by any bounded run, positional or not; the
// horizon is large because reading names is cheap, and it widens as the
// sweep removes abandoned entries in front of them.
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
	sweepMaxNames    = 16384 // directory names read per run, skipped ones included
	sweepMaxEntries  = 1024  // entries in one run's window (each lstat'ed at most once)
	sweepMaxMarkers  = 64    // markers handled per session per run
	sweepMaxOps      = 1024  // filesystem calls on sessions per run
	// sweepMaxSessionFile caps how much of a session file the sweep reads.
	// The session code sets no limit of its own (prompts are stored whole),
	// so the cap is far above any realistic session file. A larger stale
	// file is kept, never deleted; the gate still reaps it by TTL when it
	// reads the session again.
	sweepMaxSessionFile = int64(16 << 20)
	sweepBudget         = 150 * time.Millisecond
	sweepReadChunk      = 256 // names read per Readdirnames call

	sweepNow = time.Now

	// Filesystem calls of the sweep, replaceable so tests can count them
	// or simulate slow storage. Lock acquisition uses openLockFile and
	// statLockPath (lock.go).
	sweepLstat     = os.Lstat
	sweepOpen      = os.Open
	sweepRemove    = os.Remove
	sweepReadNames = func(f *os.File, n int) ([]string, error) { return f.Readdirnames(n) }

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

// sweepBudgetState bounds one phase of a run: a deadline and a count of
// filesystem calls. Once a charge is refused, out stays set.
type sweepBudgetState struct {
	deadline time.Time
	ops      int
	out      bool
}

// take charges n filesystem calls, or n names for the listing. It reports
// false, and charges nothing, when they do not fit the count or the deadline
// has passed.
func (b *sweepBudgetState) take(n int) bool {
	if b.out || b.ops < n || !sweepNow().Before(b.deadline) {
		b.out = true
		return false
	}
	b.ops -= n
	return true
}

// step charges one filesystem call.
func (b *sweepBudgetState) step() bool { return b.take(1) }

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
// under their lock and the cursor for the next run (see Progress above).
func sweepFrom(start int) (visited, next int) {
	dir := GetSessionsDir()
	begin := sweepNow()
	budget := &sweepBudgetState{deadline: begin.Add(sweepBudget), ops: sweepMaxOps}
	// Listing gets half the time, so visiting sessions always has some left.
	listDeadline := begin.Add(sweepBudget / 2)

	window, start, eof := readWindow(dir, start, listDeadline)
	if len(window) == 0 {
		// Nothing inspected at the cursor: restart from the beginning.
		return 0, 0
	}
	staleAge := maxDuration(sweepStaleAge, 2*sessionTTL)
	lockIdle := maxDuration(sweepLockIdle, 4*sessionTTL)

	// Window positions of each entry's session, and ages of regular files.
	ages := map[string]time.Duration{}
	firsts := map[string]int{}
	markers := map[string][]string{}
	for i, e := range window {
		base := ""
		if b, _, isMarker := parseMarkerName(e.name); isMarker {
			base = b
			markers[b] = append(markers[b], filepath.Join(dir, e.name))
		} else if strings.HasSuffix(e.name, ".json.lock") {
			base = strings.TrimSuffix(e.name, ".lock")
		} else if strings.HasSuffix(e.name, ".json") {
			base = e.name
		}
		if base == "" {
			continue
		}
		if _, seen := firsts[base]; !seen {
			firsts[base] = i
		}
		if e.regular {
			ages[e.name] = e.age
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
		index[e.name] = i
	}
	removed := make([]bool, len(window))
	gone := func(path string) {
		if i, ok := index[filepath.Base(path)]; ok {
			removed[i] = true
		}
	}
	cursor := func(cut int) int {
		// Never end where this run started: an unfinished first entry is
		// left for the next pass over the listing (case 1 above).
		if cut < 1 {
			cut = 1
		}
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
		if visited >= sweepMaxSessions || budget.expired() || budget.out {
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
	name    string
	regular bool
	age     time.Duration
}

// readWindow lists dir by name and returns the window of entries starting at
// position start, at most sweepMaxEntries of them, together with the window's
// actual start and whether the listing ended within the window. Names before
// start are skipped unread beyond the name itself; every name read counts
// against sweepMaxNames. When no name at start could be read (the name budget
// or the deadline ran out while skipping, or the listing has fewer entries),
// the window falls back to the names already read from position 0. Session,
// lock, and marker names in the window are lstat'ed, each after a deadline
// check; the window ends before the first one the deadline leaves unchecked,
// and is empty when nothing could be inspected.
func readWindow(dir string, start int, deadline time.Time) (window []windowEntry, at int, eof bool) {
	names := &sweepBudgetState{deadline: deadline, ops: sweepMaxNames}
	if !names.step() {
		return nil, 0, false
	}
	f, err := sweepOpen(dir)
	if err != nil {
		return nil, 0, false
	}
	defer f.Close()
	var head, list []string
	pos, ended := 0, false
	for len(list) < sweepMaxEntries {
		n := sweepReadChunk
		if start+sweepMaxEntries-pos < n {
			n = start + sweepMaxEntries - pos // never read past the window
		}
		if names.ops < n {
			n = names.ops
		}
		if n <= 0 || !names.take(n) {
			break
		}
		chunk, err := sweepReadNames(f, n)
		for _, name := range chunk {
			switch {
			case pos >= start:
				list = append(list, name)
			case len(head) < sweepMaxEntries:
				head = append(head, name)
			}
			pos++
		}
		if err != nil {
			ended = errors.Is(err, io.EOF)
			if !ended {
				return nil, 0, false
			}
			break
		}
	}
	at, eof = start, ended
	if len(list) == 0 && start > 0 {
		// The cursor is unreachable in this run: start over from 0 with
		// the names already read, so the next run never repeats this skip.
		list, at, eof = head, 0, ended && pos <= sweepMaxEntries
	}
	for _, name := range list {
		we := windowEntry{name: name}
		if sweepRelevant(name) {
			if !sweepNow().Before(deadline) {
				// Not inspected: the cursor ends before it.
				return window, at, false
			}
			if info, err := sweepLstat(filepath.Join(dir, name)); err == nil && info.Mode().IsRegular() {
				we.regular = true
				we.age = time.Since(info.ModTime())
			}
		}
		window = append(window, we)
	}
	return window, at, eof
}

// sweepRelevant reports whether the sweep looks at a directory entry: a
// session file, a lock file, or a marker.
func sweepRelevant(name string) bool {
	if _, _, ok := parseMarkerName(name); ok {
		return true
	}
	return strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".json.lock")
}

// sweepSession cleans one session under its lock, taken without waiting. It
// reports whether it got the lock and whether it finished within the budget;
// an unfinished session keeps everything it did not check. It calls gone for
// each file it found absent or removed. Every filesystem call is charged to
// budget first.
func sweepSession(dir string, c *sweepCandidate, staleAge, lockIdle time.Duration, budget *sweepBudgetState, gone func(path string)) (got, done bool) {
	l, err := acquireLock(filepath.Join(dir, c.base+".lock"), false, false, budget.step)
	if err != nil || l == nil {
		// A held or unusable lock skips the session; an exhausted budget
		// leaves it unfinished.
		return false, !budget.out
	}
	remaining := 0
	for _, p := range c.markers {
		if removeIfOlder(p, staleAge, budget.step) {
			gone(p)
		} else {
			remaining++
		}
		if budget.out {
			l.release(false)
			return true, false
		}
	}
	sessionPath := filepath.Join(dir, c.base)
	sessionGone := reapStaleSessionFile(sessionPath, staleAge, budget.step)
	if budget.out {
		l.release(false)
		return true, false
	}
	if sessionGone {
		gone(sessionPath)
	}
	idle := time.Since(l.info.ModTime()) > lockIdle
	// Markers created after the listing are fresh signals; they survive
	// (they are not touched) and do not need this lock file to exist.
	remove := remaining == 0 && !c.truncated && sessionGone && idle
	if remove && !budget.step() {
		// No budget left to delete the lock file: finish on a later run.
		l.release(false)
		return true, false
	}
	l.release(remove)
	if remove && budget.step() {
		// Windows may refuse the deletion (an open handle); only a lock
		// file that is really gone shifts the listing.
		if _, err := sweepLstat(l.path); os.IsNotExist(err) {
			gone(l.path)
		}
	}
	return true, true
}

// removeIfOlder removes the regular file at path if it is older than age,
// charging step before each filesystem call. It reports whether the file is
// gone afterwards.
func removeIfOlder(path string, age time.Duration, step func() bool) bool {
	if !step() {
		return false
	}
	info, err := sweepLstat(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	if !info.Mode().IsRegular() || time.Since(info.ModTime()) <= age || !step() {
		return false
	}
	err = sweepRemove(path)
	return err == nil || os.IsNotExist(err)
}

// reapStaleSessionFile removes the session file at path, called under its
// lock, when both its modification time and its recorded UpdatedAt are older
// than age. It charges step before each filesystem call, including each read.
// It fails closed: a file that is unreadable, undecodable, larger than
// sweepMaxSessionFile, or not fully read within the budget is kept (the gate
// fails closed on an unreadable file and status reports it). It reads once,
// without the transient-error backoff, so the sweep stays bounded. It reports
// whether no session file exists afterwards.
func reapStaleSessionFile(path string, age time.Duration, step func() bool) bool {
	if !step() {
		return false
	}
	info, err := sweepLstat(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	if !info.Mode().IsRegular() || time.Since(info.ModTime()) <= age || info.Size() > sweepMaxSessionFile || !step() {
		return false
	}
	f, err := sweepOpen(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	// The file may have grown since the lstat: read at most one byte more
	// than the cap, so an oversized file is detected without reading it all.
	data, err := io.ReadAll(io.LimitReader(&stepReader{r: f, step: step}, sweepMaxSessionFile+1))
	_ = f.Close()
	if err != nil || int64(len(data)) > sweepMaxSessionFile {
		return false
	}
	state, err := decodeSession(data)
	if err != nil || state.UpdatedAt.IsZero() || time.Since(state.UpdatedAt) <= age || !step() {
		return false
	}
	err = sweepRemove(path)
	return err == nil || os.IsNotExist(err)
}

// errSweepBudget stops a read when the sweep's budget is exhausted.
var errSweepBudget = errors.New("sweep budget exhausted")

// stepReader charges step before each read call.
type stepReader struct {
	r    io.Reader
	step func() bool
}

func (s *stepReader) Read(p []byte) (int, error) {
	if !s.step() {
		return 0, errSweepBudget
	}
	return s.r.Read(p)
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
