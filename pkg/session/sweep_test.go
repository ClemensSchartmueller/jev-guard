package session

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeAged creates a file with the given content and modification time.
func writeAged(t *testing.T, path string, data []byte, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ts := time.Now().Add(-age)
	if err := os.Chtimes(path, ts, ts); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

const (
	ancient = 30 * 24 * time.Hour // older than sweepStaleAge and sweepLockIdle
	hourAgo = time.Hour
)

func TestSweep_RemovesAbandonedLockAndMarkers(t *testing.T) {
	setupTestJevguardDir(t)
	lock := sessionLockPath("gone")
	taint := SessionFilePath("gone") + ".taint.old1"
	abort := SessionFilePath("gone") + ".abort.old2"
	writeAged(t, lock, nil, ancient)
	writeAged(t, taint, []byte(`{"session_id":"gone"}`), ancient)
	writeAged(t, abort, []byte(`{"session_id":"gone"}`), ancient)
	// A lone ancient lock file without markers.
	lone := sessionLockPath("lone")
	writeAged(t, lone, nil, ancient)
	// An aborted session that end-turn kept and nobody read since.
	stale := SessionFilePath("stalled")
	data, _ := json.Marshal(SessionState{SessionID: "stalled", Aborted: true, UpdatedAt: time.Now().Add(-ancient)})
	writeAged(t, stale, data, ancient)
	writeAged(t, sessionLockPath("stalled"), nil, ancient)

	if n := Sweep(); n != 3 {
		t.Fatalf("Sweep visited %d sessions, want 3", n)
	}
	for _, p := range []string{lock, taint, abort, lone, stale, sessionLockPath("stalled")} {
		if exists(p) {
			t.Errorf("%s was not swept", filepath.Base(p))
		}
	}
}

func TestSweep_KeepsRecentFiles(t *testing.T) {
	setupTestJevguardDir(t)
	// Recently used lock file of a session between turns (no session file).
	recentLock := sessionLockPath("between-turns")
	writeAged(t, recentLock, nil, hourAgo)
	// Markers expired under the default TTL but younger than the stale age:
	// another project may configure a TTL of up to 24 hours.
	youngMarker := SessionFilePath("young") + ".taint.x"
	writeAged(t, youngMarker, nil, 2*hourAgo)
	writeAged(t, sessionLockPath("young"), nil, ancient)
	// An ancient lock whose session file still exists (current state).
	live := &SessionState{SessionID: "live", Prompt: "build it"}
	if err := SaveSession(live); err != nil {
		t.Fatal(err)
	}
	liveLock := sessionLockPath("live")
	ts := time.Now().Add(-ancient)
	if err := os.Chtimes(liveLock, ts, ts); err != nil {
		t.Fatal(err)
	}
	// An ancient lock with a fresh marker: the marker stays, so does the lock.
	freshMarker := SessionFilePath("fresh") + ".abort.y"
	writeAged(t, freshMarker, nil, 0)
	writeAged(t, sessionLockPath("fresh"), nil, ancient)
	// An unreadable ancient session file is kept (the gate fails closed on it).
	broken := SessionFilePath("broken")
	writeAged(t, broken, []byte("{not json"), ancient)
	writeAged(t, sessionLockPath("broken"), nil, ancient)

	Sweep()

	for _, p := range []string{recentLock, youngMarker, sessionLockPath("young"), SessionFilePath("live"), liveLock, freshMarker, sessionLockPath("fresh"), broken, sessionLockPath("broken")} {
		if !exists(p) {
			t.Errorf("%s was swept", filepath.Base(p))
		}
	}
	got, err := LoadSession("live")
	if err != nil || got == nil || got.Prompt != "build it" {
		t.Fatalf("live session changed: %+v, %v", got, err)
	}
	if s, err := LoadSession("fresh"); err != nil || s == nil || !s.Aborted {
		t.Fatalf("fresh abort marker lost: %+v, %v", s, err)
	}
}

func TestSweep_SkipsLockedSession(t *testing.T) {
	setupTestJevguardDir(t)
	lock := sessionLockPath("busy")
	marker := SessionFilePath("busy") + ".taint.old"
	writeAged(t, lock, nil, ancient)
	writeAged(t, marker, nil, ancient)
	release := holdLock(t, "busy", nil)
	if n := Sweep(); n != 0 {
		t.Errorf("Sweep visited %d locked sessions", n)
	}
	if !exists(lock) || !exists(marker) {
		t.Error("sweep removed files of a locked session")
	}
	release()
	// The holder refreshed the lock file's modification time, so a later
	// sweep removes the expired marker but keeps the lock file.
	Sweep()
	if exists(marker) {
		t.Error("expired marker not swept once the lock was free")
	}
	if !exists(lock) {
		t.Error("recently held lock file was swept")
	}
}

func TestMaybeSweep_RateLimited(t *testing.T) {
	setupTestJevguardDir(t)
	first := sessionLockPath("a")
	writeAged(t, first, nil, ancient)
	MaybeSweep()
	if exists(first) {
		t.Fatal("first MaybeSweep did not sweep")
	}
	second := sessionLockPath("b")
	writeAged(t, second, nil, ancient)
	MaybeSweep()
	if !exists(second) {
		t.Fatal("MaybeSweep swept again within the interval")
	}
	stamp := filepath.Join(GetSessionsDir(), sweepStampName)
	ts := time.Now().Add(-2 * sweepInterval)
	if err := os.Chtimes(stamp, ts, ts); err != nil {
		t.Fatal(err)
	}
	MaybeSweep()
	if exists(second) {
		t.Fatal("MaybeSweep did not sweep after the interval")
	}
}

func TestSweep_BoundedPerRun(t *testing.T) {
	setupTestJevguardDir(t)
	old := sweepMaxSessions
	sweepMaxSessions = 2
	t.Cleanup(func() { sweepMaxSessions = old })
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		writeAged(t, sessionLockPath(id), nil, ancient)
	}
	if n := Sweep(); n != 2 {
		t.Fatalf("Sweep visited %d sessions, want 2", n)
	}
	for Sweep() > 0 {
	}
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		if exists(sessionLockPath(id)) {
			t.Errorf("lock %s never swept", id)
		}
	}
}

func TestMaybeSweep_NoSessionsDir(t *testing.T) {
	setupTestJevguardDir(t)
	MaybeSweep()
	if exists(GetSessionsDir()) {
		t.Fatal("MaybeSweep created the sessions directory")
	}
}

// A process that opened the lock file just before the sweep unlinked it, and
// locks it just after, must not use the orphaned file: it retries on the new
// file at the path, so a second process cannot lock the path concurrently.
func TestSessionLock_ReacquiresAfterUnlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot unlink an open file; covered by removeLockedFile")
	}
	setupTestJevguardDir(t)
	path := sessionLockPath("race")
	writeAged(t, path, nil, ancient)
	attempts := 0
	afterLockHook = func(p string) {
		attempts++
		if attempts == 1 {
			if err := os.Remove(p); err != nil {
				t.Errorf("unlink: %v", err)
			}
		}
	}
	t.Cleanup(func() { afterLockHook = nil })

	err := withSessionLock("race", func() error {
		if attempts != 2 {
			t.Fatalf("lock taken after %d attempts, want a retry after the unlink", attempts)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("lock path missing while held: %v", err)
		}
		// Another opener of the path must find it locked.
		f, err := os.OpenFile(path, os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if ok, err := tryLockFile(f); ok || err != nil {
			if ok {
				_ = unlockFile(f)
			}
			t.Fatalf("second opener locked the path while held (ok=%v, err=%v)", ok, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The sweep's own lock removal followed by a waiting writer: the writer ends
// up on a fresh lock file and its state is saved.
func TestSweep_WriterAfterLockRemoval(t *testing.T) {
	setupTestJevguardDir(t)
	path := sessionLockPath("w")
	writeAged(t, path, nil, ancient)
	Sweep()
	if exists(path) {
		t.Fatal("abandoned lock not swept")
	}
	if err := SaveSession(&SessionState{SessionID: "w", Prompt: "go on"}); err != nil {
		t.Fatal(err)
	}
	if !exists(path) {
		t.Fatal("writer did not recreate the lock file")
	}
	if s, err := LoadSession("w"); err != nil || s == nil || s.Prompt != "go on" {
		t.Fatalf("state = %+v, %v", s, err)
	}
}

func TestSessionLock_RefreshesIdleLockFile(t *testing.T) {
	setupTestJevguardDir(t)
	path := sessionLockPath("touch")
	writeAged(t, path, nil, ancient)
	if err := withSessionLock("touch", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(info.ModTime()) > time.Hour {
		t.Fatalf("lock file mtime not refreshed: %v", info.ModTime())
	}
}

// noWaitHarness makes a waiting acquisition retry for a long time and counts
// the sleeps between attempts.
func noWaitHarness(t *testing.T) *int {
	t.Helper()
	oldTimeout, oldSleep := lockTimeout, lockSleep
	sleeps := 0
	lockTimeout = time.Minute
	lockSleep = func(time.Duration) { sleeps++ }
	t.Cleanup(func() { lockTimeout, lockSleep = oldTimeout, oldSleep })
	return &sleeps
}

// With wait false, a transient open failure (a Windows lock file pending
// deletion reports access denied) skips the session at once.
func TestAcquireLock_NoWaitSkipsRetryableOpenError(t *testing.T) {
	setupTestJevguardDir(t)
	sleeps := noWaitHarness(t)
	errTransient := errors.New("access denied")
	oldOpen, oldRetryable := openLockFile, retryable
	t.Cleanup(func() { openLockFile, retryable = oldOpen, oldRetryable })
	retryable = func(err error) bool { return errors.Is(err, errTransient) }
	opens := 0
	openLockFile = func(string, int, os.FileMode) (*os.File, error) {
		opens++
		return nil, errTransient
	}
	begin := time.Now()
	l, err := acquireLock(sessionLockPath("pending"), false, false, nil)
	if l != nil || err != nil {
		t.Fatalf("acquireLock = %v, %v; want nil, nil", l, err)
	}
	if opens != 1 || *sleeps != 0 || time.Since(begin) > time.Second {
		t.Fatalf("no-wait acquisition retried: %d opens, %d sleeps, %v", opens, *sleeps, time.Since(begin))
	}
	// A waiting acquisition keeps retrying the same error.
	lockTimeout = 0
	if _, err := acquireLock(sessionLockPath("pending"), true, false, nil); !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("waiting acquisition = %v, want timeout", err)
	}
}

// With wait false, a failed verification (the path no longer names the
// locked file) skips the session at once and leaves the lock free.
func TestAcquireLock_NoWaitSkipsVerificationFailure(t *testing.T) {
	setupTestJevguardDir(t)
	sleeps := noWaitHarness(t)
	other := filepath.Join(t.TempDir(), "other")
	writeAged(t, other, nil, 0)
	oldStat := statLockPath
	t.Cleanup(func() { statLockPath = oldStat })
	stats := 0
	statLockPath = func(string) (os.FileInfo, error) {
		stats++
		return os.Stat(other)
	}
	path := sessionLockPath("moved")
	begin := time.Now()
	l, err := acquireLock(path, false, false, nil)
	if l != nil || err != nil {
		t.Fatalf("acquireLock = %v, %v; want nil, nil", l, err)
	}
	if stats != 1 || *sleeps != 0 || time.Since(begin) > time.Second {
		t.Fatalf("no-wait acquisition retried: %d verifications, %d sleeps", stats, *sleeps)
	}
	statLockPath = oldStat
	l, err = acquireLock(path, false, false, nil)
	if l == nil || err != nil {
		t.Fatalf("lock not free after a skipped acquisition: %v, %v", l, err)
	}
	l.release(false)
}

func countExisting(paths []string) int {
	n := 0
	for _, p := range paths {
		if exists(p) {
			n++
		}
	}
	return n
}

// One run inspects at most sweepMaxEntries entries; the persisted cursor lets
// later runs get past entries that are kept, until the backlog is gone.
func TestMaybeSweep_EntryBudgetResumesAcrossRuns(t *testing.T) {
	setupTestJevguardDir(t)
	oldEntries := sweepMaxEntries
	sweepMaxEntries = 4
	t.Cleanup(func() { sweepMaxEntries = oldEntries })
	var fresh, abandoned []string
	for i := 0; i < 5; i++ {
		p := sessionLockPath("fresh" + strconv.Itoa(i))
		writeAged(t, p, nil, hourAgo)
		fresh = append(fresh, p)
	}
	for i := 0; i < 10; i++ {
		p := sessionLockPath("old" + strconv.Itoa(i))
		writeAged(t, p, nil, ancient)
		abandoned = append(abandoned, p)
	}
	stamp := filepath.Join(GetSessionsDir(), sweepStampName)
	runs := 0
	for countExisting(abandoned) > 0 {
		if runs++; runs > 8 {
			t.Fatalf("backlog not cleared after %d runs, %d left", runs-1, countExisting(abandoned))
		}
		before := countExisting(abandoned)
		MaybeSweep()
		if removed := before - countExisting(abandoned); removed > sweepMaxEntries {
			t.Fatalf("run %d removed %d files, more than the %d-entry budget", runs, removed, sweepMaxEntries)
		}
		data, err := os.ReadFile(stamp)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := strconv.Atoi(strings.TrimSpace(string(data))); err != nil {
			t.Fatalf("stamp holds no cursor: %q", data)
		}
		ts := time.Now().Add(-2 * sweepInterval)
		if err := os.Chtimes(stamp, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	if runs < 3 {
		t.Fatalf("10 abandoned locks cleared in %d runs of 4 entries", runs)
	}
	if n := countExisting(fresh); n != len(fresh) {
		t.Fatalf("%d recently used lock files swept", len(fresh)-n)
	}
}

// A run stops at the deadline, keeps what it did not finish, and returns a
// cursor from which a later run completes the work.
func TestSweep_DeadlineStopsAndLaterRunContinues(t *testing.T) {
	setupTestJevguardDir(t)
	var locks []string
	for _, id := range []string{"a", "b", "c", "d"} {
		p := sessionLockPath(id)
		writeAged(t, p, nil, ancient)
		locks = append(locks, p)
	}
	// The clock passes the deadline while the second session is visited
	// under its lock (at its session file check): the first session is
	// finished, the second is cut short.
	var expired atomic.Bool
	checked := 0
	oldNow, oldLstat := sweepNow, sweepLstat
	sweepNow = func() time.Time {
		if expired.Load() {
			return time.Now().Add(time.Hour)
		}
		return time.Now()
	}
	sweepLstat = func(p string) (os.FileInfo, error) {
		if strings.HasSuffix(p, ".json") {
			if checked++; checked == 2 {
				expired.Store(true)
			}
		}
		return os.Lstat(p)
	}
	t.Cleanup(func() { sweepNow, sweepLstat = oldNow, oldLstat })

	visited, next := sweepFrom(0)
	if visited != 2 {
		t.Fatalf("first run visited %d sessions, want 2", visited)
	}
	if left := countExisting(locks); left != 3 {
		t.Fatalf("first run left %d of 4 lock files, want 3", left)
	}
	if next != 0 {
		t.Fatalf("cursor = %d, want 0 (the unfinished session is first after a removal)", next)
	}
	expired.Store(false)
	sweepLstat = oldLstat
	if _, next := sweepFrom(next); next != 0 {
		t.Fatalf("cursor after the complete listing = %d, want 0", next)
	}
	if left := countExisting(locks); left != 0 {
		t.Fatalf("later run left %d lock files", left)
	}
}

// A sweep cannot start the listing when its deadline has passed. It then
// does nothing and restarts the cursor rather than repeat the same skip.
func TestSweep_NoBudgetDoesNothing(t *testing.T) {
	setupTestJevguardDir(t)
	p := sessionLockPath("x")
	writeAged(t, p, nil, ancient)
	oldBudget := sweepBudget
	sweepBudget = 0
	t.Cleanup(func() { sweepBudget = oldBudget })
	if visited, next := sweepFrom(3); visited != 0 || next != 0 {
		t.Fatalf("sweepFrom = %d, %d; want 0, 0", visited, next)
	}
	if !exists(p) {
		t.Fatal("sweep without budget removed a file")
	}
}

// A session with more markers than sweepMaxMarkers is handled over several
// runs, and its lock file stays until every marker is gone.
func TestSweep_MarkersCappedPerSession(t *testing.T) {
	setupTestJevguardDir(t)
	oldMarkers := sweepMaxMarkers
	sweepMaxMarkers = 2
	t.Cleanup(func() { sweepMaxMarkers = oldMarkers })
	lock := sessionLockPath("many")
	writeAged(t, lock, nil, ancient)
	var markers []string
	for i := 0; i < 5; i++ {
		p := SessionFilePath("many") + ".taint.m" + strconv.Itoa(i)
		writeAged(t, p, nil, ancient)
		markers = append(markers, p)
	}
	Sweep()
	if left := countExisting(markers); left != 3 {
		t.Fatalf("first run left %d of 5 markers, want 3", left)
	}
	if !exists(lock) {
		t.Fatal("lock file swept while markers remain")
	}
	for i := 0; i < 3 && exists(lock); i++ {
		Sweep()
	}
	if countExisting(markers) != 0 || exists(lock) {
		t.Fatal("session not fully swept over later runs")
	}
}

// Concurrent hooks never sweep at the same time: one holding the
// coordination lock makes the others skip, even with a stale stamp.
func TestMaybeSweep_ConcurrentRunsOnce(t *testing.T) {
	setupTestJevguardDir(t)
	lock := sessionLockPath("abandoned")
	writeAged(t, lock, nil, ancient)
	var sweeps atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	sweepLockedHook = func() {
		if sweeps.Add(1) == 1 {
			close(entered)
			<-release
		}
	}
	t.Cleanup(func() { sweepLockedHook = nil })

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); MaybeSweep() }()
	<-entered
	// The stamp is still stale: only the coordination lock stops these.
	for i := 0; i < 3; i++ {
		MaybeSweep()
	}
	if n := sweeps.Load(); n != 1 {
		t.Fatalf("%d sweeps took the coordination lock concurrently", n)
	}
	close(release)
	wg.Wait()
	if exists(lock) {
		t.Fatal("the running sweep did not sweep")
	}
	MaybeSweep()
	if n := sweeps.Load(); n != 1 {
		t.Fatalf("a sweep ran again within the interval (%d)", n)
	}
	if !exists(filepath.Join(GetSessionsDir(), sweepStampName)) {
		t.Fatal("coordination file missing")
	}
}

// A cursor beyond a listing that has shrunk wraps to the start.
func TestSweep_CursorWrapsWhenListingShrank(t *testing.T) {
	setupTestJevguardDir(t)
	a, b := sessionLockPath("a"), sessionLockPath("b")
	writeAged(t, a, nil, ancient)
	writeAged(t, b, nil, ancient)
	if visited, next := sweepFrom(100); visited != 2 || next != 0 {
		t.Fatalf("sweepFrom(100) = %d, %d; want 2, 0", visited, next)
	}
	if exists(a) || exists(b) {
		t.Fatal("wrapped sweep left abandoned lock files")
	}
}

// listingClock simulates storage so slow that the listing deadline passes
// after limit names have been read in a run (the visiting deadline is still
// ahead). reset starts a new run.
func listingClock(t *testing.T, limit int) (reset func(), exhaustedBeforeCursor *int) {
	t.Helper()
	base := time.Now()
	read := 0
	exhausted := 0
	oldNow, oldRead := sweepNow, sweepReadNames
	sweepNow = func() time.Time {
		if read >= limit {
			return base.Add(sweepBudget * 3 / 4)
		}
		return base
	}
	sweepReadNames = func(f *os.File, n int) ([]string, error) {
		names, err := oldRead(f, n)
		read += len(names)
		return names, err
	}
	t.Cleanup(func() { sweepNow, sweepReadNames = oldNow, oldRead })
	return func() { read = 0 }, &exhausted
}

// A saved cursor the listing cannot reach within its deadline must not stall
// the sweep: the old design returned the unchanged cursor every run, so no
// later session was ever swept. Now an unreachable cursor restarts from the
// beginning, and the abandoned files are cleared within a bounded number of
// runs while the listing deadline keeps expiring.
func TestSweep_UnreachableCursorStillProgresses(t *testing.T) {
	setupTestJevguardDir(t)
	oldEntries, oldChunk := sweepMaxEntries, sweepReadChunk
	sweepMaxEntries, sweepReadChunk = 2, 1
	t.Cleanup(func() { sweepMaxEntries, sweepReadChunk = oldEntries, oldChunk })
	var fresh, abandoned []string
	for i := 0; i < 3; i++ {
		p := sessionLockPath("fresh" + strconv.Itoa(i))
		writeAged(t, p, nil, hourAgo)
		fresh = append(fresh, p)
	}
	for i := 0; i < 8; i++ {
		p := sessionLockPath("old" + strconv.Itoa(i))
		writeAged(t, p, nil, ancient)
		abandoned = append(abandoned, p)
	}
	// Six names per run: the listing never gets near cursor 40.
	reset, _ := listingClock(t, 6)

	next := 40
	for run := 1; countExisting(abandoned) > 0; run++ {
		if run > 30 {
			t.Fatalf("%d abandoned lock files left after 30 runs", countExisting(abandoned))
		}
		reset()
		prev := next
		_, next = sweepFrom(prev)
		if prev >= 6 && next == prev {
			t.Fatalf("run %d returned its unreachable cursor %d unchanged", run, prev)
		}
		if run == 1 && next != 0 {
			t.Fatalf("unreachable cursor 40 led to cursor %d, want a restart at 0", next)
		}
	}
	if n := countExisting(fresh); n != len(fresh) {
		t.Fatalf("%d recently used lock files swept", len(fresh)-n)
	}
}

// sortedListing makes the sweep read directory names in sorted order, so a
// test can place entries at known listing positions.
func sortedListing(t *testing.T) {
	t.Helper()
	oldRead := sweepReadNames
	pending := map[*os.File][]string{}
	sweepReadNames = func(f *os.File, n int) ([]string, error) {
		rest, ok := pending[f]
		if !ok {
			all, err := oldRead(f, -1)
			if err != nil {
				return nil, err
			}
			sort.Strings(all)
			rest = all
		}
		if len(rest) == 0 {
			delete(pending, f)
			return nil, io.EOF
		}
		if n <= 0 || n > len(rest) {
			n = len(rest)
		}
		pending[f] = rest[n:]
		return rest[:n], nil
	}
	t.Cleanup(func() { sweepReadNames = oldRead })
}

// A run that reaches its cursor with time left must inspect the entry there
// before reading further names. Otherwise a fresh (undeletable) prefix can
// make the cursor cycle: with a window of 2, one name per read, and the
// listing deadline spent after six names, cursors went 0 -> 2 -> 4 -> 0
// forever, because the run at cursor 4 read entries 4 and 5 before
// inspecting either, although entry 4 could be inspected after five names.
func TestSweep_CursorEntryInspectedBeforeReadingFurther(t *testing.T) {
	setupTestJevguardDir(t)
	oldEntries, oldChunk := sweepMaxEntries, sweepReadChunk
	sweepMaxEntries, sweepReadChunk = 2, 1
	t.Cleanup(func() { sweepMaxEntries, sweepReadChunk = oldEntries, oldChunk })
	var fresh []string
	for _, id := range []string{"s0", "s1", "s2", "s3", "s5"} {
		p := sessionLockPath(id)
		writeAged(t, p, nil, hourAgo)
		fresh = append(fresh, p)
	}
	abandoned := sessionLockPath("s4")
	writeAged(t, abandoned, nil, ancient)
	sortedListing(t)
	reset, _ := listingClock(t, 6)

	next := 0
	for run := 1; exists(abandoned); run++ {
		if run > 6 {
			t.Fatalf("abandoned lock file at listing position 4 left after 6 runs (cursor %d)", next)
		}
		reset()
		_, next = sweepFrom(next)
	}
	if n := countExisting(fresh); n != len(fresh) {
		t.Fatalf("%d recently used lock files swept", len(fresh)-n)
	}
}

// A run that falls back from an unreachable cursor still processes the names
// it read at the start of the listing when time allows (here the name budget,
// not the deadline, stops the skip).
func TestSweep_NameBudgetFallsBackToStart(t *testing.T) {
	setupTestJevguardDir(t)
	oldNames := sweepMaxNames
	sweepMaxNames = 4
	t.Cleanup(func() { sweepMaxNames = oldNames })
	var locks []string
	for _, id := range []string{"a", "b", "c"} {
		p := sessionLockPath(id)
		writeAged(t, p, nil, ancient)
		locks = append(locks, p)
	}
	if visited, _ := sweepFrom(100); visited != 3 {
		t.Fatalf("fallback run visited %d sessions, want 3", visited)
	}
	if n := countExisting(locks); n != 0 {
		t.Fatalf("%d abandoned lock files left", n)
	}
}

// countVisitCalls counts the filesystem calls the sweep makes on sessions
// after its listing, through their seams: opening and verifying lock files,
// lstat, open, and remove. The listing's own lstats are not counted: they are
// bounded by the window, not by sweepMaxOps.
func countVisitCalls(t *testing.T) *int {
	t.Helper()
	calls, visiting := 0, false
	count := func() {
		if visiting {
			calls++
		}
	}
	oldOpenLock, oldStatLock := openLockFile, statLockPath
	oldLstat, oldOpen, oldRemove := sweepLstat, sweepOpen, sweepRemove
	openLockFile = func(p string, flag int, perm os.FileMode) (*os.File, error) {
		visiting = true // the first lock acquisition ends the listing
		count()
		return oldOpenLock(p, flag, perm)
	}
	statLockPath = func(p string) (os.FileInfo, error) { count(); return oldStatLock(p) }
	sweepLstat = func(p string) (os.FileInfo, error) { count(); return oldLstat(p) }
	sweepOpen = func(p string) (*os.File, error) {
		if p == GetSessionsDir() {
			visiting = false // a new run lists the directory
		}
		count()
		return oldOpen(p)
	}
	sweepRemove = func(p string) error { count(); return oldRemove(p) }
	t.Cleanup(func() {
		openLockFile, statLockPath = oldOpenLock, oldStatLock
		sweepLstat, sweepOpen, sweepRemove = oldLstat, oldOpen, oldRemove
	})
	return &calls
}

// Many expired markers across sessions cannot push a run past its operation
// cap: every lstat and remove is charged, not one token per marker. Later
// runs finish the work.
func TestSweep_OpCapCountsEveryCall(t *testing.T) {
	setupTestJevguardDir(t)
	const opCap = 25
	oldOps := sweepMaxOps
	sweepMaxOps = opCap
	t.Cleanup(func() { sweepMaxOps = oldOps })
	var all []string
	for s := 0; s < 4; s++ {
		id := "m" + strconv.Itoa(s)
		writeAged(t, sessionLockPath(id), nil, ancient)
		all = append(all, sessionLockPath(id))
		for i := 0; i < 6; i++ {
			p := SessionFilePath(id) + ".taint.x" + strconv.Itoa(i)
			writeAged(t, p, nil, ancient)
			all = append(all, p)
		}
	}
	calls := countVisitCalls(t)
	_, next := sweepFrom(0)
	if *calls > opCap {
		t.Fatalf("visiting made %d filesystem calls, cap %d", *calls, opCap)
	}
	if *calls < opCap-5 {
		t.Fatalf("visiting made only %d calls; the test should exhaust the cap of %d", *calls, opCap)
	}
	if countExisting(all) == 0 {
		t.Fatal("one run removed everything; the cap was not reached")
	}
	for run := 0; run < 20 && countExisting(all) > 0; run++ {
		*calls = 0
		_, next = sweepFrom(next)
		if *calls > opCap {
			t.Fatalf("later run made %d filesystem calls, cap %d", *calls, opCap)
		}
	}
	if n := countExisting(all); n != 0 {
		t.Fatalf("%d files left after later runs", n)
	}
}

// A stale session file larger than the read cap is kept and never read in
// full: not opened when its size is known, and cut off at the cap when it
// grew after the size check.
func TestSweep_OversizedSessionFileKept(t *testing.T) {
	setupTestJevguardDir(t)
	data, _ := json.Marshal(SessionState{SessionID: "big", Prompt: strings.Repeat("p", 200), UpdatedAt: time.Now().Add(-ancient)})
	path := SessionFilePath("big")
	writeAged(t, path, data, ancient)
	writeAged(t, sessionLockPath("big"), nil, ancient)
	oldCap, oldOpen, oldLstat := sweepMaxSessionFile, sweepOpen, sweepLstat
	sweepMaxSessionFile = 64
	t.Cleanup(func() { sweepMaxSessionFile, sweepOpen, sweepLstat = oldCap, oldOpen, oldLstat })
	opens := 0
	sweepOpen = func(p string) (*os.File, error) {
		if p == path {
			opens++
		}
		return oldOpen(p)
	}

	Sweep()
	if !exists(path) || !exists(sessionLockPath("big")) {
		t.Fatal("oversized session file or its lock was swept")
	}
	if opens != 0 {
		t.Fatalf("oversized session file opened %d times", opens)
	}

	// The lstat reports a small file (it grew afterwards): the read stops at
	// the cap, so the file, which would be reaped if read whole, is kept.
	sweepLstat = func(p string) (os.FileInfo, error) {
		info, err := oldLstat(p)
		if err == nil && p == path {
			return smallInfo{info}, nil
		}
		return info, err
	}
	Sweep()
	if opens != 1 {
		t.Fatalf("session file opened %d times, want 1", opens)
	}
	if !exists(path) {
		t.Fatal("session file larger than the read cap was swept")
	}
	sweepMaxSessionFile = oldCap
	Sweep()
	if exists(path) {
		t.Fatal("stale session file within the cap was not swept")
	}
}

type smallInfo struct{ os.FileInfo }

func (smallInfo) Size() int64 { return 10 }
