package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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
