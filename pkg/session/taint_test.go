package session

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMarkTainted_PreservesPromptAndAbort(t *testing.T) {
	setupTestJevguardDir(t)
	at := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

	if err := SaveSession(&SessionState{SessionID: "s1", TurnID: 3, Prompt: "fetch the docs"}); err != nil {
		t.Fatal(err)
	}
	if err := MarkTainted("s1", "WebFetch", at); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSession("s1")
	if err != nil || got == nil {
		t.Fatalf("LoadSession = %+v, %v", got, err)
	}
	if !got.Tainted || got.TaintSource == nil || got.TaintSource.ToolName != "WebFetch" || !got.TaintSource.At.Equal(at) {
		t.Fatalf("taint not recorded: %+v", got)
	}
	if got.Prompt != "fetch the docs" || got.TurnID != 3 {
		t.Fatalf("taint changed prompt state: %+v", got)
	}

	if err := SaveSession(&SessionState{SessionID: "s2", Prompt: "stop"}); err != nil {
		t.Fatal(err)
	}
	if err := MarkTainted("s2", "mcp__srv__read", at); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadSession("s2"); got == nil || !got.Aborted || !got.Tainted {
		t.Fatalf("taint must keep the abort flag: %+v", got)
	}
}

func TestMarkTainted_CreatesMissingSession(t *testing.T) {
	setupTestJevguardDir(t)
	if err := MarkTainted("", "WebSearch", time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSession("default")
	if err != nil || got == nil || !got.Tainted || got.Prompt != "" || got.Aborted {
		t.Fatalf("LoadSession(default) = %+v, %v", got, err)
	}
}

func TestMarkTainted_LeavesUnreadableSessionUntouched(t *testing.T) {
	setupTestJevguardDir(t)
	if err := os.MkdirAll(GetSessionsDir(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(SessionFilePath("s1"), []byte("{corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := MarkTainted("s1", "WebFetch", time.Now()); err == nil {
		t.Fatal("expected an error for an unreadable session")
	}
	data, _ := os.ReadFile(SessionFilePath("s1"))
	if string(data) != "{corrupt" {
		t.Fatalf("unreadable session was overwritten: %q", data)
	}
}

func TestEndTurn_ClearsTaintKeepsAbort(t *testing.T) {
	setupTestJevguardDir(t)
	if err := SaveSession(&SessionState{SessionID: "s1", Prompt: "read the page"}); err != nil {
		t.Fatal(err)
	}
	if err := MarkTainted("s1", "WebFetch", time.Now()); err != nil {
		t.Fatal(err)
	}
	aborted, err := EndTurn("s1")
	if err != nil || aborted {
		t.Fatalf("EndTurn = %t, %v", aborted, err)
	}
	if got, _ := LoadSession("s1"); got != nil {
		t.Fatalf("session should be cleared, got %+v", got)
	}

	if err := SaveSession(&SessionState{SessionID: "s2", Prompt: "stop"}); err != nil {
		t.Fatal(err)
	}
	if aborted, err := EndTurn("s2"); err != nil || !aborted {
		t.Fatalf("EndTurn on aborted session = %t, %v", aborted, err)
	}
	if got, _ := LoadSession("s2"); got == nil || !got.Aborted {
		t.Fatalf("abort flag must survive end-turn, got %+v", got)
	}
}

func TestIngestReplacesTaint(t *testing.T) {
	setupTestJevguardDir(t)
	if err := MarkTainted("s1", "WebFetch", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := SaveSession(&SessionState{SessionID: "s1", Prompt: "next prompt"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadSession("s1"); got == nil || got.Tainted || got.TaintSource != nil {
		t.Fatalf("a new prompt must clear the taint, got %+v", got)
	}
}

// Parallel taint writers (tool calls, subagents) racing an ingested abort
// must never un-abort the session or lose the abort's write.
func TestMarkTainted_ConcurrentWithAbortNeverClearsAbort(t *testing.T) {
	setupTestJevguardDir(t)
	for round := 0; round < 20; round++ {
		id := fmt.Sprintf("race-%d", round)
		if err := SaveSession(&SessionState{SessionID: id, Prompt: "fetch it"}); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, 9)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- MarkTainted(id, "WebFetch", time.Now())
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- SaveSession(&SessionState{SessionID: id, Prompt: "stop"})
		}()
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := LoadSession(id)
		if err != nil || got == nil || !got.Aborted {
			t.Fatalf("round %d: abort lost: %+v, %v", round, got, err)
		}
	}
}

// shortLockTimeout shortens lock acquisition for one test.
func shortLockTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := lockTimeout
	lockTimeout = d
	t.Cleanup(func() { lockTimeout = old })
}

// holdLock acquires the session lock in a goroutine, runs during under it,
// and keeps the lock until the returned release function is called. It
// returns after during has finished.
func holdLock(t *testing.T, sessionID string, during func()) (release func()) {
	t.Helper()
	held, done, finished := make(chan struct{}), make(chan struct{}), make(chan error)
	go func() {
		finished <- withSessionLock(sessionID, func() error {
			if during != nil {
				during()
			}
			close(held)
			<-done
			return nil
		})
	}()
	<-held
	return func() {
		close(done)
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
	}
}

func TestSessionLock_LiveHolderIsNeverStolen(t *testing.T) {
	setupTestJevguardDir(t)
	shortLockTimeout(t, 30*time.Millisecond)
	release := holdLock(t, "s1", nil)
	// An old mtime used to mark the lock stale; the OS lock ignores it.
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(sessionLockPath("s1"), past, past); err != nil {
		t.Fatal(err)
	}
	err := mergeTaint("s1", TaintSource{ToolName: "WebFetch"}, "")
	if !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("expected a lock timeout while the holder is alive, got %v", err)
	}
	release()
	if err := mergeTaint("s1", TaintSource{ToolName: "WebFetch"}, ""); err != nil {
		t.Fatalf("lock should be free after release: %v", err)
	}
}

// A process that exits without unlocking (a crash) releases its lock: the OS
// drops locks held by a closed descriptor.
func TestSessionLock_ReleasedWhenHolderDescriptorCloses(t *testing.T) {
	setupTestJevguardDir(t)
	if err := os.MkdirAll(GetSessionsDir(), 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(sessionLockPath("s1"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := tryLockFile(f); !ok || err != nil {
		t.Fatalf("tryLockFile = %t, %v", ok, err)
	}
	_ = f.Close()
	shortLockTimeout(t, 30*time.Millisecond)
	if err := MarkTainted("s1", "WebFetch", time.Now()); err != nil {
		t.Fatalf("lock of a closed descriptor must not block: %v", err)
	}
}

// Review R3: a slow writer holding the lock can no longer have it stolen and
// then overwrite an abort ingested meanwhile. The abort waits for the lock,
// and if it times out the abort marker still holds the session.
func TestSessionLock_SlowWriterCannotUnabort(t *testing.T) {
	setupTestJevguardDir(t)
	if err := SaveSession(&SessionState{SessionID: "s1", Prompt: "work"}); err != nil {
		t.Fatal(err)
	}
	shortLockTimeout(t, 30*time.Millisecond)
	var cached *SessionState
	release := holdLock(t, "s1", func() { cached, _, _ = readSession("s1") })
	if err := SaveSession(&SessionState{SessionID: "s1", Prompt: "stop"}); err == nil || !strings.Contains(err.Error(), "abort recorded in marker") {
		t.Fatalf("expected the abort to fall back to its marker, got %v", err)
	}
	// The slow writer resumes and writes its stale positive state.
	cached.Tainted = true
	if err := saveSessionLocked(cached); err != nil {
		t.Fatal(err)
	}
	release()
	got, err := LoadSession("s1")
	if err != nil || got == nil || !got.Aborted || got.Prompt != "" {
		t.Fatalf("abort must survive the slow writer: %+v, %v", got, err)
	}
	if aborted, err := EndTurn("s1"); err != nil || !aborted {
		t.Fatalf("end-turn must keep a marker abort: %t, %v", aborted, err)
	}
	if err := SaveSession(&SessionState{SessionID: "s1", Prompt: "carry on"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadSession("s1"); got == nil || got.Aborted || got.Prompt != "carry on" {
		t.Fatalf("a new prompt must clear the abort marker: %+v", got)
	}
}

// Review R5: an obstruction at the lock path returns promptly instead of
// spinning past the deadline.
func TestSessionLock_UnusableLockPathReturnsPromptly(t *testing.T) {
	setupTestJevguardDir(t)
	if err := os.MkdirAll(sessionLockPath("s1"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sessionLockPath("s1")+"/child", nil, 0600); err != nil {
		t.Fatal(err)
	}
	shortLockTimeout(t, 20*time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- mergeTaint("s1", TaintSource{ToolName: "WebFetch"}, "") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error for a directory at the lock path")
		}
	case <-time.After(time.Second):
		t.Fatal("lock acquisition ignored its deadline")
	}
}

// Review R1: a lock timeout keeps the taint through the marker.
func TestMarkTainted_LockTimeoutKeepsTaintMarker(t *testing.T) {
	setupTestJevguardDir(t)
	if err := SaveSession(&SessionState{SessionID: "s1", Prompt: "fetch docs"}); err != nil {
		t.Fatal(err)
	}
	shortLockTimeout(t, 20*time.Millisecond)
	release := holdLock(t, "s1", nil)
	err := MarkTainted("s1", "WebFetch", time.Now())
	release()
	if err == nil || errors.Is(err, ErrTaintNotRecorded) || !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("expected a lock timeout with the marker kept, got %v", err)
	}
	got, err := LoadSession("s1")
	if err != nil || got == nil || !got.Tainted || got.TaintSource == nil || got.TaintSource.ToolName != "WebFetch" || got.Prompt != "fetch docs" {
		t.Fatalf("marker taint not applied: %+v, %v", got, err)
	}
	if aborted, err := EndTurn("s1"); err != nil || aborted {
		t.Fatalf("EndTurn = %t, %v", aborted, err)
	}
	if got, _ := LoadSession("s1"); got != nil {
		t.Fatalf("end-turn must clear the taint marker, got %+v", got)
	}
}

// Review R1: a failed state write keeps the taint through the marker, and an
// undecodable marker still taints.
func TestMarkTainted_WriteFailureKeepsTaintMarker(t *testing.T) {
	setupTestJevguardDir(t)
	if err := SaveSession(&SessionState{SessionID: "s1", Prompt: "fetch docs"}); err != nil {
		t.Fatal(err)
	}
	oldRename := renameFunc
	renameFunc = func(string, string) error { return os.ErrPermission }
	err := MarkTainted("s1", "mcp__srv__read", time.Now())
	renameFunc = oldRename
	if err == nil || errors.Is(err, ErrTaintNotRecorded) {
		t.Fatalf("expected a state write failure with the marker kept, got %v", err)
	}
	if got, _ := LoadSession("s1"); got == nil || !got.Tainted || got.TaintSource.ToolName != "mcp__srv__read" {
		t.Fatalf("marker taint not applied: %+v", got)
	}

	if err := os.WriteFile(taintMarkerPath("s2"), []byte("{trunc"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadSession("s2"); err != nil || got == nil || !got.Tainted || got.TaintSource.ToolName != "unknown tool" {
		t.Fatalf("an undecodable marker must still taint: %+v, %v", got, err)
	}
	if err := SaveSession(&SessionState{SessionID: "s2", Prompt: "next"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadSession("s2"); got == nil || got.Tainted {
		t.Fatalf("a new prompt must clear the taint marker: %+v", got)
	}
}

func TestMarkTainted_BothWritesFailReportsNotRecorded(t *testing.T) {
	setupTestJevguardDir(t)
	oldWrite := writeMarkerFunc
	writeMarkerFunc = func(string, interface{}) error { return os.ErrPermission }
	t.Cleanup(func() { writeMarkerFunc = oldWrite })
	shortLockTimeout(t, 20*time.Millisecond)
	release := holdLock(t, "s1", nil)
	err := MarkTainted("s1", "WebFetch", time.Now())
	release()
	if !errors.Is(err, ErrTaintNotRecorded) {
		t.Fatalf("expected ErrTaintNotRecorded, got %v", err)
	}
}

func TestLoadSession_ExpiredMarkersAreIgnored(t *testing.T) {
	setupTestJevguardDir(t)
	if err := MarkTainted("s1", "WebFetch", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ClearSession("s1"); err != nil {
		t.Fatal(err)
	}
	taintPath, abortPath := taintMarkerPath("s1"), abortMarkerPath("s1")
	if err := writeMarker(taintPath, markerRecord{ToolName: "WebFetch"}); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(abortPath, markerRecord{}); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * SessionTTL())
	for _, p := range []string{taintPath, abortPath} {
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := LoadSession("s1"); err != nil || got != nil {
		t.Fatalf("expired markers must be ignored: %+v, %v", got, err)
	}
}

// pauseAfterRename runs during once, right after the next session file rename
// commits, before the writer that renamed continues.
func pauseAfterRename(t *testing.T, during func()) {
	t.Helper()
	oldRename := renameFunc
	t.Cleanup(func() { renameFunc = oldRename })
	done := false
	renameFunc = func(src, dst string) error {
		if err := os.Rename(src, dst); err != nil {
			return err
		}
		if !done {
			done = true
			during()
		}
		return nil
	}
}

// Review S1: a taint or abort published while an older ingest holds the lock
// (and times out into its marker) survives that ingest's marker clearing.
func TestSaveSession_OlderIngestKeepsNewerMarker(t *testing.T) {
	for _, signal := range []string{"taint", "abort"} {
		t.Run(signal, func(t *testing.T) {
			setupTestJevguardDir(t)
			shortLockTimeout(t, 20*time.Millisecond)
			if err := SaveSession(&SessionState{SessionID: "s", Prompt: "old"}); err != nil {
				t.Fatal(err)
			}
			var fallbackErr error
			pauseAfterRename(t, func() {
				if signal == "abort" {
					fallbackErr = SaveSession(&SessionState{SessionID: "s", Prompt: "stop"})
				} else {
					fallbackErr = MarkTainted("s", "WebFetch", time.Now())
				}
			})
			if err := SaveSession(&SessionState{SessionID: "s", Prompt: "new positive prompt"}); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(fallbackErr, ErrLockTimeout) {
				t.Fatalf("expected the competing writer to time out into its marker: %v", fallbackErr)
			}
			got, err := LoadSession("s")
			if err != nil || got == nil {
				t.Fatalf("LoadSession = %+v, %v", got, err)
			}
			if signal == "taint" && (!got.Tainted || got.Prompt != "new positive prompt") {
				t.Fatalf("newer taint lost: %+v", got)
			}
			if signal == "abort" && (!got.Aborted || got.Prompt != "") {
				t.Fatalf("newer abort lost: %+v", got)
			}
			// The next ingest retires the marker it observes.
			if err := SaveSession(&SessionState{SessionID: "s", Prompt: "after"}); err != nil {
				t.Fatal(err)
			}
			if got, _ := LoadSession("s"); got == nil || got.Tainted || got.Aborted || got.Prompt != "after" {
				t.Fatalf("a later prompt must retire the marker: %+v", got)
			}
		})
	}
}

// Review S1: end-turn removes only the markers it listed, so a taint
// published after its listing survives.
func TestEndTurn_KeepsMarkerPublishedAfterListing(t *testing.T) {
	setupTestJevguardDir(t)
	if err := SaveSession(&SessionState{SessionID: "s", Prompt: "work"}); err != nil {
		t.Fatal(err)
	}
	markers, err := markersFor("s")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(taintMarkerPath("s"), markerRecord{SessionID: "s", ToolName: "WebSearch"}); err != nil {
		t.Fatal(err)
	}
	if err := withSessionLock("s", func() error { return removeSessionFile("s", markers) }); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadSession("s"); got == nil || !got.Tainted || got.TaintSource.ToolName != "WebSearch" {
		t.Fatalf("taint published after the listing was removed: %+v", got)
	}
}

// Review S3: a taint merge delayed past the next prompt does not re-taint it,
// and one delayed past end-turn does not recreate the session.
func TestMarkTainted_RetiredEventDoesNotMergeLater(t *testing.T) {
	for _, transition := range []string{"next prompt", "end-turn"} {
		t.Run(transition, func(t *testing.T) {
			setupTestJevguardDir(t)
			if err := SaveSession(&SessionState{SessionID: "s", Prompt: "first"}); err != nil {
				t.Fatal(err)
			}
			orig := writeMarkerFunc
			t.Cleanup(func() { writeMarkerFunc = orig })
			writeMarkerFunc = func(p string, v interface{}) error {
				if err := orig(p, v); err != nil {
					return err
				}
				if transition == "end-turn" {
					_, err := EndTurn("s")
					return err
				}
				return SaveSession(&SessionState{SessionID: "s", Prompt: "next prompt"})
			}
			if err := MarkTainted("s", "WebFetch", time.Now()); err != nil {
				t.Fatal(err)
			}
			got, err := LoadSession("s")
			if err != nil {
				t.Fatal(err)
			}
			if transition == "end-turn" && got != nil {
				t.Fatalf("a retired taint recreated the ended session: %+v", got)
			}
			if transition == "next prompt" && (got == nil || got.Tainted || got.Prompt != "next prompt") {
				t.Fatalf("a retired taint re-tainted the next prompt: %+v", got)
			}
		})
	}
}

// A successful merge moves the taint into the session file and removes its
// marker; an unwritable marker still merges (fail closed).
func TestMarkTainted_MergeConsumesOwnMarker(t *testing.T) {
	setupTestJevguardDir(t)
	if err := MarkTainted("s", "WebFetch", time.Now()); err != nil {
		t.Fatal(err)
	}
	if m, err := markersFor("s"); err != nil || len(m.Paths) != 0 {
		t.Fatalf("merged marker left behind: %+v, %v", m, err)
	}
	if got, _ := LoadSession("s"); got == nil || !got.Tainted {
		t.Fatalf("taint not merged: %+v", got)
	}

	orig := writeMarkerFunc
	t.Cleanup(func() { writeMarkerFunc = orig })
	writeMarkerFunc = func(string, interface{}) error { return os.ErrPermission }
	if err := MarkTainted("s2", "WebFetch", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadSession("s2"); got == nil || !got.Tainted {
		t.Fatalf("merge without a marker must still taint: %+v", got)
	}
}

// Review S4: status folds markers like the gate, for marker-only sessions
// (including hashed session IDs) and for markers over an existing session.
func TestScanSessions_FoldsMarkers(t *testing.T) {
	setupTestJevguardDir(t)
	shortLockTimeout(t, 20*time.Millisecond)
	hashed := "session with spaces"
	for _, id := range []string{"marker-only", hashed} {
		release := holdLock(t, id, nil)
		err := MarkTainted(id, "WebFetch", time.Now())
		release()
		if !errors.Is(err, ErrLockTimeout) {
			t.Fatalf("expected a lock timeout: %v", err)
		}
	}
	if err := SaveSession(&SessionState{SessionID: "positive", Prompt: "do work"}); err != nil {
		t.Fatal(err)
	}
	release := holdLock(t, "positive", nil)
	err := SaveSession(&SessionState{SessionID: "positive", Prompt: "stop"})
	release()
	if !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("expected a lock timeout: %v", err)
	}

	listed, err := ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*SessionState{}
	for _, s := range listed {
		byID[s.SessionID] = s
	}
	for _, id := range []string{"marker-only", hashed, "positive"} {
		loaded, err := LoadSession(id)
		if err != nil {
			t.Fatal(err)
		}
		got := byID[id]
		if got == nil || got.Tainted != loaded.Tainted || got.Aborted != loaded.Aborted || got.Prompt != loaded.Prompt {
			t.Fatalf("%s: status %+v differs from gate %+v", id, got, loaded)
		}
	}
	if !byID["marker-only"].Tainted || !byID["positive"].Aborted {
		t.Fatalf("marker state missing from status: %+v", byID)
	}
}

// publishTaintMarker writes a taint marker for sessionID as MarkTainted does
// before its merge, and returns it with its source.
func publishTaintMarker(t *testing.T, sessionID string) (string, TaintSource) {
	t.Helper()
	marker := taintMarkerPath(sessionID)
	src := TaintSource{ToolName: "WebFetch", At: time.Now().UTC()}
	if err := writeMarker(marker, markerRecord{SessionID: sessionID, ToolName: src.ToolName, At: src.At}); err != nil {
		t.Fatal(err)
	}
	return marker, src
}

// T1 (review round 3): a merge that commits the taint to the session file and
// removes its marker while a reader is in progress must not hide the taint
// from that reader, whichever read it falls between.
func TestLoadSession_TaintHandoffDuringRead(t *testing.T) {
	t.Run("merge right after the session file read", func(t *testing.T) {
		setupTestJevguardDir(t)
		if err := SaveSession(&SessionState{SessionID: "s", Prompt: "active prompt"}); err != nil {
			t.Fatal(err)
		}
		marker, src := publishTaintMarker(t, "s")
		orig := readFileFunc
		defer func() { readFileFunc = orig }()
		readFileFunc = func(p string) ([]byte, error) {
			data, err := os.ReadFile(p)
			if p == SessionFilePath("s") {
				readFileFunc = orig
				if mergeErr := mergeTaint("s", src, marker); mergeErr != nil {
					t.Fatal(mergeErr)
				}
			}
			return data, err
		}
		got, err := LoadSession("s")
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || !got.Tainted || got.Prompt != "active prompt" {
			t.Fatalf("gate missed the taint handed off during its read: %+v", got)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("merge did not consume its marker: %v", err)
		}
	})

	t.Run("merge between marker listing and marker read", func(t *testing.T) {
		setupTestJevguardDir(t)
		if err := SaveSession(&SessionState{SessionID: "s", Prompt: "active prompt"}); err != nil {
			t.Fatal(err)
		}
		marker, src := publishTaintMarker(t, "s")
		orig := statMarkerFunc
		defer func() { statMarkerFunc = orig }()
		statMarkerFunc = func(p string) (os.FileInfo, error) {
			if p == marker {
				statMarkerFunc = orig
				if err := mergeTaint("s", src, marker); err != nil {
					t.Fatal(err)
				}
			}
			return orig(p)
		}
		got, err := LoadSession("s")
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || !got.Tainted || got.TaintSource == nil || got.TaintSource.ToolName != "WebFetch" {
			t.Fatalf("gate missed the taint handed off during its read: %+v", got)
		}
	})

	t.Run("status of a marker-only session merged during the scan", func(t *testing.T) {
		setupTestJevguardDir(t)
		marker, src := publishTaintMarker(t, "s")
		orig := statMarkerFunc
		defer func() { statMarkerFunc = orig }()
		statMarkerFunc = func(p string) (os.FileInfo, error) {
			if p == marker {
				statMarkerFunc = orig
				if err := mergeTaint("s", src, marker); err != nil {
					t.Fatal(err)
				}
			}
			return orig(p)
		}
		scan, err := ScanSessions()
		if err != nil {
			t.Fatal(err)
		}
		if len(scan.Active) != 1 || !scan.Active[0].Tainted || scan.Active[0].SessionID != "s" {
			t.Fatalf("status missed the taint handed off during its scan: %+v", scan.Active)
		}
	})
}
