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

// holdLock acquires the session lock in a goroutine and keeps it until the
// returned release function is called.
func holdLock(t *testing.T, sessionID string, during func()) (release func()) {
	t.Helper()
	held, done, finished := make(chan struct{}), make(chan struct{}), make(chan error)
	go func() {
		finished <- withSessionLock(sessionID, func() error {
			close(held)
			if during != nil {
				during()
			}
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
	err := mergeTaint("s1", TaintSource{ToolName: "WebFetch"})
	if !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("expected a lock timeout while the holder is alive, got %v", err)
	}
	release()
	if err := mergeTaint("s1", TaintSource{ToolName: "WebFetch"}); err != nil {
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
	go func() { done <- mergeTaint("s1", TaintSource{ToolName: "WebFetch"}) }()
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
	if err := writeMarker(taintMarkerPath("s1"), TaintSource{ToolName: "WebFetch"}); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(abortMarkerPath("s1"), struct{}{}); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * SessionTTL())
	for _, p := range []string{taintMarkerPath("s1"), abortMarkerPath("s1")} {
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := LoadSession("s1"); err != nil || got != nil {
		t.Fatalf("expired markers must be ignored: %+v, %v", got, err)
	}
}
