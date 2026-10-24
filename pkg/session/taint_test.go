package session

import (
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
	entries, _ := os.ReadDir(GetSessionsDir())
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".lock") {
			t.Errorf("lock file left behind: %s", e.Name())
		}
	}
}

func TestSessionLock_BreaksStaleLockAndTimesOut(t *testing.T) {
	setupTestJevguardDir(t)
	if err := os.MkdirAll(GetSessionsDir(), 0700); err != nil {
		t.Fatal(err)
	}
	lock := sessionLockPath("s1")
	if err := os.WriteFile(lock, nil, 0600); err != nil {
		t.Fatal(err)
	}

	oldTimeout, oldStale := lockTimeout, lockStaleAfter
	t.Cleanup(func() { lockTimeout, lockStaleAfter = oldTimeout, oldStale })

	lockTimeout, lockStaleAfter = 30*time.Millisecond, time.Hour
	if err := MarkTainted("s1", "WebFetch", time.Now()); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected lock timeout, got %v", err)
	}

	past := time.Now().Add(-time.Minute)
	if err := os.Chtimes(lock, past, past); err != nil {
		t.Fatal(err)
	}
	lockStaleAfter = time.Second
	if err := MarkTainted("s1", "WebFetch", time.Now()); err != nil {
		t.Fatalf("stale lock should be broken: %v", err)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatalf("lock should be released, stat err = %v", err)
	}
}
