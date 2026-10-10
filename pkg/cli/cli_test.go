package cli

import (
	"bytes"
	"strings"
	"testing"

	"jev-guard/pkg/session"
)

func TestEvaluateArgs_Version(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"DoubleDash", []string{"--version"}},
		{"SingleDash", []string{"-v"}},
		{"SingleDashLong", []string{"-version"}},
		{"CommandName", []string{"version"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			runner := NewRunner(&stdout, &stderr, func() bool { return true })

			action, code := runner.EvaluateArgs(tt.args)
			if action != ActionHandled {
				t.Fatalf("expected ActionHandled, got %v", action)
			}
			if code != 0 {
				t.Fatalf("expected exit code 0, got %d", code)
			}
			if !strings.Contains(stdout.String(), "jev-guard version") {
				t.Fatalf("expected output to contain 'jev-guard version', got %q", stdout.String())
			}
		})
	}
}

func TestEvaluateArgs_Help(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"DoubleDash", []string{"--help"}},
		{"SingleDash", []string{"-h"}},
		{"SingleDashLong", []string{"-help"}},
		{"CommandName", []string{"help"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			runner := NewRunner(&stdout, &stderr, func() bool { return false })

			action, code := runner.EvaluateArgs(tt.args)
			if action != ActionHandled {
				t.Fatalf("expected ActionHandled, got %v", action)
			}
			if code != 0 {
				t.Fatalf("expected exit code 0, got %d", code)
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("expected output to contain 'Usage:', got %q", stdout.String())
			}
		})
	}
}

func TestEvaluateArgs_UnknownArg(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })

	action, code := runner.EvaluateArgs([]string{"--invalid-flag"})
	if action != ActionHandled {
		t.Fatalf("expected ActionHandled, got %v", action)
	}
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unrecognized flag") {
		t.Fatalf("expected stderr to contain 'unrecognized flag', got %q", stderr.String())
	}
}

func TestEvaluateArgs_TerminalNoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return true })

	action, code := runner.EvaluateArgs([]string{})
	if action != ActionHandled {
		t.Fatalf("expected ActionHandled, got %v", action)
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Notice:") {
		t.Fatalf("expected output to contain terminal Notice, got %q", stdout.String())
	}
}

func TestEvaluateArgs_PipeNoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })

	action, code := runner.EvaluateArgs([]string{})
	if action != ActionExecuteGate {
		t.Fatalf("expected ActionExecuteGate, got %v", action)
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("expected no stdout/stderr output for gate execution, got out=%q, err=%q", stdout.String(), stderr.String())
	}
}

func TestEvaluateArgs_IngestFlags(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })

	action, code := runner.EvaluateArgs([]string{"ingest", "--session", "test-sess", "--turn", "2", "--prompt", "Delete build artifacts"})
	if action != ActionHandled {
		t.Fatalf("expected ActionHandled, got %v", action)
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("expected stdout to be empty to prevent prompt pollution, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Session intent recorded") {
		t.Errorf("expected stderr to mention session intent recorded, got %q", stderr.String())
	}
}

func TestEvaluateArgs_IngestEqualsSyntax(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })

	action, code := runner.EvaluateArgs([]string{"ingest", "--session=equals-sess", "--turn=3", "--prompt=Clean up cache directory"})
	if action != ActionHandled {
		t.Fatalf("expected ActionHandled, got %v", action)
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("expected stdout to be empty to prevent prompt pollution, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "equals-sess") || !strings.Contains(stderr.String(), "turn: 3") {
		t.Errorf("expected stderr to mention equals-sess and turn 3, got %q", stderr.String())
	}
}

func TestEvaluateArgs_IngestStdin(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })
	runner.Stdin = strings.NewReader(`{"session_id": "piped-sess", "turn_id": 1, "prompt": "Compile app"}`)

	action, code := runner.EvaluateArgs([]string{"ingest"})
	if action != ActionHandled {
		t.Fatalf("expected ActionHandled, got %v", action)
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("expected stdout to be empty to prevent prompt pollution, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "piped-sess") {
		t.Errorf("expected stderr to mention piped-sess, got %q", stderr.String())
	}
}

func TestEvaluateArgs_IngestAbort(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })

	action, code := runner.EvaluateArgs([]string{"ingest", "--session", "abort-sess", "--prompt", "Stop! Cancel all operations"})
	if action != ActionHandled {
		t.Fatalf("expected ActionHandled, got %v", action)
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("expected stdout to be empty to prevent prompt pollution, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Abort signal recorded") {
		t.Errorf("expected abort signal notice in stderr, got %q", stderr.String())
	}
}

func TestEvaluateArgs_IngestTerminalWithoutPrompt(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return true }) // interactive terminal

	action, code := runner.EvaluateArgs([]string{"ingest"})
	if action != ActionHandled {
		t.Fatalf("expected ActionHandled, got %v", action)
	}
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "requires a non-empty prompt") {
		t.Errorf("expected error message about non-empty prompt, got %q", stderr.String())
	}
}

func TestEvaluateArgs_ClearIntent(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })

	// First ingest
	_, _ = runner.EvaluateArgs([]string{"ingest", "--session", "to-clear", "--prompt", "Test"})
	stdout.Reset()

	// Clear specific
	action, code := runner.EvaluateArgs([]string{"clear-intent", "--session", "to-clear"})
	if action != ActionHandled || code != 0 {
		t.Fatalf("expected ActionHandled with code 0, got %v, %d", action, code)
	}
	if !strings.Contains(stdout.String(), "Session intent cleared") {
		t.Errorf("expected clear output, got %q", stdout.String())
	}
}

func TestEvaluateArgs_ClearIntentEqualsSyntax(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })

	// First ingest
	_, _ = runner.EvaluateArgs([]string{"ingest", "--session=to-clear-eq", "--prompt=Test"})
	stdout.Reset()

	// Clear specific using equals syntax
	action, code := runner.EvaluateArgs([]string{"clear-intent", "--session=to-clear-eq"})
	if action != ActionHandled || code != 0 {
		t.Fatalf("expected ActionHandled with code 0, got %v, %d", action, code)
	}
	if !strings.Contains(stdout.String(), "Session intent cleared for session 'to-clear-eq'") {
		t.Errorf("expected clear output for to-clear-eq, got %q", stdout.String())
	}
}

func TestEvaluateArgs_CacheClearAlias(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })

	action, code := runner.EvaluateArgs([]string{"cache", "clear", "--all"})
	if action != ActionHandled || code != 0 {
		t.Fatalf("expected ActionHandled with code 0, got %v, %d", action, code)
	}
	if !strings.Contains(stdout.String(), "cleared") {
		t.Errorf("expected clear output, got %q", stdout.String())
	}
}

func TestEvaluateArgs_CacheNoArgs(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })

	action, code := runner.EvaluateArgs([]string{"cache"})
	if action != ActionHandled || code != 0 {
		t.Fatalf("expected ActionHandled with code 0, got %v, %d", action, code)
	}
	if !strings.Contains(stdout.String(), "jev-guard status:") {
		t.Errorf("expected status output, got %q", stdout.String())
	}
}

func TestEvaluateArgs_CacheStatus(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })

	action, code := runner.EvaluateArgs([]string{"cache", "status"})
	if action != ActionHandled || code != 0 {
		t.Fatalf("expected ActionHandled with code 0, got %v, %d", action, code)
	}
	if !strings.Contains(stdout.String(), "jev-guard status:") {
		t.Errorf("expected status output, got %q", stdout.String())
	}
}

func TestEvaluateArgs_CacheUnknown(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })

	action, code := runner.EvaluateArgs([]string{"cache", "invalid"})
	if action != ActionHandled || code != 1 {
		t.Fatalf("expected ActionHandled with code 1, got %v, %d", action, code)
	}
	if !strings.Contains(stderr.String(), "unrecognized flag or command") {
		t.Errorf("expected error output, got %q", stderr.String())
	}
}

func TestEvaluateArgs_Status(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })

	// Ingest one session
	_, _ = runner.EvaluateArgs([]string{"ingest", "--session", "status-sess", "--prompt", "Working on tests"})
	stdout.Reset()

	action, code := runner.EvaluateArgs([]string{"status"})
	if action != ActionHandled || code != 0 {
		t.Fatalf("expected ActionHandled with code 0, got %v, %d", action, code)
	}
	if !strings.Contains(stdout.String(), "status-sess") {
		t.Errorf("expected status output to list status-sess, got %q", stdout.String())
	}
}

func newStdinRunner(stdin string) (*Runner, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })
	runner.Stdin = strings.NewReader(stdin)
	return runner, &stdout, &stderr
}

func TestEndTurn_ClearsOnlyNamedSession(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	for _, id := range []string{"a", "b"} {
		if err := session.SaveSession(&session.SessionState{SessionID: id, Prompt: "do it"}); err != nil {
			t.Fatal(err)
		}
	}
	runner, stdout, _ := newStdinRunner(`{"session_id":"a","hook_event_name":"Stop"}`)
	action, code := runner.EvaluateArgs([]string{"end-turn"})
	if action != ActionHandled || code != 0 {
		t.Fatalf("got %v, %d", action, code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must be empty, got %q", stdout.String())
	}
	if s, _ := session.LoadSession("a"); s != nil {
		t.Fatal("session a should be cleared")
	}
	if s, _ := session.LoadSession("b"); s == nil {
		t.Fatal("session b must survive")
	}
}

func TestEndTurn_ExplicitSessionFlagAndAbortCleared(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	_ = session.SaveSession(&session.SessionState{SessionID: "x", Prompt: "stop"})
	_ = session.SaveSession(&session.SessionState{SessionID: "y", Prompt: "keep"})
	runner, stdout, _ := newStdinRunner("")
	if _, code := runner.EvaluateArgs([]string{"end-turn", "--session", "x"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must be empty, got %q", stdout.String())
	}
	if s, _ := session.LoadSession("x"); s != nil {
		t.Fatal("aborted session x should be cleared")
	}
	if s, _ := session.LoadSession("y"); s == nil {
		t.Fatal("session y must survive")
	}
}

func TestEndTurn_EmptyStdinIsNoOp(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	_ = session.SaveSession(&session.SessionState{SessionID: "keep", Prompt: "p"})
	_ = session.SaveSession(&session.SessionState{SessionID: "default", Prompt: "p"})
	for _, in := range []string{"", "  \n", "not json"} {
		runner, stdout, _ := newStdinRunner(in)
		action, code := runner.EvaluateArgs([]string{"end-turn"})
		if action != ActionHandled || code != 0 {
			t.Fatalf("input %q: got %v, %d", in, action, code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout must be empty, got %q", stdout.String())
		}
	}
	for _, id := range []string{"keep", "default"} {
		if s, _ := session.LoadSession(id); s == nil {
			t.Fatalf("session %s must survive a no-op end-turn", id)
		}
	}
}

func TestClearIntent_NoFlagsDoesNotClearAll(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	_ = session.SaveSession(&session.SessionState{SessionID: "s1", Prompt: "p"})
	runner, stdout, stderr := newStdinRunner("")
	_, code := runner.EvaluateArgs([]string{"clear-intent"})
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "--all") {
		t.Fatalf("expected usage on stderr only, stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	runner, _, _ = newStdinRunner("")
	if _, code := runner.EvaluateArgs([]string{"cache", "clear"}); code != 1 {
		t.Fatalf("cache clear without flags: expected exit 1, got %d", code)
	}
	if s, _ := session.LoadSession("s1"); s == nil {
		t.Fatal("session must survive clear-intent without flags")
	}
	runner, _, _ = newStdinRunner("")
	if _, code := runner.EvaluateArgs([]string{"clear-intent", "--all"}); code != 0 {
		t.Fatalf("--all: exit %d", code)
	}
	if s, _ := session.LoadSession("s1"); s != nil {
		t.Fatal("--all should clear everything")
	}
}
