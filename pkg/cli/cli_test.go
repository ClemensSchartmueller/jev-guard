package cli

import (
	"bytes"
	"strings"
	"testing"
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
	if !strings.Contains(stdout.String(), "Session intent recorded") {
		t.Errorf("expected output to mention session intent recorded, got %q", stdout.String())
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
	if !strings.Contains(stdout.String(), "equals-sess") || !strings.Contains(stdout.String(), "turn: 3") {
		t.Errorf("expected output to mention equals-sess and turn 3, got %q", stdout.String())
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
	if !strings.Contains(stdout.String(), "piped-sess") {
		t.Errorf("expected output to mention piped-sess, got %q", stdout.String())
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
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Abort signal recorded") {
		t.Errorf("expected abort signal notice, got %q", stdout.String())
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

	action, code := runner.EvaluateArgs([]string{"cache", "clear"})
	if action != ActionHandled || code != 0 {
		t.Fatalf("expected ActionHandled with code 0, got %v, %d", action, code)
	}
	if !strings.Contains(stdout.String(), "cleared") {
		t.Errorf("expected clear output, got %q", stdout.String())
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
