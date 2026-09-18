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
