package main

import (
	"os"
	"path/filepath"
	"testing"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

func TestResolveUserIntent(t *testing.T) {
	tests := []struct {
		name          string
		callTurnID    int
		sessionTurnID int
		prompt        string
		expected      string
	}{
		{
			name:          "both turn IDs zero",
			callTurnID:    0,
			sessionTurnID: 0,
			prompt:        "do something safe",
			expected:      "do something safe",
		},
		{
			name:          "call turn ID zero, session non-zero",
			callTurnID:    0,
			sessionTurnID: 2,
			prompt:        "do something safe",
			expected:      "do something safe",
		},
		{
			name:          "call turn ID non-zero, session zero",
			callTurnID:    2,
			sessionTurnID: 0,
			prompt:        "do something safe",
			expected:      "do something safe",
		},
		{
			name:          "matching turn IDs",
			callTurnID:    3,
			sessionTurnID: 3,
			prompt:        "do something safe",
			expected:      "do something safe",
		},
		{
			name:          "mismatched turn IDs",
			callTurnID:    4,
			sessionTurnID: 3,
			prompt:        "stale previous turn prompt",
			expected:      "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveUserIntent(tc.callTurnID, tc.sessionTurnID, tc.prompt)
			if got != tc.expected {
				t.Errorf("resolveUserIntent(%d, %d, %q) = %q; want %q",
					tc.callTurnID, tc.sessionTurnID, tc.prompt, got, tc.expected)
			}
		})
	}
}

func TestApplyAuditMode(t *testing.T) {
	res := &harness.EvaluationResult{
		Decision: harness.DecisionDeny,
		Reason:   "unsafe action",
	}

	auditRes := applyAuditMode(res, "audit")
	if auditRes.Decision != harness.DecisionAllow {
		t.Errorf("expected DecisionAllow in audit mode, got %v", auditRes.Decision)
	}

	enforceRes := applyAuditMode(res, "enforce")
	if enforceRes.Decision != harness.DecisionDeny {
		t.Errorf("expected DecisionDeny in enforce mode, got %v", enforceRes.Decision)
	}
}

func writeTranscript(t *testing.T, convID, lastUser string) (home, path string) {
	t.Helper()
	home = t.TempDir()
	dir := filepath.Join(home, ".gemini", "antigravity", "brain", convID, ".system_generated", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "transcript.jsonl")
	body := `{"type":"USER_INPUT","source":"USER_EXPLICIT","status":"DONE","content":"` + lastUser + `"}` + "\n" +
		`{"type":"PLANNER_RESPONSE","source":"MODEL","status":"DONE","content":"ok"}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, path
}

func TestApplyTranscriptIntent(t *testing.T) {
	home, path := writeTranscript(t, "conv-1", "refactor the parser")
	newCall := func() *harness.NormalizedToolCall {
		return &harness.NormalizedToolCall{Harness: harness.HarnessAntigravity, SessionID: "conv-1", TranscriptPath: path}
	}

	call := newCall()
	if applyTranscriptIntent(call, config.DefaultConfig(), home) || call.UserIntent != "refactor the parser" {
		t.Fatalf("expected intent to be set, got held/intent %q", call.UserIntent)
	}

	off := false
	cfg := config.DefaultConfig()
	cfg.AntigravityTranscriptIntent = &off
	call = newCall()
	if applyTranscriptIntent(call, cfg, home) || call.UserIntent != "" {
		t.Fatalf("setting disabled must leave no intent, got %q", call.UserIntent)
	}

	call = newCall()
	call.TranscriptPath = filepath.Join(t.TempDir(), "transcript.jsonl")
	if applyTranscriptIntent(call, config.DefaultConfig(), home) || call.UserIntent != "" {
		t.Fatal("invalid path must yield no intent")
	}

	claude := newCall()
	claude.Harness = harness.HarnessClaudeCode
	if applyTranscriptIntent(claude, config.DefaultConfig(), home) || claude.UserIntent != "" {
		t.Fatal("non-Antigravity calls must be unaffected")
	}
}

func TestApplyTranscriptIntent_StopIsHeld(t *testing.T) {
	home, path := writeTranscript(t, "conv-2", "stop")
	call := &harness.NormalizedToolCall{Harness: harness.HarnessAntigravity, SessionID: "conv-2", TranscriptPath: path}
	if !applyTranscriptIntent(call, config.DefaultConfig(), home) {
		t.Fatal("expected stop request to hold the action")
	}
	if call.UserIntent != "" {
		t.Fatalf("held call must not carry intent, got %q", call.UserIntent)
	}

	off := false
	cfg := config.DefaultConfig()
	cfg.AntigravityTranscriptIntent = &off
	if applyTranscriptIntent(call, cfg, home) {
		t.Fatal("setting disabled must not hold")
	}
}
