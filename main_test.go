package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"jev-guard/pkg/cli"
	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

func TestResolveUserIntent(t *testing.T) {
	tests := []struct {
		name          string
		callTurnID    int
		callTurnKey   string
		sessionKey    string
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
		{name: "matching turn keys", callTurnKey: "t1", sessionKey: "t1", prompt: "p", expected: "p"},
		{name: "different turn keys", callTurnKey: "t2", sessionKey: "t1", prompt: "p", expected: ""},
		{name: "call key but session has none", callTurnKey: "t1", prompt: "p", expected: ""},
		{name: "session key only (Claude call)", sessionKey: "t1", prompt: "p", expected: "p"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveUserIntent(tc.callTurnID, tc.sessionTurnID, tc.callTurnKey, tc.sessionKey, tc.prompt)
			if got != tc.expected {
				t.Errorf("resolveUserIntent(callTurnID=%d, sessionTurnID=%d, callTurnKey=%q, sessionKey=%q, prompt=%q) = %q; want %q",
					tc.callTurnID, tc.sessionTurnID, tc.callTurnKey, tc.sessionKey, tc.prompt, got, tc.expected)
			}
		})
	}
}

// ingest runs the real `ingest` CLI command with the given hook payload on stdin.
func ingest(t *testing.T, payload string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	runner := cli.NewRunner(&stdout, &stderr, func() bool { return false })
	runner.Stdin = strings.NewReader(payload)
	if _, code := runner.EvaluateArgs([]string{"ingest"}); code != 0 {
		t.Fatalf("ingest exit %d, stderr=%q", code, stderr.String())
	}
}

// toolCall builds a Codex PreToolUse call for the given session and turn, plus the
// config for it. It fails the test if context awareness is not enabled.
func toolCall(t *testing.T, sessionID, turnID string) (*harness.NormalizedToolCall, *config.Config) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"session_id":      sessionID,
		"turn_id":         turnID,
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "rm -rf build"},
		"tool_use_id":     "x1",
		"cwd":             t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	call, err := harness.ParsePayload(raw)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	cfg := config.LoadConfigForCall(call)
	if !cfg.IsContextAwarenessEnabled() {
		t.Fatal("context awareness must be enabled for the Codex e2e tests")
	}
	return call, cfg
}

func TestCodexFlow_IntentScopedToTurn(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	ingest(t, `{"session_id":"codex-e2e","turn_id":"turn-A","hook_event_name":"UserPromptSubmit","prompt":"Delete the build folder"}`)

	callA, cfgA := toolCall(t, "codex-e2e", "turn-A")
	if res := applySessionContext(callA, cfgA); res != nil {
		t.Fatalf("turn-A: expected nil result, got %+v", res)
	}
	if callA.UserIntent != "Delete the build folder" {
		t.Errorf("turn-A: UserIntent = %q; want %q", callA.UserIntent, "Delete the build folder")
	}

	callB, cfgB := toolCall(t, "codex-e2e", "turn-B")
	if res := applySessionContext(callB, cfgB); res != nil {
		t.Fatalf("turn-B: expected nil result, got %+v", res)
	}
	if callB.UserIntent != "" {
		t.Errorf("turn-B: UserIntent = %q; want empty", callB.UserIntent)
	}
}

func TestCodexFlow_AbortHeldAcrossTurns(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	ingest(t, `{"session_id":"codex-abort","turn_id":"turn-A","hook_event_name":"UserPromptSubmit","prompt":"Stop! Cancel all operations"}`)

	for _, turn := range []string{"turn-A", "turn-B"} {
		call, cfg := toolCall(t, "codex-abort", turn)
		res := applySessionContext(call, cfg)
		if res == nil {
			t.Fatalf("%s: expected abort hold, got nil", turn)
		}
		if res.Decision != harness.DecisionForceAsk {
			t.Errorf("%s: Decision = %v; want %v", turn, res.Decision, harness.DecisionForceAsk)
		}
		if res.Source != "session_aborted" {
			t.Errorf("%s: Source = %q; want %q", turn, res.Source, "session_aborted")
		}
	}
}

func TestCodexFlow_NewTurnIngestClearsAbort(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	ingest(t, `{"session_id":"codex-abort","turn_id":"turn-A","hook_event_name":"UserPromptSubmit","prompt":"Stop! Cancel all operations"}`)
	ingest(t, `{"session_id":"codex-abort","turn_id":"turn-B","hook_event_name":"UserPromptSubmit","prompt":"List the files"}`)

	call, cfg := toolCall(t, "codex-abort", "turn-B")
	if res := applySessionContext(call, cfg); res != nil {
		t.Fatalf("turn-B: expected nil result after new prompt, got %+v", res)
	}
	if call.UserIntent != "List the files" {
		t.Errorf("turn-B: UserIntent = %q; want %q", call.UserIntent, "List the files")
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
