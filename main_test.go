package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jev-guard/pkg/boundary"
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

func TestIsLocalPathVerified(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nb.ipynb"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, err := boundary.NewResolver([]string{root}, root)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		call *harness.NormalizedToolCall
		want bool
	}{
		{"write inside workspace", &harness.NormalizedToolCall{ToolName: "Write", TargetPath: filepath.Join(root, "a.go"), RawArgs: map[string]interface{}{"file_path": filepath.Join(root, "a.go")}}, true},
		{"mixed path args", &harness.NormalizedToolCall{ToolName: "Write", TargetPath: filepath.Join(root, "a.go"), RawArgs: map[string]interface{}{"TargetFile": filepath.Join(root, "a.go"), "file_path": filepath.Join(outside, "x")}}, false},
		{"non-canonical key", &harness.NormalizedToolCall{ToolName: "write_to_file", TargetPath: filepath.Join(root, "a.go"), RawArgs: map[string]interface{}{"file_path": filepath.Join(root, "a.go")}}, false},
		{"canonical TargetFile", &harness.NormalizedToolCall{ToolName: "write_to_file", TargetPath: filepath.Join(root, "a.go"), RawArgs: map[string]interface{}{"TargetFile": filepath.Join(root, "a.go")}}, true},
		{"notebook edit", &harness.NormalizedToolCall{ToolName: "NotebookEdit", TargetPath: filepath.Join(root, "nb.ipynb"), RawArgs: map[string]interface{}{"notebook_path": filepath.Join(root, "nb.ipynb")}}, true},
		{"unknown tool with path and destination", &harness.NormalizedToolCall{ToolName: "CopyFiles", TargetPath: filepath.Join(root, "a.go"), RawArgs: map[string]interface{}{"path": filepath.Join(root, "a.go"), "destination": "/etc/x"}}, false},
		{"bash command", &harness.NormalizedToolCall{ToolName: "Bash", Command: "ls", TargetPath: filepath.Join(root, "a.go")}, false},
		{"url target", &harness.NormalizedToolCall{ToolName: "WebFetch", TargetPath: "https://example.com/x"}, false},
		{"outside workspace", &harness.NormalizedToolCall{ToolName: "Write", TargetPath: filepath.Join(outside, "b.go")}, false},
		{"empty target", &harness.NormalizedToolCall{ToolName: "Write"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.call.Cwd = root
			tt.call.WorkspaceRoots = []string{root}
			contained := checkWorkspaceBoundary(tt.call, resolver)
			if got := isLocalPathVerified(tt.call, contained); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsLocalPathVerifiedSensitivePaths(t *testing.T) {
	sensitive := []string{
		"/repo/.git/hooks/pre-commit",
		"/repo/.claude/settings.json",
		"/repo/.claude/settings.local.json",
		"/repo/.vscode/tasks.json",
		"/repo/.codex/config.toml",
		"/repo/.github/workflows/ci.yml",
		`C:\repo\.Git\hooks\post-checkout`,
		"/repo/CLAUDE.md",
		"/repo/.mcp.json",
	}
	for _, p := range sensitive {
		call := &harness.NormalizedToolCall{ToolName: "Write", TargetPath: p, RawArgs: map[string]interface{}{"file_path": p}}
		if isLocalPathVerified(call, true) {
			t.Errorf("isLocalPathVerified(%q) = true; want false", p)
		}
	}

	p := "/repo/src/main.go"
	call := &harness.NormalizedToolCall{ToolName: "Write", TargetPath: p, RawArgs: map[string]interface{}{"file_path": p}}
	if !isLocalPathVerified(call, true) {
		t.Errorf("isLocalPathVerified(%q) = false; want true", p)
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

func TestApplyTranscriptIntent_OverridesSessionIntent(t *testing.T) {
	home, path := writeTranscript(t, "conv-4", "refactor the parser")
	call := &harness.NormalizedToolCall{Harness: harness.HarnessAntigravity, SessionID: "conv-4", TranscriptPath: path}
	call.UserIntent = "old cached intent"
	if applyTranscriptIntent(call, config.DefaultConfig(), home) {
		t.Fatal("expected no hold")
	}
	if call.UserIntent != "refactor the parser" {
		t.Fatalf("transcript intent must replace session intent, got %q", call.UserIntent)
	}
}

func TestApplyTranscriptIntent_UnusableLatestClearsIntent(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".gemini", "antigravity", "brain", "conv-3", ".system_generated", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "transcript.jsonl")
	body := `{"type":"USER_INPUT","source":"USER_EXPLICIT","status":"DONE","content":"delete the build directory"}` + "\n" +
		`{"type":"PLANNER_RESPONSE","source":"MODEL","status":"DONE","content":"ok"}` + "\n" +
		`{"type":"USER_INPUT","source":"USER_EXPLICIT","content":""}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	call := &harness.NormalizedToolCall{Harness: harness.HarnessAntigravity, SessionID: "conv-3", TranscriptPath: path}
	call.UserIntent = "stale cached intent"
	if applyTranscriptIntent(call, config.DefaultConfig(), home) {
		t.Fatal("unusable latest message must not hold")
	}
	if call.UserIntent != "" {
		t.Fatalf("unusable latest message must clear session intent, got %q", call.UserIntent)
	}
}

func TestApplyTranscriptIntent_UnavailableKeepsSessionIntent(t *testing.T) {
	home := t.TempDir()
	call := &harness.NormalizedToolCall{Harness: harness.HarnessAntigravity, SessionID: "conv-5"}
	call.TranscriptPath = filepath.Join(t.TempDir(), "transcript.jsonl")
	call.UserIntent = "cached"
	if applyTranscriptIntent(call, config.DefaultConfig(), home) {
		t.Fatal("unavailable transcript must not hold")
	}
	if call.UserIntent != "cached" {
		t.Fatalf("unavailable transcript must keep session intent, got %q", call.UserIntent)
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
