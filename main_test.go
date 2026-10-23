package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"jev-guard/pkg/boundary"
	"jev-guard/pkg/config"
	"jev-guard/pkg/fastpath"
	"jev-guard/pkg/harness"
	"jev-guard/pkg/session"
)

func TestTraceGateEvaluationPreservesVerifiedBoundaryEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"answers":{
			"is_workspace_contained":{"type":"noul","noul":0.1},
			"destructive_potential":{"type":"score","score":0.45,"confidence":0.91},
			"violation_category":{"type":"choice","choice":"none","confidence":0.96}
		}}`)
	}))
	defer server.Close()
	cfg := config.DefaultConfig()
	cfg.APIKey, cfg.BaseURL = "test-key", server.URL
	ws := t.TempDir()
	for _, tc := range []struct {
		name string
		call *harness.NormalizedToolCall
		want harness.Decision
	}{
		{"verified file", &harness.NormalizedToolCall{ToolName: "Write", TargetPath: "result.txt", Cwd: ws, RawArgs: map[string]interface{}{"file_path": "result.txt"}}, harness.DecisionAllow},
		{"unverified shell", &harness.NormalizedToolCall{ToolName: "Bash", Command: "touch result.txt", Cwd: ws}, harness.DecisionAsk},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trace := traceGateEvaluation(tc.call, cfg, false)
			if !trace.SemanticRan || trace.EvalErr != nil || trace.Final == nil || trace.Final.Decision != tc.want {
				t.Fatalf("trace=%+v final=%+v; want %s", trace, trace.Final, tc.want)
			}
		})
	}
}

type countingBoundaryChecker struct {
	calls     int
	contained bool
	err       error
}

func (c *countingBoundaryChecker) IsPathContained(target, cwd string) (bool, error) {
	c.calls++
	return c.contained, c.err
}

func TestTraceAndFastpathShareBoundaryResolution(t *testing.T) {
	for _, contained := range []bool{true, false} {
		underlying := &countingBoundaryChecker{contained: contained}
		checker := &cachedBoundaryChecker{checker: underlying}
		call := &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: "README.md", Cwd: t.TempDir()}
		if got := checkWorkspaceBoundary(call, checker); got != contained {
			t.Fatalf("contained = %t, want %t", got, contained)
		}
		result := fastpath.NewFilter(checker, config.DefaultConfig()).Evaluate(call)
		want := harness.DecisionAllow
		if !contained {
			want = harness.DecisionAsk
		}
		if result == nil || result.Decision != want || underlying.calls != 1 {
			t.Fatalf("result=%v boundary checks=%d; want %s and one check", result, underlying.calls, want)
		}
	}
}

func TestCachedBoundaryCheckerPreservesErrorsAndDistinctPaths(t *testing.T) {
	wantErr := errors.New("resolution failed")
	underlying := &countingBoundaryChecker{err: wantErr}
	checker := &cachedBoundaryChecker{checker: underlying}
	for _, query := range [][2]string{{"file:///tmp/x", "/tmp"}, {"file:///tmp/x", "/tmp"}, {"/tmp/x", "/tmp"}, {"/tmp/x", "/other"}} {
		contained, err := checker.IsPathContained(query[0], query[1])
		if contained || err != wantErr {
			t.Fatalf("resolution changed: contained=%t err=%v", contained, err)
		}
	}
	if underlying.calls != 3 {
		t.Fatalf("distinct paths/cwd should remain independent: checks=%d", underlying.calls)
	}
}

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

func TestApplySessionContext(t *testing.T) {
	type setupFn func(t *testing.T)
	saveSession := func(state *session.SessionState) setupFn {
		return func(t *testing.T) {
			if err := session.SaveSession(state); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeCorrupt := func(t *testing.T) {
		if err := os.WriteFile(session.SessionFilePath("s1"), []byte("{not json"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	makeDirectory := func(t *testing.T) {
		if err := os.Mkdir(session.SessionFilePath("s1"), 0700); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name            string
		setup           setupFn
		disableContext  bool
		wantHold        bool
		wantDecision    harness.Decision
		wantSource      string
		wantIntent      string
		wantStderr      bool
		wantFileRemains bool
	}{
		{name: "absent session", setup: nil},
		{name: "valid session", setup: saveSession(&session.SessionState{SessionID: "s1", Prompt: "list files"}), wantIntent: "list files"},
		{name: "aborted session", setup: saveSession(&session.SessionState{SessionID: "s1", Prompt: "stop"}), wantHold: true, wantDecision: harness.DecisionForceAsk, wantSource: sourceSessionAborted},
		{name: "corrupt json", setup: writeCorrupt, wantHold: true, wantDecision: harness.DecisionForceAsk, wantSource: sourceSessionReadError, wantStderr: true, wantFileRemains: true},
		{name: "unreadable directory", setup: makeDirectory, wantHold: true, wantDecision: harness.DecisionForceAsk, wantSource: sourceSessionReadError, wantStderr: true, wantFileRemains: true},
		{name: "context awareness disabled with corrupt file", setup: writeCorrupt, disableContext: true, wantFileRemains: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("JEV_GUARD_HOME", t.TempDir())
			if err := os.MkdirAll(session.GetSessionsDir(), 0700); err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(t)
			}
			cfg := config.DefaultConfig()
			if tc.disableContext {
				f := false
				cfg.ContextAwarenessEnabled = &f
			}
			call := &harness.NormalizedToolCall{SessionID: "s1", ToolName: "Bash", Command: "ls"}
			var stderr bytes.Buffer

			hold := applySessionContext(call, cfg, &stderr)

			if !tc.wantHold {
				if hold != nil {
					t.Fatalf("expected nil hold, got %+v", *hold)
				}
			} else {
				if hold == nil {
					t.Fatal("expected a hold, got nil")
				}
				if hold.Decision != tc.wantDecision {
					t.Errorf("Decision = %q, want %q", hold.Decision, tc.wantDecision)
				}
				if hold.Source != tc.wantSource {
					t.Errorf("Source = %q, want %q", hold.Source, tc.wantSource)
				}
			}
			if call.UserIntent != tc.wantIntent {
				t.Errorf("UserIntent = %q, want %q", call.UserIntent, tc.wantIntent)
			}
			if tc.wantStderr && stderr.Len() == 0 {
				t.Error("expected stderr diagnostic, got none")
			}
			if !tc.wantStderr && stderr.Len() != 0 {
				t.Errorf("expected empty stderr, got %q", stderr.String())
			}
			if tc.wantFileRemains {
				if _, err := os.Stat(session.SessionFilePath("s1")); err != nil {
					t.Errorf("session file should remain: %v", err)
				}
			}
		})
	}
}

func TestApplyAuditMode_RewritesSessionReadErrorHold(t *testing.T) {
	hold := &harness.EvaluationResult{
		Decision:   harness.DecisionForceAsk,
		Reason:     "held",
		Source:     sourceSessionReadError,
		Confidence: 1.0,
	}
	got := applyAuditMode(hold, "audit")
	if got.Decision != harness.DecisionAllow {
		t.Errorf("Decision = %q, want %q", got.Decision, harness.DecisionAllow)
	}
	if got.Source != sourceSessionReadError {
		t.Errorf("Source = %q, want %q", got.Source, sourceSessionReadError)
	}
}
