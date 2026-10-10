package main

import (
	"os"
	"path/filepath"
	"testing"

	"jev-guard/pkg/boundary"
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

func TestIsLocalPathVerified(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("x"), 0o600); err != nil {
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
		{"write inside workspace", &harness.NormalizedToolCall{ToolName: "Write", TargetPath: filepath.Join(root, "a.go")}, true},
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
