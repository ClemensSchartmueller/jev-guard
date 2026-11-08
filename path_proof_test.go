package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

// A locally contained path must not suppress the model's containment warning
// when a harmless-looking alias actually targets agent configuration.
func TestGatePathProofResolvedSensitivePaths(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	ws := t.TempDir()
	for _, dir := range []string{".claude", "src"} {
		if err := os.MkdirAll(filepath.Join(ws, dir), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ws, dir, "settings.json"), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for alias, dest := range map[string]string{"agent-alias": ".claude", "source-alias": "src", "dangling-alias": ".claude/missing.json"} {
		if err := os.Symlink(filepath.Join(ws, dest), filepath.Join(ws, alias)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"answers":{"is_workspace_contained":{"type":"noul","noul":0.1},"destructive_potential":{"type":"score","score":0.1,"confidence":0.9},"violation_category":{"type":"choice","choice":"none","confidence":0.9},"intent_alignment":{"type":"choice","choice":"unprompted","confidence":0.9}}}`)
	}))
	defer server.Close()
	cfg := config.DefaultConfig()
	cfg.APIKey, cfg.BaseURL = "test-key", server.URL
	disabled := false
	cfg.FastpathEnabled = &disabled
	for _, tc := range []struct {
		name, cwd, target string
		want              harness.Decision
	}{
		{"symlink directory", ws, "agent-alias/settings.json", harness.DecisionAsk},
		{"new file through symlink", ws, "agent-alias/new.json", harness.DecisionAsk},
		{"dangling final symlink", ws, "dangling-alias", harness.DecisionAsk},
		{"ordinary missing file", ws, "src/new/file.go", harness.DecisionAllow},
		{"cwd inside configuration", filepath.Join(ws, ".claude"), "settings.json", harness.DecisionAsk},
		{"ordinary symlink", ws, "source-alias/settings.json", harness.DecisionAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call := &harness.NormalizedToolCall{ToolName: "Write", TargetPath: tc.target, Cwd: tc.cwd, WorkspaceRoots: []string{ws}, RawArgs: map[string]interface{}{"file_path": tc.target}}
			trace := traceGateEvaluation(call, cfg, false)
			if !trace.Contained || !trace.SemanticRan || trace.EvalErr != nil {
				t.Fatalf("expected contained semantic evaluation, got %+v", trace)
			}
			if trace.Final == nil || trace.Final.Decision != tc.want {
				t.Fatalf("final=%+v; want %s", trace.Final, tc.want)
			}
			if tc.want == harness.DecisionAsk && trace.Final.Source != "policy_jev_containment" {
				t.Fatalf("expected model containment warning, got %+v", trace.Final)
			}
		})
	}
}

// Absolute paths retain the conservative lexical exclusion for the .claude
// container; only relative ordinary worktree paths receive proof.
func TestPathProofClaudeWorktree(t *testing.T) {
	wt := filepath.Join(t.TempDir(), ".claude", "worktrees", "feature")
	if err := os.MkdirAll(filepath.Join(wt, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: elsewhere"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		target string
		want   bool
	}{{"src/main.go", true}, {".claude/settings.json", false}, {filepath.Join(wt, "src/main.go"), false}} {
		call := &harness.NormalizedToolCall{ToolName: "Write", TargetPath: tc.target, Cwd: wt, WorkspaceRoots: []string{wt}, RawArgs: map[string]interface{}{"file_path": tc.target}}
		if got := isLocalPathVerified(call, true); got != tc.want {
			t.Errorf("path proof for %q = %v; want %v", tc.target, got, tc.want)
		}
	}
}
