package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
	"jev-guard/pkg/session"
)

// nestedWorkspaceDirs creates depth nested directories named "a" under ws/name and returns
// their path relative to ws (relative, since trusted-command arguments are lower-cased).
func nestedWorkspaceDirs(t *testing.T, ws, name string, depth int) string {
	t.Helper()
	rel := filepath.Join(name, strings.TrimSuffix(strings.Repeat("a/", depth), "/"))
	if err := os.MkdirAll(filepath.Join(ws, rel), 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(rel)
}

// The whole gate (anti-tampering, boundary, fast path and taint) shares one path resolution
// scope per call: words under one deep directory are walked once, and words under distinct
// deep trees exhaust the shared budget and ask, instead of each check paying in full.
func TestTraceGateEvaluation_DeepPathsShareOneResolutionScope(t *testing.T) {
	ws, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	shared := nestedWorkspaceDirs(t, ws, "shared", 1500)
	var sharedWords, distinctWords strings.Builder
	sharedWords.WriteString("echo")
	distinctWords.WriteString("echo")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&sharedWords, " %s/z%d", shared, i)
	}
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&distinctWords, " %s/z", nestedWorkspaceDirs(t, ws, fmt.Sprint(i), 1500))
	}

	cfg := taintConfig(config.TaintModeEnforce)
	for _, tc := range []struct {
		name, command string
		want          harness.Decision
		source        string
	}{
		{"shared prefix", sharedWords.String(), harness.DecisionAllow, "fastpath_trusted"},
		{"distinct trees", distinctWords.String(), harness.DecisionAsk, "boundary_limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call := &harness.NormalizedToolCall{ToolName: "Bash", Command: tc.command, Cwd: ws, WorkspaceRoots: []string{ws},
				Taint: &session.TaintSource{ToolName: "WebFetch", At: time.Now()}}
			start := time.Now()
			trace := traceGateEvaluation(call, cfg, true)
			elapsed := time.Since(start)
			if elapsed > 2*time.Second {
				t.Errorf("gate evaluation took %v", elapsed)
			}
			if trace.Final == nil || trace.Final.Decision != tc.want || trace.Final.Source != tc.source {
				t.Fatalf("final = %+v, want %s from %s", trace.Final, tc.want, tc.source)
			}
			t.Logf("%v", elapsed)
		})
	}
}
