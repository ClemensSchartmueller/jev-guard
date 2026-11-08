package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jev-guard/internal/testpaths"
	"jev-guard/pkg/boundary"
	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
	"jev-guard/pkg/session"
)

// The whole gate (anti-tampering, boundary, fast path and taint) shares one path resolution
// scope per call: words under one deep directory are walked once, and words under distinct
// trees exhaust the shared budget and ask, instead of each check paying in full. The deep
// prefix is 500 levels (fewer where the path limit is lower): walking it once per word would
// cost far more than the budget. The distinct trees are shallow, under a budget lowered to
// about three of them. Words are relative, since trusted-command arguments are lower-cased.
func TestTraceGateEvaluation_DeepPathsShareOneResolutionScope(t *testing.T) {
	ws, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rel := func(dir string) string {
		r, err := filepath.Rel(ws, dir)
		if err != nil {
			t.Fatal(err)
		}
		return filepath.ToSlash(r)
	}
	sharedDir, _ := testpaths.DeepDirs(t, filepath.Join(ws, "shared"), 500, 16)
	shared := rel(sharedDir)
	var sharedWords, distinctWords strings.Builder
	sharedWords.WriteString("echo")
	distinctWords.WriteString("echo")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&sharedWords, " %s/z%d", shared, i)
	}
	const depth = 40
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&distinctWords, " %s/z", rel(testpaths.NestedDirs(t, filepath.Join(ws, fmt.Sprint(i)), depth)))
	}
	distinctBudget := int64(3 * depth * (len(ws) + depth + 4))

	cfg := taintConfig(config.TaintModeEnforce)
	for _, tc := range []struct {
		name, command string
		want          harness.Decision
		source        string
		budget        int64
	}{
		{"shared prefix", sharedWords.String(), harness.DecisionAllow, "fastpath_trusted", 0},
		{"distinct trees", distinctWords.String(), harness.DecisionAsk, "boundary_limit", distinctBudget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.budget > 0 {
				t.Cleanup(boundary.SetWorkBudgetForTesting(tc.budget))
			}
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
