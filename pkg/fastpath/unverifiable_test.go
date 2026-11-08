package fastpath

import (
	"os"
	"path/filepath"
	"testing"

	"jev-guard/pkg/harness"
)

// A path the OS cannot look up for a reason other than a missing name (a symlink loop, a
// file followed by more components) is unverifiable: a Read of it asks, it is not trusted.
func TestFastPath_UnresolvablePathAsks(t *testing.T) {
	ws := limitWorkspace(t)
	if err := os.WriteFile(filepath.Join(ws, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	targets := []string{filepath.Join(ws, "file", "x")}
	if err := os.Symlink("loop", filepath.Join(ws, "loop")); err == nil {
		targets = append(targets, filepath.Join(ws, "loop", "x"))
	} else {
		t.Logf("symlinks unavailable, skipping the loop case: %v", err)
	}
	for _, p := range targets {
		call := &harness.NormalizedToolCall{ToolName: "Read", TargetPath: p, Cwd: ws, WorkspaceRoots: []string{ws}}
		res := NewDefaultFilter().Evaluate(call)
		if res == nil || res.Decision != harness.DecisionAsk {
			t.Errorf("Read %s: got %+v, want ASK", p, res)
		}
	}
}
