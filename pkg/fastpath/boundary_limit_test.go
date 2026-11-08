package fastpath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"jev-guard/internal/testpaths"
	"jev-guard/pkg/boundary"
	"jev-guard/pkg/harness"
)

// pathologicalWord is the issue #72 input: a 64 KiB relative path of missing components.
var pathologicalWord = strings.Repeat("a/", 32*1024) + "z"

func limitWorkspace(t *testing.T) string {
	t.Helper()
	ws, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return ws
}

func assertBoundaryLimitAsk(t *testing.T, res *harness.EvaluationResult) {
	t.Helper()
	if res == nil || res.Decision != harness.DecisionAsk || res.Source != sourceBoundaryLimit {
		t.Fatalf("expected ASK from %s, got %+v", sourceBoundaryLimit, res)
	}
	if strings.Contains(res.Reason, "a/a/a/") {
		t.Errorf("reason repeats the path: %.120s...", res.Reason)
	}
}

// A trusted command with an over-limit argument used to be resolved in ~14 s and then allowed.
func TestFastPath_TrustedCommandOverLimitArgumentAsks(t *testing.T) {
	ws := limitWorkspace(t)
	filter := NewDefaultFilter()
	for _, intent := range []string{"", "please echo this"} {
		call := &harness.NormalizedToolCall{
			ToolName:       "Bash",
			Command:        "echo " + pathologicalWord,
			Cwd:            ws,
			WorkspaceRoots: []string{ws},
			UserIntent:     intent,
		}
		start := time.Now()
		res := filter.Evaluate(call)
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("intent %q: evaluation took %v", intent, elapsed)
		}
		assertBoundaryLimitAsk(t, res)
	}

	// The same command with an ordinary argument is still trusted.
	res := filter.Evaluate(&harness.NormalizedToolCall{
		ToolName: "Bash", Command: "echo a/a/z", Cwd: ws, WorkspaceRoots: []string{ws},
	})
	if res == nil || res.Decision != harness.DecisionAllow {
		t.Fatalf("expected ALLOW for a short in-workspace argument, got %+v", res)
	}
}

func TestFastPath_TrustedCommandOverLimitFlagValueAsks(t *testing.T) {
	ws := limitWorkspace(t)
	res := NewDefaultFilter().Evaluate(&harness.NormalizedToolCall{
		ToolName: "Bash", Command: "ls --color=" + pathologicalWord, Cwd: ws, WorkspaceRoots: []string{ws},
	})
	assertBoundaryLimitAsk(t, res)
}

func TestFastPath_OverLimitTargetAsks(t *testing.T) {
	ws := limitWorkspace(t)
	res := NewDefaultFilter().Evaluate(&harness.NormalizedToolCall{
		ToolName:       "Read",
		TargetPath:     filepath.Join(ws, pathologicalWord),
		RawArgs:        map[string]interface{}{"file_path": filepath.Join(ws, pathologicalWord)},
		Cwd:            ws,
		WorkspaceRoots: []string{ws},
	})
	assertBoundaryLimitAsk(t, res)
}

func TestFastPath_OverLimitSensitiveCandidateFailsClosed(t *testing.T) {
	ws := limitWorkspace(t)
	filter := NewDefaultFilter()
	target := filepath.Join(ws, pathologicalWord)
	if _, err := filter.checkResolvedSensitive(target, "", ws); !errors.Is(err, boundary.ErrPathTooLong) {
		t.Fatalf("checkResolvedSensitive err = %v, want ErrPathTooLong", err)
	}
	call := &harness.NormalizedToolCall{ToolName: "Write", TargetPath: target, Cwd: ws}
	if reason := filter.SensitiveReason(call); reason == "" {
		t.Fatal("SensitiveReason must not clear a path it could not resolve")
	}
}

// budgetForTrees is a work budget that fits about n resolutions of a depth-deep tree of
// one-letter directories under parent, so a test can exhaust it with shallow trees.
func budgetForTrees(parent string, depth, n int) int64 {
	return int64(n * depth * (len(parent) + depth + 2))
}

// Review of PR #79: with 1,500 existing nested directories, `echo <nested>/z0 ... <nested>/z99`
// (each word under the length limit) took 86.8 s and ended ALLOW; ten words took 7.6 s. The
// shared prefix is now resolved once per evaluation, so the call is cheap and stays trusted.
// 500 levels (fewer where the platform's path limit is lower) are enough: walking the prefix
// once per word would cost about 30 MiB of lookups, far over the budget.
func TestFastPath_ManyWordsUnderDeepExistingPrefix(t *testing.T) {
	ws := limitWorkspace(t)
	dir, _ := testpaths.DeepDirs(t, ws, 500, 16)
	rel, err := filepath.Rel(ws, dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("echo")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, " %s/z%d", filepath.ToSlash(rel), i)
	}
	call := &harness.NormalizedToolCall{ToolName: "Bash", Command: b.String(), Cwd: ws, WorkspaceRoots: []string{ws}}
	start := time.Now()
	res := NewDefaultFilter().Evaluate(call)
	elapsed := time.Since(start)
	if elapsed > 2*time.Second { // was 87 s
		t.Errorf("100 deep words took %v", elapsed)
	}
	if res == nil || res.Decision != harness.DecisionAllow || res.Source != "fastpath_trusted" {
		t.Fatalf("expected trusted ALLOW for in-workspace words, got %+v", res)
	}
	t.Logf("100 words, %d bytes: %v", len(call.Command), elapsed)
}

// Words under distinct deep trees share no prefix to reuse. The evaluation's resolution
// budget bounds them, and running out of it asks instead of allowing. The budget is lowered
// to about three trees, so the trees can be shallow.
func TestFastPath_ExhaustedResolutionBudgetAsks(t *testing.T) {
	ws := limitWorkspace(t)
	const depth = 40
	t.Cleanup(boundary.SetWorkBudgetForTesting(budgetForTrees(filepath.Join(ws, "0"), depth, 3)))
	var b strings.Builder
	b.WriteString("echo")
	for i := 0; i < 8; i++ {
		dir := testpaths.NestedDirs(t, filepath.Join(ws, fmt.Sprint(i)), depth)
		rel, err := filepath.Rel(ws, dir)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, " %s/z", filepath.ToSlash(rel))
	}
	call := &harness.NormalizedToolCall{ToolName: "Bash", Command: b.String(), Cwd: ws, WorkspaceRoots: []string{ws}}
	start := time.Now()
	res := NewDefaultFilter().Evaluate(call)
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Errorf("evaluation took %v", elapsed)
	}
	if res == nil || res.Decision != harness.DecisionAsk || res.Source != sourceBoundaryLimit {
		t.Fatalf("expected ASK from %s, got %+v", sourceBoundaryLimit, res)
	}
	t.Logf("8 distinct trees: %v, %s", elapsed, res.Reason)
	if !strings.Contains(res.Reason, "budget") {
		t.Errorf("reason does not name the budget: %s", res.Reason)
	}
}

// A read of ws/link/../f, link -> an outside directory, reads the f next to link's target. Its
// cleaned spelling ws/f is inside the workspace; the resolved path is not.
func TestFastPath_DotDotAfterSymlinkLeavesWorkspace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Win32 removes .. lexically")
	}
	ws := limitWorkspace(t)
	outside := limitWorkspace(t)
	if err := os.Mkdir(filepath.Join(outside, "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "deep"), filepath.Join(ws, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, dir := range []string{ws, outside} {
		if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{ws + "/link/../f", "link/../f"} {
		res := NewDefaultFilter().Evaluate(&harness.NormalizedToolCall{
			ToolName:       "Read",
			TargetPath:     target,
			RawArgs:        map[string]interface{}{"file_path": target},
			Cwd:            ws,
			WorkspaceRoots: []string{ws},
		})
		if res != nil && res.Decision == harness.DecisionAllow {
			t.Errorf("Read %s (reads %s) = %+v, want no ALLOW", target, filepath.Join(outside, "f"), res)
		}
	}
}
