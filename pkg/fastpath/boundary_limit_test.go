package fastpath

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
