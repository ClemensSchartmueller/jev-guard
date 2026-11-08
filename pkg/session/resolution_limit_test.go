package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"jev-guard/internal/testpaths"
	"jev-guard/pkg/boundary"
)

// A path that cannot be canonicalized because a resolution limit was reached could be an
// alias of the jev-guard directory. Anti-tampering is an unconditional DENY, so such a path
// counts as a jev-guard path instead of falling through to an overridable ASK.
func TestIsJevguardPathFailsClosedOnResolutionLimits(t *testing.T) {
	setupTestJevguardDir(t)
	ws, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ordinary := filepath.Join(ws, "file.txt")
	if IsJevguardPath(ordinary) {
		t.Fatalf("%s reported as a jev-guard path", ordinary)
	}

	overLimit := filepath.Join(ws, strings.Repeat("d", boundary.MaxResolvePathLength()), "marker")
	if !IsJevguardPath(overLimit) {
		t.Error("over-limit path is not treated as a possible jev-guard path")
	}

	// Spend the evaluation's budget (lowered, so the trees can be shallow) on distinct trees,
	// then check an ordinary path.
	const depth = 40
	t.Cleanup(boundary.SetWorkBudgetForTesting(int64(3 * depth * (len(ws) + depth + 4))))
	end := boundary.BeginEvaluation()
	defer end()
	exhausted := false
	for i := 0; i < 10 && !exhausted; i++ {
		dir := testpaths.NestedDirs(t, filepath.Join(ws, fmt.Sprint(i)), depth)
		_, err := boundary.CanonicalizePath(filepath.Join(dir, "z"))
		exhausted = errors.Is(err, boundary.ErrWorkBudgetExhausted)
	}
	if !exhausted {
		t.Fatal("budget not exhausted")
	}
	if !IsJevguardPath(ordinary) {
		t.Error("path checked after the budget ran out is not treated as a possible jev-guard path")
	}
}

// ".." after a symlink applies to the symlink's target, as in the OS: ws/link/../state.json
// with link -> <jev-guard dir>/sub names a file in the jev-guard directory, although its
// cleaned spelling ws/state.json does not. Cleaning before resolution used to miss it.
func TestIsJevguardPathAppliesDotDotAfterSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Win32 removes .. lexically")
	}
	home, err := filepath.EvalSymlinks(setupTestJevguardDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JEV_GUARD_HOME", home)
	if err := os.Mkdir(filepath.Join(home, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	ws, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "sub"), filepath.Join(ws, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if IsJevguardPath(filepath.Join(ws, "state.json")) {
		t.Fatal("test premise: the workspace file is not a jev-guard path")
	}
	if p := ws + "/link/../state.json"; !IsJevguardPath(p) {
		t.Errorf("%s (opens %s) is not treated as a jev-guard path", p, filepath.Join(home, "state.json"))
	}
}
