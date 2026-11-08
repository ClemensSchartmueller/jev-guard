package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	// Spend the evaluation's budget on distinct deep trees, then check an ordinary path.
	end := boundary.BeginEvaluation()
	defer end()
	exhausted := false
	for i := 0; i < 10 && !exhausted; i++ {
		dir := filepath.Join(ws, fmt.Sprint(i), strings.TrimSuffix(strings.Repeat("a"+string(filepath.Separator), 1500), string(filepath.Separator)))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
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
