package boundary

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// deepDir creates depth nested directories named "a" under parent and returns the deepest.
func deepDir(t *testing.T, parent string, depth int) string {
	t.Helper()
	dir := filepath.Join(parent, strings.TrimSuffix(strings.Repeat("a"+string(filepath.Separator), depth), string(filepath.Separator)))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// countLookupBytes wraps the lstat seam to count lookups and the path bytes they pass.
func countLookupBytes(t *testing.T) (calls, bytes *int) {
	t.Helper()
	c, b := 0, 0
	orig := lstat
	lstat = func(p string) (os.FileInfo, error) {
		c++
		b += len(p)
		return orig(p)
	}
	t.Cleanup(func() { lstat = orig })
	return &c, &b
}

// Review of PR #79: 1,500 existing nested directories and ten ~3 KB words below them took
// 7.6 s to resolve (100 words: 87 s), each word under the length limit. Within one evaluation
// the shared prefix is walked once and every further word costs a lookup or two.
func TestDeepExistingPrefixIsWalkedOncePerEvaluation(t *testing.T) {
	ws := realTempDir(t)
	dir := deepDir(t, ws, 1500)
	if len(dir) > MaxResolvePathLength()-8 {
		t.Skipf("temp dir too long for the test: %d bytes", len(dir))
	}
	calls, bytes := countLookupBytes(t)
	end := BeginEvaluation()
	defer end()

	start := time.Now()
	for i := 0; i < 100; i++ {
		word := filepath.Join(dir, fmt.Sprintf("z%d", i))
		got, err := CanonicalizePath(word)
		if err != nil {
			t.Fatalf("word %d: %v", i, err)
		}
		if got != word {
			t.Fatalf("word %d resolved to %.80s...", i, got)
		}
		if i == 0 {
			t.Logf("first word: %d lookups, %d bytes", *calls, *bytes)
		}
	}
	elapsed := time.Since(start)
	depth := strings.Count(dir, string(filepath.Separator))
	// One walk of the prefix, then one lookup per word.
	if max := depth + 1 + 100; *calls > max {
		t.Errorf("%d lookups for 100 words under a %d-deep prefix, want at most %d", *calls, depth, max)
	}
	if elapsed > 2*time.Second {
		t.Errorf("100 deep words took %v", elapsed)
	}
	t.Logf("100 words: %d lookups, %d bytes, %v", *calls, *bytes, elapsed)
}

// Distinct deep trees share no prefix, so the budget is what bounds them: the evaluation
// stops with ErrWorkBudgetExhausted once WorkBudget of lookups are spent.
func TestWorkBudgetIsSharedAcrossPathsOfAnEvaluation(t *testing.T) {
	ws := realTempDir(t)
	var words []string
	for i := 0; i < 6; i++ {
		words = append(words, filepath.Join(deepDir(t, filepath.Join(ws, fmt.Sprint(i)), 1500), "z"))
	}
	resolver, err := NewResolver([]string{ws}, ws)
	if err != nil {
		t.Fatal(err)
	}
	_, bytes := countLookupBytes(t)
	end := BeginEvaluation()
	start := time.Now()
	var limitErr error
	for _, w := range words {
		if _, err := resolver.IsPathContained(w, ws); err != nil {
			limitErr = err
			break
		}
	}
	elapsed := time.Since(start)
	end()

	if !errors.Is(limitErr, ErrWorkBudgetExhausted) || !errors.Is(limitErr, ErrResolutionLimit) {
		t.Fatalf("err = %v, want ErrWorkBudgetExhausted matching ErrResolutionLimit", limitErr)
	}
	if errors.Is(limitErr, ErrPathTooLong) {
		t.Error("a budget error must not claim the path is too long")
	}
	if *bytes > WorkBudget {
		t.Errorf("looked up %d bytes, budget %d", *bytes, WorkBudget)
	}
	if elapsed > 2*time.Second {
		t.Errorf("exhausting the budget took %v", elapsed)
	}

	// Outside the evaluation each resolution has a budget of its own again.
	if _, err := CanonicalizePath(words[len(words)-1]); err != nil {
		t.Errorf("a fresh resolution failed: %v", err)
	}
}

// A chain of symlinks, each into a deep directory, used to multiply the walk by up to 255
// hops inside one filepath.EvalSymlinks call. The metered walk stops at the budget.
func TestSymlinkChainIsBoundedByBudget(t *testing.T) {
	ws := realTempDir(t)
	dir := deepDir(t, ws, 1500)
	const hops = 200
	for i := 0; i < hops; i++ {
		if err := os.Symlink(filepath.Join(dir, fmt.Sprintf("l%d", i+1)), filepath.Join(dir, fmt.Sprintf("l%d", i))); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, fmt.Sprintf("l%d", hops)), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(ws, "start")
	if err := os.Symlink(filepath.Join(dir, "l0"), link); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err := CanonicalizePath(filepath.Join(link, "x"))
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("resolving the chain took %v", elapsed)
	}
	if !errors.Is(err, ErrWorkBudgetExhausted) {
		t.Fatalf("err = %v, want ErrWorkBudgetExhausted", err)
	}
}

func TestNestedBeginEvaluationJoinsTheOuterScope(t *testing.T) {
	end := BeginEvaluation()
	outer := active
	inner := BeginEvaluation()
	if active != outer {
		t.Fatal("nested BeginEvaluation replaced the outer scope")
	}
	inner()
	if active != outer {
		t.Fatal("ending a nested scope ended the outer one")
	}
	end()
	if active != nil {
		t.Fatal("scope still active after end")
	}
}

// The metered walk must resolve exactly as before: EvalSymlinks as filepath.EvalSymlinks,
// and CanonicalizePath as the deepest prefix filepath.EvalSymlinks resolves plus the rest.
func TestWalkMatchesFilepathEvalSymlinks(t *testing.T) {
	ws := realTempDir(t)
	outside := realTempDir(t)
	mk := func(p string) {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, name string) {
		if err := os.Symlink(target, name); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	mk(filepath.Join(ws, "d", "e"))
	mk(filepath.Join(outside, "o", "p"))
	if err := os.WriteFile(filepath.Join(ws, "d", "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link(outside, filepath.Join(ws, "abs"))
	link(filepath.Join("..", "d", "e"), filepath.Join(ws, "d", "rel"))
	link("rel", filepath.Join(ws, "d", "chain"))
	link(filepath.Join(outside, "missing"), filepath.Join(ws, "dangling"))
	link("loop", filepath.Join(ws, "loop"))
	link(filepath.Join("e", "..", "file"), filepath.Join(ws, "d", "tofile"))
	link(filepath.Join("..", "..", filepath.Base(outside), "o"), filepath.Join(ws, "d", "e", "up"))

	inputs := []string{
		ws,
		filepath.Join(ws, "d", "e"),
		filepath.Join(ws, "abs", "o", "p"),
		filepath.Join(ws, "abs", "o", "new", "deeper"),
		filepath.Join(ws, "d", "rel"),
		filepath.Join(ws, "d", "chain", "x"),
		filepath.Join(ws, "dangling"),
		filepath.Join(ws, "dangling", "x"),
		filepath.Join(ws, "loop", "x"),
		filepath.Join(ws, "d", "tofile"),
		filepath.Join(ws, "d", "tofile", "child"),
		filepath.Join(ws, "d", "file", "child"),
		filepath.Join(ws, "d", "e", "up", "p"),
		filepath.Join(ws, "missing", "a", "b"),
	}
	reference := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Clean(r)
		}
		for dir := filepath.Dir(p); ; dir = filepath.Dir(dir) {
			if r, err := filepath.EvalSymlinks(dir); err == nil {
				rel, _ := filepath.Rel(dir, p)
				return filepath.Join(r, rel)
			}
			if filepath.Dir(dir) == dir {
				return p
			}
		}
	}
	end := BeginEvaluation()
	defer end()
	for pass := 0; pass < 2; pass++ { // the second pass starts from cached prefixes
		for _, in := range inputs {
			want, wantErr := filepath.EvalSymlinks(in)
			got, err := EvalSymlinks(in)
			if (err == nil) != (wantErr == nil) || (err == nil && got != filepath.Clean(want)) {
				t.Errorf("pass %d: EvalSymlinks(%s) = %q, %v; want %q, %v", pass, in, got, err, want, wantErr)
			}
			canon, err := CanonicalizePath(in)
			if err != nil {
				t.Errorf("pass %d: CanonicalizePath(%s): %v", pass, in, err)
			} else if ref := reference(in); canon != ref {
				t.Errorf("pass %d: CanonicalizePath(%s) = %q, want %q", pass, in, canon, ref)
			}
		}
	}
}
