package boundary

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
)

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

// lowerBudget sets the work budget for the test.
func lowerBudget(t *testing.T, n int64) {
	t.Helper()
	t.Cleanup(SetWorkBudgetForTesting(n))
}

// walkCost is what resolving p costs in a fresh evaluation.
func walkCost(t *testing.T, p string) int64 {
	t.Helper()
	e := newEvaluation()
	if _, err := e.resolve(p, false); err != nil {
		t.Fatal(err)
	}
	return workBudget - e.remaining
}

// Review of PR #79: 1,500 existing nested directories and ten ~3 KB words below them took
// 7.6 s to resolve (100 words: 87 s), each word under the length limit. Within one evaluation
// the shared prefix is walked once and every further word costs a lookup or two. The depth is
// the point here, so the tree is as deep as the platform's path limit allows (macOS: ~450).
func TestDeepExistingPrefixIsWalkedOncePerEvaluation(t *testing.T) {
	ws := realTempDir(t)
	dir, _ := testpaths.DeepDirs(t, ws, 1500, 16)
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
		if !samePath(got, word) {
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

// samePath compares resolved paths as the platform does (Windows ignores case).
func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// Windows normalizes every resolved path (case, short names) as filepath.EvalSymlinks does.
// That used to be one more full walk per word, charged to the shared budget: a single
// 1,500-deep path, or words under one deep prefix, exhausted the budget on Windows only.
// Normalization is now cached per prefix and charged to its own budget, so it never costs
// more than the walk. A fake normBase exercises the Windows code path on every OS.
func TestNormalizationIsCachedPerPrefix(t *testing.T) {
	ws := realTempDir(t)
	dir := testpaths.NestedDirs(t, ws, testpaths.Depth(ws, 200, 16))
	if err := os.WriteFile(filepath.Join(dir, "f0"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	orig := normBase
	normCalls := 0
	normBase = func(p string) (string, error) {
		normCalls++
		return strings.ToUpper(filepath.Base(p)), nil
	}
	t.Cleanup(func() { normBase = orig })

	e := newEvaluation()
	upper := func(p string) string {
		vol, n := volumePrefix(p)
		return normVolumeName(vol) + vol[len(filepath.VolumeName(vol)):] + strings.ToUpper(p[n:])
	}
	for i := 0; i < 100; i++ {
		word := filepath.Join(dir, fmt.Sprintf("f%d", i)) // f0 exists, the rest do not
		got, err := e.resolve(word, false)
		if err != nil {
			t.Fatalf("word %d: %v", i, err)
		}
		want := upper(dir) + string(filepath.Separator) + fmt.Sprintf("f%d", i)
		if i == 0 {
			want = upper(word)
		}
		if got != want {
			t.Fatalf("word %d = %.80s..., want %.80s...", i, got, want)
		}
	}
	walked, normalizedCost := workBudget-e.remaining, workBudget-e.normRemaining
	if normalizedCost > walked {
		t.Errorf("normalization cost %d, more than the walk's %d", normalizedCost, walked)
	}
	if depth := strings.Count(dir, string(filepath.Separator)); normCalls > depth+1 {
		t.Errorf("%d normalization lookups for a %d-deep prefix and one existing word", normCalls, depth)
	}
}

// Distinct deep trees share no prefix, so the budget is what bounds them: the evaluation
// stops with ErrWorkBudgetExhausted once its budget of lookups is spent. The budget is
// lowered to what two and a half trees cost, so the trees can be shallow.
func TestWorkBudgetIsSharedAcrossPathsOfAnEvaluation(t *testing.T) {
	ws := realTempDir(t)
	var words []string
	for i := 0; i < 6; i++ {
		words = append(words, filepath.Join(testpaths.NestedDirs(t, filepath.Join(ws, fmt.Sprint(i)), 40), "z"))
	}
	budget := walkCost(t, words[0]) * 5 / 2
	lowerBudget(t, budget)
	resolver, err := NewResolver([]string{ws}, ws)
	if err != nil {
		t.Fatal(err)
	}
	_, bytes := countLookupBytes(t)
	end := BeginEvaluation()
	var limitErr error
	resolved := 0
	for _, w := range words {
		if _, err := resolver.IsPathContained(w, ws); err != nil {
			limitErr = err
			break
		}
		resolved++
	}
	end()

	if !errors.Is(limitErr, ErrWorkBudgetExhausted) || !errors.Is(limitErr, ErrResolutionLimit) {
		t.Fatalf("err = %v, want ErrWorkBudgetExhausted matching ErrResolutionLimit", limitErr)
	}
	if errors.Is(limitErr, ErrPathTooLong) {
		t.Error("a budget error must not claim the path is too long")
	}
	if resolved != 2 {
		t.Errorf("%d trees resolved within a budget of two and a half", resolved)
	}
	if int64(*bytes) > budget {
		t.Errorf("looked up %d bytes, budget %d", *bytes, budget)
	}

	// Outside the evaluation each resolution has a budget of its own again.
	if _, err := CanonicalizePath(words[len(words)-1]); err != nil {
		t.Errorf("a fresh resolution failed: %v", err)
	}
}

// A chain of symlinks, each into a deep directory, used to multiply the walk by up to 255
// hops inside one filepath.EvalSymlinks call. The metered walk stops at the budget (lowered,
// so the directory can be shallow).
func TestSymlinkChainIsBoundedByBudget(t *testing.T) {
	ws := realTempDir(t)
	dir := testpaths.NestedDirs(t, ws, 30)
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
	// Each hop walks the whole directory again; the budget fits a tenth of the hops.
	lowerBudget(t, walkCost(t, dir)*hops/10)

	start := time.Now()
	_, err := CanonicalizePath(filepath.Join(link, "x"))
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("resolving the chain took %v", elapsed)
	}
	if !errors.Is(err, ErrWorkBudgetExhausted) {
		t.Fatalf("err = %v, want ErrWorkBudgetExhausted", err)
	}
}

// filepath.EvalSymlinks follows at most 255 symlinks; so does the walk.
func TestLinkCountMatchesFilepath(t *testing.T) {
	ws := realTempDir(t)
	if err := os.Mkdir(filepath.Join(ws, "end"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 255; i >= 0; i-- {
		target := "end"
		if i < 255 {
			target = fmt.Sprintf("l%d", i+1)
		}
		if err := os.Symlink(target, filepath.Join(ws, fmt.Sprintf("l%d", i))); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	for _, i := range []int{0, 1, 2} { // 256, 255 and 254 links
		p := filepath.Join(ws, fmt.Sprintf("l%d", i))
		_, want := filepath.EvalSymlinks(p)
		_, got := EvalSymlinks(p)
		if (want == nil) != (got == nil) {
			t.Errorf("%d links: filepath.EvalSymlinks error %v, EvalSymlinks error %v", 256-i, want, got)
		}
	}
}

// Overlapping scopes: the scope ends when the last holder ends it, so a later evaluation never
// gets a fresh budget while an earlier one is still running. Each end function counts once.
func TestOverlappingScopesShareOneBudgetUntilTheLastEnds(t *testing.T) {
	a := BeginEvaluation()
	e := active
	b := BeginEvaluation()
	if active != e {
		t.Fatal("the second scope did not join the first")
	}
	a()
	a() // a second call of the same end function is a no-op
	if active != e {
		t.Fatal("ending the first scope ended the scope the second still holds")
	}
	_, _ = withEvaluation(func(got *evaluation) (string, error) {
		if got != e {
			t.Error("a resolution in the remaining scope got a fresh budget")
		}
		return "", nil
	})
	b()
	if active != nil {
		t.Fatal("scope still active after every holder ended it")
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

// The metered walk must resolve exactly as filepath.EvalSymlinks, ".." after a symlink and
// trailing separators included; CanonicalizePath as the deepest prefix filepath.EvalSymlinks
// resolves plus the rest, except that a dangling symlink resolves to its target.
func TestWalkMatchesFilepathEvalSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Win32 removes .. lexically; the walk cleans first there (TestWindowsCleansLexically)")
	}
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
	mk(filepath.Join(outside, "deep"))
	if err := os.WriteFile(filepath.Join(ws, "d", "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link(outside, filepath.Join(ws, "abs"))
	link(filepath.Join(outside, "deep"), filepath.Join(ws, "todeep"))
	link(filepath.Join("..", "d", "e"), filepath.Join(ws, "d", "rel"))
	link("rel", filepath.Join(ws, "d", "chain"))
	link(filepath.Join(outside, "missing"), filepath.Join(ws, "dangling"))
	link("loop", filepath.Join(ws, "loop"))
	link(filepath.Join("e", "..", "file"), filepath.Join(ws, "d", "tofile"))
	link(filepath.Join("..", "..", "..", filepath.Base(outside), "o"), filepath.Join(ws, "d", "e", "up"))

	s := string(filepath.Separator)
	inputs := []struct {
		in    string
		canon string // CanonicalizePath's result when it is not reference(in)
	}{
		{in: ws},
		{in: ws + s},
		{in: filepath.Join(ws, "d", "e")},
		{in: filepath.Join(ws, "d", "e") + s},
		{in: filepath.Join(ws, "d", "e") + s + "." + s},
		{in: filepath.Join(ws, "abs", "o", "p")},
		{in: filepath.Join(ws, "abs", "o", "new", "deeper")},
		{in: filepath.Join(ws, "d", "rel")},
		{in: filepath.Join(ws, "d", "chain", "x")},
		{in: filepath.Join(ws, "dangling"), canon: filepath.Join(outside, "missing")},
		{in: filepath.Join(ws, "dangling", "x"), canon: filepath.Join(outside, "missing", "x")},
		{in: filepath.Join(ws, "loop", "x")},
		{in: filepath.Join(ws, "d", "tofile")},
		{in: filepath.Join(ws, "d", "tofile", "child")},
		{in: filepath.Join(ws, "d", "file", "child")},
		{in: filepath.Join(ws, "d", "file") + s, canon: filepath.Join(ws, "d", "file")},
		{in: filepath.Join(ws, "d", "file") + s + ".", canon: filepath.Join(ws, "d", "file")},
		{in: filepath.Join(ws, "d", "e", "up", "p")},
		{in: filepath.Join(ws, "missing", "a", "b")},
		// ".." applies to what the symlink before it resolved to, as the OS does.
		{in: ws + s + "todeep" + s + ".." + s + "file", canon: filepath.Join(outside, "file")},
		{in: ws + s + "todeep" + s + ".." + s + "new", canon: filepath.Join(outside, "new")},
		{in: ws + s + "abs" + s + ".." + s + filepath.Base(ws) + s + "file", canon: filepath.Join(ws, "file")},
		{in: ws + s + "d" + s + "e" + s + "up" + s + ".." + s + "o" + s + "p", canon: filepath.Join(outside, "o", "p")},
		{in: ws + s + "d" + s + "rel" + s + ".." + s + "file", canon: filepath.Join(ws, "d", "file")},
		{in: ws + s + "d" + s + "file" + s + ".." + s + "e", canon: filepath.Join(ws, "d", "e")},
		{in: ws + s + "new" + s + ".." + s + "todeep" + s + ".." + s + "file", canon: filepath.Join(outside, "file")},
		{in: ws + s + "dangling" + s + ".." + s + "file", canon: filepath.Join(outside, "file")},
		{in: ws + s + "d" + s + ".." + s + "d" + s + "e"},
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
		for _, c := range inputs {
			in := c.in
			want, wantErr := filepath.EvalSymlinks(in)
			got, err := EvalSymlinks(in)
			if (err == nil) != (wantErr == nil) || (err == nil && got != filepath.Clean(want)) {
				t.Errorf("pass %d: EvalSymlinks(%s) = %q, %v; want %q, %v", pass, in, got, err, want, wantErr)
			}
			ref := c.canon
			if ref == "" {
				ref = reference(in)
			}
			canon, err := CanonicalizePath(in)
			if err != nil {
				t.Errorf("pass %d: CanonicalizePath(%s): %v", pass, in, err)
			} else if canon != ref {
				t.Errorf("pass %d: CanonicalizePath(%s) = %q, want %q", pass, in, canon, ref)
			}
		}
	}
}

// A relative input keeps its ".." too: it is joined to the working directory, not cleaned.
func TestRelativeInputKeepsDotDot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Win32 removes .. lexically")
	}
	ws := realTempDir(t)
	outside := realTempDir(t)
	if err := os.Mkdir(filepath.Join(outside, "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "deep"), filepath.Join(ws, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	chdir(t, ws)
	for _, resolve := range []func(string) (string, error){EvalSymlinks, CanonicalizePath} {
		got, err := resolve("link/../file")
		if err != nil || got != filepath.Join(outside, "file") {
			t.Errorf("resolve(link/../file) = %q, %v; want %q", got, err, filepath.Join(outside, "file"))
		}
	}
	r, _ := NewResolver([]string{ws}, ws)
	if ok, err := r.IsPathContained("link/../file", ws); ok || err != nil {
		t.Errorf("IsPathContained(link/../file) = %v, %v; want false (the OS opens %s)", ok, err, filepath.Join(outside, "file"))
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

// Win32 removes "." and ".." lexically before the filesystem sees a path, so on Windows
// "link\..\file" is the file next to the link, and the walk cleans the input as Win32 does.
func TestWindowsCleansLexically(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows path semantics")
	}
	ws := realTempDir(t)
	outside := realTempDir(t)
	if err := os.Mkdir(filepath.Join(outside, "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{ws, outside} {
		if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(outside, "deep"), filepath.Join(ws, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	in := ws + `\link\..\file`
	data, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(ws, "file")
	if err := os.WriteFile(want, []byte("ws"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, _ = os.ReadFile(in); string(data) != "ws" {
		t.Fatalf("Windows opened %q for %s, not the file next to the link", data, in)
	}
	got, err := EvalSymlinks(in)
	if err != nil || !strings.EqualFold(got, want) {
		t.Errorf("EvalSymlinks(%s) = %q, %v; want %q", in, got, err, want)
	}
}
