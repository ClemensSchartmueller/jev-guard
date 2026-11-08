package boundary

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// countEvalSymlinks replaces the evalSymlinks seam with one that counts calls.
func countEvalSymlinks(t *testing.T) *int {
	t.Helper()
	calls := 0
	orig := evalSymlinks
	evalSymlinks = func(p string) (string, error) {
		calls++
		return orig(p)
	}
	t.Cleanup(func() { evalSymlinks = orig })
	return &calls
}

// fakeEvalSymlinks resolves exactly the given paths (and nothing else). The map
// must be closed under prefixes, as the real filesystem is for cleaned paths.
func fakeEvalSymlinks(t *testing.T, resolved map[string]string) *int {
	t.Helper()
	calls := 0
	orig := evalSymlinks
	evalSymlinks = func(p string) (string, error) {
		calls++
		if real, ok := resolved[p]; ok {
			return real, nil
		}
		return "", os.ErrNotExist
	}
	t.Cleanup(func() { evalSymlinks = orig })
	return &calls
}

func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestMaxResolvePathBytesForOS(t *testing.T) {
	if got := maxResolvePathBytesForOS("windows"); got != 32767 {
		t.Errorf("windows limit = %d, want 32767", got)
	}
	for _, goos := range []string{"linux", "darwin", "freebsd"} {
		if got := maxResolvePathBytesForOS(goos); got != 4096 {
			t.Errorf("%s limit = %d, want 4096", goos, got)
		}
	}
}

// TestPathologicalPathIsBoundedAndNotContained is the regression test for issue #72: a
// 64 KiB path of missing components used to take ~14 s and ended in ALLOW.
func TestPathologicalPathIsBoundedAndNotContained(t *testing.T) {
	ws := realTempDir(t)
	resolver, err := NewResolver([]string{ws}, ws)
	if err != nil {
		t.Fatal(err)
	}
	calls := countEvalSymlinks(t)
	word := strings.Repeat("a/", 32*1024) // 64 KiB, inside the workspace lexically

	start := time.Now()
	contained, err := resolver.IsPathContained(word, ws)
	elapsed := time.Since(start)

	if contained {
		t.Fatal("over-limit path reported as contained")
	}
	if !errors.Is(err, ErrPathTooLong) {
		t.Fatalf("err = %v, want ErrPathTooLong", err)
	}
	if strings.Contains(err.Error(), "a/a/a/") {
		t.Errorf("error repeats the path: %.80s...", err.Error())
	}
	if *calls != 0 {
		t.Errorf("over-limit path made %d EvalSymlinks calls, want 0", *calls)
	}
	if elapsed > time.Second {
		t.Errorf("rejecting a 64 KiB path took %v", elapsed)
	}
}

// TestDeepMissingTailUsesLogarithmicLookups checks the work bound inside the limit: the
// deepest existing ancestor is found by binary search, not one parent at a time.
func TestDeepMissingTailUsesLogarithmicLookups(t *testing.T) {
	ws := realTempDir(t)
	budget := MaxResolvePathBytes() - len(ws) - 2
	components := budget / 2
	tail := strings.TrimSuffix(strings.Repeat("a"+string(filepath.Separator), components), string(filepath.Separator))
	target := ws + string(filepath.Separator) + tail
	if len(target) > MaxResolvePathBytes() {
		t.Fatalf("test path is %d bytes, over the limit", len(target))
	}
	calls := countEvalSymlinks(t)

	got, err := CanonicalizePath(target)
	if err != nil {
		t.Fatalf("CanonicalizePath: %v", err)
	}
	if got != filepath.Clean(target) {
		t.Errorf("got %.80s..., want the path as written", got)
	}
	separators := strings.Count(target, string(filepath.Separator))
	maxCalls := 2
	for n := 1; n < separators+1; n *= 2 {
		maxCalls++
	}
	if *calls > maxCalls {
		t.Errorf("%d EvalSymlinks calls for %d components, want at most %d", *calls, separators, maxCalls)
	}
}

func TestResolveExistingAndMissing(t *testing.T) {
	ws := realTempDir(t)
	existing := filepath.Join(ws, "src", "pkg")
	if err := os.MkdirAll(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		ws:                                ws,
		existing:                          existing,
		filepath.Join(existing, "new.go"): filepath.Join(existing, "new.go"),
		filepath.Join(ws, "missing", "deeper", "file.txt"):                              filepath.Join(ws, "missing", "deeper", "file.txt"),
		strings.Join([]string{existing, "x", "..", "y.go"}, string(filepath.Separator)): filepath.Join(existing, "y.go"),
		filepath.Join(ws, "src") + string(filepath.Separator):                           filepath.Join(ws, "src"),
	}
	for in, want := range cases {
		got, err := CanonicalizePath(in)
		if err != nil {
			t.Errorf("CanonicalizePath(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("CanonicalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveRelativePath(t *testing.T) {
	ws := realTempDir(t)
	if err := os.MkdirAll(filepath.Join(ws, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(ws); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	got, err := CanonicalizePath(filepath.Join("src", "missing", "f.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(ws, "src", "missing", "f.txt"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	resolver, err := NewResolver([]string{ws}, ws)
	if err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]bool{
		"src/missing/f.txt":     true,
		"../outside/f.txt":      false,
		"src/../../outside.txt": false,
	} {
		contained, err := resolver.IsPathContained(rel, ws)
		if err != nil {
			t.Errorf("IsPathContained(%q): %v", rel, err)
		}
		if contained != want {
			t.Errorf("IsPathContained(%q) = %t, want %t", rel, contained, want)
		}
	}
}

func TestResolveSymlinkedAncestorWithMissingTail(t *testing.T) {
	ws := realTempDir(t)
	outside := realTempDir(t)
	link := filepath.Join(ws, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	target := filepath.Join(link, "a", "b", "new.txt")

	got, err := CanonicalizePath(target)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(outside, "a", "b", "new.txt"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	resolver, err := NewResolver([]string{ws}, ws)
	if err != nil {
		t.Fatal(err)
	}
	contained, err := resolver.IsPathContained(target, ws)
	if err != nil {
		t.Fatal(err)
	}
	if contained {
		t.Error("path through a symlink out of the workspace reported as contained")
	}
}

func TestResolveFileAncestor(t *testing.T) {
	ws := realTempDir(t)
	file := filepath.Join(ws, "file.txt")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := CanonicalizePath(filepath.Join(file, "child"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(file, "child"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestResolveSymlinksFake exercises the ancestor search on fixed path shapes, including
// Windows drive and UNC paths, which only parse as such on Windows.
func TestResolveSymlinksFake(t *testing.T) {
	type tc struct {
		name     string
		in       string
		resolved map[string]string
		want     string
	}
	var cases []tc
	if runtime.GOOS == "windows" {
		cases = []tc{
			{"drive root only", `C:\ws\a\b`, map[string]string{`C:\`: `C:\`}, `C:\ws\a\b`},
			{"drive symlinked ancestor", `C:\ws\link\a\b`,
				map[string]string{`C:\`: `C:\`, `C:\ws`: `C:\ws`, `C:\ws\link`: `D:\real`}, `D:\real\a\b`},
			{"unc", `\\srv\share\ws\a`,
				map[string]string{`\\srv\share\`: `\\srv\share\`, `\\srv\share\ws`: `\\srv\share\ws`}, `\\srv\share\ws\a`},
			{"nothing resolves", `C:\ws\a`, map[string]string{}, `C:\ws\a`},
		}
	} else {
		cases = []tc{
			{"root only", "/ws/a/b", map[string]string{"/": "/"}, "/ws/a/b"},
			{"symlinked ancestor", "/ws/link/a/b",
				map[string]string{"/": "/", "/ws": "/ws", "/ws/link": "/real"}, "/real/a/b"},
			{"link to root", "/ws/link/a",
				map[string]string{"/": "/", "/ws": "/ws", "/ws/link": "/"}, "/a"},
			{"whole path", "/ws/a", map[string]string{"/": "/", "/ws": "/ws", "/ws/a": "/other"}, "/other"},
			{"nothing resolves", "/ws/a", map[string]string{}, "/ws/a"},
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeEvalSymlinks(t, c.resolved)
			if got := resolveSymlinks(c.in); got != c.want {
				t.Errorf("resolveSymlinks(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestOverLimitDeclaredRootDoesNotFallBackToCwd(t *testing.T) {
	ws := realTempDir(t)
	longRoot := filepath.Join(ws, strings.Repeat("r", MaxResolvePathBytes()))
	resolver, err := NewResolver([]string{longRoot}, ws)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolver.WorkspaceRoots) != 0 {
		t.Fatalf("roots = %v, want none", resolver.WorkspaceRoots)
	}
	contained, err := resolver.IsPathContained(filepath.Join(ws, "f.txt"), ws)
	if err != nil {
		t.Fatal(err)
	}
	if contained {
		t.Error("path contained although the only declared root could not be resolved")
	}
}

func TestOverLimitCwdHasNoRoot(t *testing.T) {
	ws := realTempDir(t)
	longCwd := filepath.Join(ws, strings.Repeat("c", MaxResolvePathBytes()))
	if root := FindGitRoot(longCwd); root != "" {
		t.Errorf("FindGitRoot = %q, want none", root)
	}
	resolver, err := NewResolver(nil, longCwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolver.WorkspaceRoots) != 0 {
		t.Errorf("roots = %v, want none", resolver.WorkspaceRoots)
	}
}

func TestOverLimitWindowsDrivePathOnOtherOS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("lexical drive-path branch is for non-Windows hosts")
	}
	_, err := CanonicalizePath(`C:\` + strings.Repeat(`a\`, MaxResolvePathBytes()))
	if !errors.Is(err, ErrPathTooLong) {
		t.Errorf("err = %v, want ErrPathTooLong", err)
	}
}
