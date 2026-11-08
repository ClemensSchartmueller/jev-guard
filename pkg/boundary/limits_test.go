package boundary

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// countLookups wraps the lstat seam to count filesystem lookups.
func countLookups(t *testing.T) *int {
	t.Helper()
	calls := 0
	orig := lstat
	lstat = func(p string) (os.FileInfo, error) {
		calls++
		return orig(p)
	}
	t.Cleanup(func() { lstat = orig })
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

func TestMaxResolvePathLengthForOS(t *testing.T) {
	if got := maxResolvePathLengthForOS("windows"); got != 32767 {
		t.Errorf("windows limit = %d, want 32767", got)
	}
	if got := maxResolvePathLengthForOS("darwin"); got != 1024 {
		t.Errorf("darwin limit = %d, want 1024", got)
	}
	for _, goos := range []string{"linux", "freebsd"} {
		if got := maxResolvePathLengthForOS(goos); got != 4096 {
			t.Errorf("%s limit = %d, want 4096", goos, got)
		}
	}
}

// Windows counts its path limit in UTF-16 code units, not UTF-8 bytes: a CJK ideograph is
// three bytes but one unit, so a valid path can exceed 32,767 bytes (review of PR #79).
func TestPathLengthCountsUTF16OnWindows(t *testing.T) {
	cjk := `\\?\C:\` + strings.Repeat(strings.Repeat("界", 100)+`\`, 120)
	if got, want := pathLengthForOS(cjk, "windows"), 7+120*101; got != want {
		t.Errorf("windows length = %d, want %d UTF-16 units", got, want)
	}
	if got := pathLengthForOS(cjk, "windows"); got > maxResolvePathLengthForOS("windows") {
		t.Errorf("a %d-unit path is over the Windows limit", got)
	}
	if len(cjk) <= maxResolvePathLengthForOS("windows") {
		t.Fatalf("test path is only %d bytes", len(cjk))
	}
	if got := pathLengthForOS("a😀", "windows"); got != 3 {
		t.Errorf("surrogate pair length = %d, want 3", got)
	}
	if got := pathLengthForOS("a\xff", "windows"); got != 2 {
		t.Errorf("invalid UTF-8 length = %d, want 2", got)
	}
	if got := pathLengthForOS(cjk, "linux"); got != len(cjk) {
		t.Errorf("linux length = %d, want %d bytes", got, len(cjk))
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
	calls := countLookups(t)
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
		t.Errorf("over-limit path made %d lookups, want 0", *calls)
	}
	if elapsed > time.Second {
		t.Errorf("rejecting a 64 KiB path took %v", elapsed)
	}
}

// TestDeepMissingTailStopsAtFirstMissingComponent checks the work bound inside the limit:
// the walk stops at the first missing component instead of looking up every ancestor.
func TestDeepMissingTailStopsAtFirstMissingComponent(t *testing.T) {
	ws := realTempDir(t)
	budget := MaxResolvePathLength() - len(ws) - 2
	components := budget / 2
	tail := strings.TrimSuffix(strings.Repeat("a"+string(filepath.Separator), components), string(filepath.Separator))
	target := ws + string(filepath.Separator) + tail
	if len(target) > MaxResolvePathLength() {
		t.Fatalf("test path is %d bytes, over the limit", len(target))
	}
	calls := countLookups(t)

	got, err := CanonicalizePath(target)
	if err != nil {
		t.Fatalf("CanonicalizePath: %v", err)
	}
	if got != filepath.Clean(target) {
		t.Errorf("got %.80s..., want the path as written", got)
	}
	if maxCalls := strings.Count(ws, string(filepath.Separator)) + 1; *calls > maxCalls {
		t.Errorf("%d lookups for a workspace of depth %d, want at most %d", *calls, maxCalls-1, maxCalls)
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

// A file followed by more components cannot be looked up (ENOTDIR): unverifiable, not a
// name to be created.
func TestResolveFileAncestor(t *testing.T) {
	ws := realTempDir(t)
	file := filepath.Join(ws, "file.txt")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := CanonicalizePath(filepath.Join(file, "child")); err == nil {
		t.Errorf("got %q, want an error", got)
	}
}

// fakeFS backs the lstat and readlink seams: "" is a directory, "file" a file, and any
// other value a symlink to it. normalization is off, as on Unix.
func fakeFS(t *testing.T, entries map[string]string) *int {
	t.Helper()
	calls := 0
	origLstat, origReadlink, origNormBase := lstat, readlink, normBase
	lstat = func(p string) (os.FileInfo, error) {
		calls++
		v, ok := entries[p]
		if !ok {
			return nil, os.ErrNotExist
		}
		mode := fs.ModeDir
		switch v {
		case "":
		case "file":
			mode = 0
		default:
			mode = fs.ModeSymlink
		}
		return fakeInfo{name: filepath.Base(p), mode: mode}, nil
	}
	readlink = func(p string) (string, error) {
		v, ok := entries[p]
		if !ok || v == "" || v == "file" {
			return "", os.ErrInvalid
		}
		return v, nil
	}
	normBase = nil
	t.Cleanup(func() { lstat, readlink, normBase = origLstat, origReadlink, origNormBase })
	return &calls
}

type fakeInfo struct {
	name string
	mode fs.FileMode
}

func (i fakeInfo) Name() string       { return i.name }
func (i fakeInfo) Size() int64        { return 0 }
func (i fakeInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeInfo) Sys() any           { return nil }

// TestResolveSymlinksFake exercises the walk on fixed path shapes, including Windows drive
// and UNC paths, which only parse as such on Windows. Past a component that does not
// exist, the rest is taken as names to be created; ".." removes the last of them. Any other
// lookup failure is an error (want "").
func TestResolveSymlinksFake(t *testing.T) {
	type tc struct {
		name    string
		in      string
		entries map[string]string
		want    string
	}
	var cases []tc
	if runtime.GOOS == "windows" {
		cases = []tc{
			{"drive root only", `C:\ws\a\b`, nil, `C:\ws\a\b`},
			{"drive symlinked ancestor", `C:\ws\link\a\b`,
				map[string]string{`C:\ws`: "", `C:\ws\link`: `D:\real`, `D:\real`: ""}, `D:\real\a\b`},
			{"unc", `\\srv\share\ws\a`, map[string]string{`\\srv\share\ws`: ""}, `\\srv\share\ws\a`},
		}
	} else {
		cases = []tc{
			{"nothing resolves", "/ws/a/b", nil, "/ws/a/b"},
			{"symlinked ancestor", "/ws/link/a/b",
				map[string]string{"/ws": "", "/ws/link": "/real", "/real": ""}, "/real/a/b"},
			// Writing through a dangling symlink creates its target.
			{"dangling symlink resolves to its target", "/ws/link/a",
				map[string]string{"/ws": "", "/ws/link": "/real/missing", "/real": ""}, "/real/missing/a"},
			// ".." applies after the symlink before it is followed, also past a missing name.
			{"dotdot after symlink", "/ws/link/../f",
				map[string]string{"/ws": "", "/ws/link": "/real/deep", "/real": "", "/real/deep": "", "/real/f": "file"}, "/real/f"},
			{"dotdot after missing name", "/ws/new/../link/../f",
				map[string]string{"/ws": "", "/ws/link": "/real/deep", "/real": "", "/real/deep": ""}, "/real/f"},
			{"missing names popped by dotdot", "/ws/new/x/../../f",
				map[string]string{"/ws": ""}, "/ws/f"},
			{"link to root", "/ws/link/a", map[string]string{"/ws": "", "/ws/link": "/"}, "/a"},
			{"whole path", "/ws/a", map[string]string{"/ws": "", "/ws/a": "/other", "/other": ""}, "/other"},
			{"relative link with dot-dot", "/ws/d/l/x",
				map[string]string{"/ws": "", "/ws/d": "", "/ws/d/l": "../real", "/ws/real": ""}, "/ws/real/x"},
			{"chain", "/ws/l1/x",
				map[string]string{"/ws": "", "/ws/l1": "l2", "/ws/l2": "/real", "/real": ""}, "/real/x"},
			{"link to a file, then a child", "/ws/f/child",
				map[string]string{"/ws": "", "/ws/f": "/real/file", "/real": "", "/real/file": "file"}, ""},
			{"link loop", "/ws/loop/x", map[string]string{"/ws": "", "/ws/loop": "/ws/loop"}, ""},
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeFS(t, c.entries)
			got, err := newEvaluation().resolve(c.in, false)
			if c.want == "" {
				if err == nil {
					t.Errorf("resolve(%q) = %q, want an error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve(%q): %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("resolve(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestOverLimitDeclaredRootDoesNotFallBackToCwd(t *testing.T) {
	ws := realTempDir(t)
	longRoot := filepath.Join(ws, strings.Repeat("r", MaxResolvePathLength()))
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
	longCwd := filepath.Join(ws, strings.Repeat("c", MaxResolvePathLength()))
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
	_, err := CanonicalizePath(`C:\` + strings.Repeat(`a\`, MaxResolvePathLength()))
	if !errors.Is(err, ErrPathTooLong) {
		t.Errorf("err = %v, want ErrPathTooLong", err)
	}
}

// A declared root that cannot be resolved (here ENOTDIR) must not be replaced by the
// broader cwd or Git root.
func TestNewResolver_UnresolvableDeclaredRootDoesNotFallBack(t *testing.T) {
	ws := realTempDir(t)
	if err := os.WriteFile(filepath.Join(ws, "file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(ws, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	declared := filepath.Join(ws, "file", "child")
	r, err := NewResolver([]string{declared}, ws)
	if err != nil {
		t.Fatal(err)
	}
	contained, _ := r.IsPathContained(filepath.Join(ws, "sibling"), ws)
	if contained {
		t.Error("unresolvable declared root broadened to cwd")
	}
}
