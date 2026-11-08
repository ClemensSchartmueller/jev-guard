// Package testpaths creates deep directory trees for tests within the platform's path limit.
//
// macOS rejects paths of 1,024 bytes or more (PATH_MAX), Linux 4,096; a fixed depth that fits
// Linux fails to mkdir on macOS. Tests that need a deep tree ask for a depth and get the
// deepest that fits, and tests where the depth is not the point use a shallow one, since deep
// trees are slow to create on Windows.
package testpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// MaxPathLength is the platform's limit on a path passed to the OS, in bytes (Windows counts
// UTF-16 units; the paths made here are ASCII). It matches boundary.MaxResolvePathLength,
// which this package cannot import (boundary's own tests use it).
func MaxPathLength() int {
	switch runtime.GOOS {
	case "windows":
		return 32767
	case "darwin", "ios":
		return 1024
	}
	return 4096
}

// Depth is the depth of a tree of one-letter directories under parent, at most want, that
// leaves reserve bytes of the path limit free for names below it.
func Depth(parent string, want, reserve int) int {
	room := MaxPathLength() - 1 - reserve - len(parent)
	if d := room / 2; d < want {
		return d
	}
	return want
}

// NestedDirs creates depth nested directories named "a" under parent and returns the deepest.
func NestedDirs(t testing.TB, parent string, depth int) string {
	t.Helper()
	if depth < 1 {
		t.Fatalf("no room for a tree under %s", parent)
	}
	sep := string(filepath.Separator)
	dir := filepath.Join(parent, strings.TrimSuffix(strings.Repeat("a"+sep, depth), sep))
	if len(dir) >= MaxPathLength() {
		t.Fatalf("a %d-deep tree under %s is over the path limit", depth, parent)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// DeepDirs creates the deepest tree, at most want deep, under parent that leaves reserve
// bytes free, and returns its deepest directory and depth.
func DeepDirs(t testing.TB, parent string, want, reserve int) (string, int) {
	t.Helper()
	d := Depth(parent, want, reserve)
	return NestedDirs(t, parent, d), d
}
