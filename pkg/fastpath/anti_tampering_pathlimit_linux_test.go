package fastpath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jev-guard/pkg/harness"
)

// A protected file reachable through a path whose absolute lookup is exactly at the OS path
// limit: the OS rejects the absolute lookup as a whole path, but a relative open from the deep
// directory, or a short symlink to it, still reads the file. That must keep at least the ASK
// floor, never count as clean.
func TestCheckAntiTampering_WholePathLimitKeepsFloor(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "secure-store")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "state"), []byte("protected"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JEV_GUARD_HOME", home)

	// Build a directory whose absolute path is 4,094 bytes, so deep+"/x" is 4,096.
	base := filepath.Join(root, "d")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)
	if err := os.Chdir(base); err != nil {
		t.Fatal(err)
	}
	deep := base
	for remaining := 4094 - len(base); remaining > 0; {
		n := min(remaining-1, 200)
		if n < 1 {
			t.Skip("cannot reach the exact length")
		}
		name := strings.Repeat("a", n)
		if remaining-(n+1) == 1 {
			name = strings.Repeat("a", n-1)
		}
		if err := os.Mkdir(name, 0o700); err != nil {
			t.Skipf("cannot build deep tree: %v", err)
		}
		if err := os.Chdir(name); err != nil {
			t.Skipf("cannot enter deep tree: %v", err)
		}
		deep += "/" + name
		remaining = 4094 - len(deep)
	}
	if len(deep) != 4094 {
		t.Skipf("deep directory is %d bytes", len(deep))
	}
	if err := os.Symlink(filepath.Join(home, "state"), "x"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if data, err := os.ReadFile("x"); err != nil || string(data) != "protected" {
		t.Skipf("relative read through x failed: %v", err)
	}
	if err := os.Chdir(orig); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(root, "short")
	if err := os.Symlink(deep, short); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, command, cwd string
	}{
		{"relative from the deep directory", "/bin/cat x", deep},
		{"short symlink to the deep directory", "/bin/cat " + filepath.Join(short, "x"), root},
	} {
		res := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: tc.command, Cwd: tc.cwd})
		if res == nil {
			t.Errorf("%s: clean; want the ASK floor or DENY", tc.name)
		}
	}
}
