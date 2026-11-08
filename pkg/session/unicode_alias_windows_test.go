//go:build windows

// Review of PR #79: a valid path over 32,767 UTF-8 bytes, far under Windows' limit of 32,767
// UTF-16 units, ending in a directory alias of JEV_GUARD_HOME, must be recognised. This
// package's TestMain isolates the profile. Requires Windows symlink privileges.
package session

import (
	"jev-guard/pkg/boundary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnicodeAliasOverByteLengthIsJevguardPath(t *testing.T) {
	protected := GetJevguardDir()
	if err := os.MkdirAll(protected, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(protected, "review-marker"), []byte("protected"), 0600); err != nil {
		t.Fatal(err)
	}
	dir := `\\?\` + t.TempDir()
	for len(dir) <= boundary.MaxResolvePathLength() {
		dir = filepath.Join(dir, strings.Repeat("界", 100))
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(protected, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	target := filepath.Join(alias, "review-marker")
	if _, err := os.ReadFile(target); err != nil {
		t.Fatal(err)
	}
	if !IsJevguardPath(target) {
		t.Fatalf("OS can read protected alias (%d UTF-8 bytes), but anti-tampering misses it", len(target))
	}
}
