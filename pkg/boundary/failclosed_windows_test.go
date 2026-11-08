package boundary

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// extendedPath spells an absolute path in the extended-length namespace.
func extendedPath(p string) string {
	switch {
	case strings.HasPrefix(p, `\\?\`):
		return p
	case strings.HasPrefix(p, `\\`):
		return `\\?\UNC\` + strings.TrimPrefix(p, `\\`)
	}
	return `\\?\` + p
}

// Windows passes \\?\ paths to the filesystem without collapsing "..", so link\.. must not be
// cleaned to the neighbouring file: the path is unverifiable (review artifact for PR #79).
func TestExtendedDotDotIsUnverifiable(t *testing.T) {
	ws := realTempDir(t)
	out := realTempDir(t)
	if err := os.Mkdir(filepath.Join(out, "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "file"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(out, "deep"), filepath.Join(ws, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	ext := extendedPath(ws)
	for _, p := range []string{ext + `\link\..\file`, ext + `\.\file`, strings.ReplaceAll(ext, `\`, `/`) + `/link/../file`} {
		if got, err := EvalSymlinks(p); !errors.Is(err, ErrUnverifiablePath) {
			t.Errorf("EvalSymlinks(%q) = %q, %v; want ErrUnverifiablePath", p, got, err)
		}
		if got, err := CanonicalizePath(p); !errors.Is(err, ErrResolutionLimit) {
			t.Errorf("CanonicalizePath(%q) = %q, %v; want a resolution limit", p, got, err)
		}
	}
}
