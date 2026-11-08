package fastpath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Windows passes \\?\ paths to the filesystem without collapsing "..": the strict exemption
// must not validate tool-results\link\..\out.txt as the neighbouring saved file.
func TestClaudeSessionToolResult_ExtendedDotDotRejected(t *testing.T) {
	home, toolResultsDir, ws, _ := setupToolResultEnv(t)
	outside := filepath.Join(t.TempDir(), "deep")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(toolResultsDir, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	ext := func(p string) string {
		if strings.HasPrefix(p, `\\`) {
			return `\\?\UNC\` + strings.TrimPrefix(p, `\\`)
		}
		return `\\?\` + p
	}
	prev := userHomeDir
	userHomeDir = func() (string, error) { return ext(home), nil }
	t.Cleanup(func() { userHomeDir = prev })

	target := ext(toolResultsDir) + `\link\..\out.txt`
	if isClaudeSessionToolResult(toolResultCall(ws, "Read", target, testToolResultSID)) {
		t.Errorf("exemption accepted %s", target)
	}
}
