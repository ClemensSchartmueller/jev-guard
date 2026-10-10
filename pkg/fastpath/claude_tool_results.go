package fastpath

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"jev-guard/pkg/harness"
)

// Test seams.
var (
	userHomeDir  = os.UserHomeDir
	evalSymlinks = filepath.EvalSymlinks
)

var claudeSessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,127}$`)

// isClaudeSessionToolResult reports whether call is a Claude Code Read of a file
// that Claude Code itself saved for the current session, i.e. exactly
// <home>/.claude/projects/<project>/<session_id>/tool-results/<file>.
// Anything else (other tools, other sessions, nested paths, symlinks leaving
// the directory, non-regular files, any resolution error) returns false.
func isClaudeSessionToolResult(call *harness.NormalizedToolCall) bool {
	if call == nil {
		return false
	}
	if call.Harness != harness.HarnessClaudeCode {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(call.ToolName), "read") {
		return false
	}
	if !claudeSessionIDPattern.MatchString(call.SessionID) {
		return false
	}

	target := strings.TrimSpace(call.TargetPath)
	if target == "" || !filepath.IsAbs(target) {
		return false
	}

	home, err := userHomeDir()
	if err != nil || home == "" {
		return false
	}

	if !matchesToolResultPath(filepath.Clean(target), home, call.SessionID) {
		return false
	}

	resolved, err := evalSymlinks(target)
	if err != nil {
		return false
	}
	resolvedHome, err2 := evalSymlinks(home)
	if err2 != nil {
		return false
	}
	if !matchesToolResultPath(resolved, resolvedHome, call.SessionID) {
		return false
	}

	info, err := os.Lstat(resolved)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func matchesToolResultPath(p, home, sessionID string) bool {
	rel, err := filepath.Rel(filepath.Join(home, ".claude", "projects"), p)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return parts[1] == sessionID && parts[2] == "tool-results"
}
