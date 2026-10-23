package fastpath

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"jev-guard/pkg/harness"
)

const testToolResultSID = "681cd75e-af15-41df-9181-8a8dcebf87d2"

// setupToolResultEnv overrides the home directory seam for one test and
// creates the Claude Code project layout. It returns the home directory, the
// session tool-results directory, the workspace root, and the saved file path.
func setupToolResultEnv(t *testing.T) (home, toolResultsDir, ws, allowed string) {
	t.Helper()
	home = t.TempDir()
	prev := userHomeDir
	userHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { userHomeDir = prev })

	toolResultsDir = filepath.Join(home, ".claude", "projects", "C--dev-proj", testToolResultSID, "tool-results")
	if err := os.MkdirAll(toolResultsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	allowed = filepath.Join(toolResultsDir, "out.txt")
	if err := os.WriteFile(allowed, []byte("saved output"), 0o644); err != nil {
		t.Fatal(err)
	}
	ws = t.TempDir()
	return home, toolResultsDir, ws, allowed
}

func toolResultCall(ws, toolName, target, sid string) *harness.NormalizedToolCall {
	return &harness.NormalizedToolCall{
		Harness:        harness.HarnessClaudeCode,
		ToolName:       toolName,
		TargetPath:     target,
		SessionID:      sid,
		Cwd:            ws,
		WorkspaceRoots: []string{ws},
	}
}

func writeTestFile(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestClaudeSessionToolResult_Allowed(t *testing.T) {
	_, _, ws, allowed := setupToolResultEnv(t)

	t.Run("saved tool result", func(t *testing.T) {
		call := toolResultCall(ws, "Read", allowed, testToolResultSID)
		res := NewDefaultFilter().Evaluate(call)
		if res == nil {
			t.Fatal("expected non-nil result")
		}
		if res.Decision != harness.DecisionAllow {
			t.Fatalf("expected ALLOW, got %s (reason: %s)", res.Decision, res.Reason)
		}
	})
}

func TestClaudeSessionToolResult_NotAllowed(t *testing.T) {
	home, toolResultsDir, ws, allowed := setupToolResultEnv(t)
	projDir := filepath.Join(home, ".claude", "projects", "C--dev-proj")

	otherSessionFile := filepath.Join(projDir, "other-session", "tool-results", "out.txt")
	writeTestFile(t, otherSessionFile)

	directSessionFile := filepath.Join(projDir, testToolResultSID, "other.txt")
	writeTestFile(t, directSessionFile)

	nestedFile := filepath.Join(toolResultsDir, "sub", "x.txt")
	writeTestFile(t, nestedFile)

	settingsFile := filepath.Join(home, ".claude", "settings.json")
	writeTestFile(t, settingsFile)

	// Built by string concatenation so the ".." segments are not cleaned away.
	sep := string(filepath.Separator)
	// Resolves to the existing <home>/.claude/settings.json.
	traversal := toolResultsDir + sep + ".." + sep + ".." + sep + ".." + sep + ".." + sep + "settings.json"

	missing := filepath.Join(toolResultsDir, "missing.txt")

	cases := []struct {
		name string
		call *harness.NormalizedToolCall
	}{
		{"other session same file", toolResultCall(ws, "Read", allowed, "other-session")},
		{"empty session id", toolResultCall(ws, "Read", allowed, "")},
		{"traversal session id", toolResultCall(ws, "Read", allowed, "../x")},
		{"file directly in session dir", toolResultCall(ws, "Read", directSessionFile, testToolResultSID)},
		{"nested path", toolResultCall(ws, "Read", nestedFile, testToolResultSID)},
		{"claude settings file", toolResultCall(ws, "Read", settingsFile, testToolResultSID)},
		{"traversal out of tool-results", toolResultCall(ws, "Read", traversal, testToolResultSID)},
		{"glob on tool-results dir", toolResultCall(ws, "Glob", toolResultsDir, testToolResultSID)},
		{"grep on tool-results dir", toolResultCall(ws, "Grep", toolResultsDir, testToolResultSID)},
		{"antigravity harness", &harness.NormalizedToolCall{
			Harness:        harness.HarnessAntigravity,
			ToolName:       "Read",
			TargetPath:     allowed,
			SessionID:      testToolResultSID,
			Cwd:            ws,
			WorkspaceRoots: []string{ws},
		}},
		{"tool-results directory itself", toolResultCall(ws, "Read", toolResultsDir, testToolResultSID)},
		{"non-existent file", toolResultCall(ws, "Read", missing, testToolResultSID)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := NewDefaultFilter().Evaluate(tc.call)
			if res == nil {
				t.Fatal("expected non-nil result")
			}
			if res.Decision == harness.DecisionAllow {
				t.Fatalf("expected non-ALLOW, got ALLOW (reason: %s)", res.Reason)
			}
		})
	}

	t.Run("symlink leaving tool-results", func(t *testing.T) {
		outsideDir := t.TempDir()
		outside := filepath.Join(outsideDir, "secret.txt")
		if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(toolResultsDir, "link.txt")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlink not supported: %v", err)
		}
		res := NewDefaultFilter().Evaluate(toolResultCall(ws, "Read", link, testToolResultSID))
		if res == nil {
			t.Fatal("expected non-nil result")
		}
		if res.Decision == harness.DecisionAllow {
			t.Fatalf("expected non-ALLOW for symlink escape, got ALLOW (reason: %s)", res.Reason)
		}
	})
}

func TestClaudeSessionToolResult_RejectsMoreCases(t *testing.T) {
	home, toolResultsDir, ws, allowed := setupToolResultEnv(t)

	t.Run("directory in tool-results", func(t *testing.T) {
		dir := filepath.Join(toolResultsDir, "dir")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if isClaudeSessionToolResult(toolResultCall(ws, "Read", dir, testToolResultSID)) {
			t.Fatal("expected a directory to be rejected")
		}
	})

	t.Run("symlink into other session", func(t *testing.T) {
		other := filepath.Join(home, ".claude", "projects", "C--dev-proj", "other-session", "tool-results", "out.txt")
		writeTestFile(t, other)
		link := filepath.Join(toolResultsDir, "other-link.txt")
		if err := os.Symlink(other, link); err != nil {
			t.Skipf("symlink not supported: %v", err)
		}
		if isClaudeSessionToolResult(toolResultCall(ws, "Read", link, testToolResultSID)) {
			t.Fatal("expected a symlink into another session to be rejected")
		}
	})

	t.Run("home resolution error", func(t *testing.T) {
		userHomeDir = func() (string, error) { return "", errHomeNotStubbed }
		if isClaudeSessionToolResult(toolResultCall(ws, "Read", allowed, testToolResultSID)) {
			t.Fatal("expected rejection when the home directory cannot be resolved")
		}
	})

	t.Run("empty home", func(t *testing.T) {
		userHomeDir = func() (string, error) { return "", nil }
		if isClaudeSessionToolResult(toolResultCall(ws, "Read", allowed, testToolResultSID)) {
			t.Fatal("expected rejection for an empty home directory")
		}
	})
}

func TestClaudeSessionToolResult_SymlinkedHome(t *testing.T) {
	_, _, ws, allowed := setupToolResultEnv(t)
	realHome, err := userHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	linkHome := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(realHome, linkHome); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	userHomeDir = func() (string, error) { return linkHome, nil }

	rel, err := filepath.Rel(realHome, allowed)
	if err != nil {
		t.Fatal(err)
	}
	if !isClaudeSessionToolResult(toolResultCall(ws, "Read", filepath.Join(linkHome, rel), testToolResultSID)) {
		t.Fatal("expected a tool result under a symlinked home to be allowed")
	}
}

// TestClaudeSessionToolResult_IgnoresHostHome proves the matcher reads the
// home directory only through the userHomeDir seam: a valid layout under
// $HOME is not allowed while the TestMain default seam is in place.
func TestClaudeSessionToolResult_IgnoresHostHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	saved := filepath.Join(home, ".claude", "projects", "C--dev-proj", testToolResultSID, "tool-results", "out.txt")
	writeTestFile(t, saved)

	if _, err := userHomeDir(); !errors.Is(err, errHomeNotStubbed) {
		t.Fatalf("expected the TestMain default seam, got err=%v", err)
	}
	if isClaudeSessionToolResult(toolResultCall(t.TempDir(), "Read", saved, testToolResultSID)) {
		t.Fatal("matcher resolved the host home instead of the userHomeDir seam")
	}
}
