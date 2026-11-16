package fastpath

import (
	"os"
	"path/filepath"
	"testing"

	"jev-guard/pkg/harness"
)

func TestFastPath_TrustedCommandExpansion(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, nil)
	for _, arg := range []string{
		`.en?`, `.en*`, `.en[v]`, `*`, `sub/.en?`, `server.ke?`, `{.env,x}`,
		`'*.env'`, `"*.env"`, `']'`, `~/main.go`, `~user/main.go`, `--path=*.env`,
	} {
		t.Run(arg, func(t *testing.T) {
			for _, tool := range []string{"Bash", "PowerShell"} {
				call := &harness.NormalizedToolCall{ToolName: tool, Command: "git diff -- " + arg}
				// Existing sensitive checks may ASK before the trusted-command check.
				if res := filter.Evaluate(call); res != nil && res.Decision == harness.DecisionAllow {
					t.Errorf("%s: expansion must not be fast-path ALLOWed, got %+v", tool, res)
				}
			}
		})
	}
	for _, command := range []string{"git diff -- main.go", "git status"} {
		assertTrustedAllow(t, filter, command, &harness.NormalizedToolCall{ToolName: "Bash", Command: command})
	}
	res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: "Bash", Command: "git diff --no-index go.mod .env"})
	if res == nil || res.Decision != harness.DecisionAsk || res.Source != "fastpath_sensitive" {
		t.Errorf("literal .env: expected sensitive ASK, got %+v", res)
	}
}

// Bash is available on Windows too: the shell reader must not select escape
// rules from runtime.GOOS. These expectations are identical on every host.
func TestTrustedSensitiveShellEscapes(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, nil)
	for _, tool := range []string{"Bash", "PowerShell"} {
		for _, arg := range []string{`.e\nv`, `.e^nv`, ".e`nv", `.e^"n"v`, `.e^"n^"v`, `.e^"^"nv`} {
			res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: tool, Command: "git diff -- " + arg})
			if res == nil || res.Decision != harness.DecisionAsk || res.Source != "fastpath_sensitive" {
				t.Errorf("%s %q: expected sensitive ASK on every OS, got %+v", tool, arg, res)
			}
		}
	}
}

func TestTrustedNoIndexDefers(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, nil)
	cwd := t.TempDir()
	for _, dir := range []string{"a", "sub"} {
		if err := os.Mkdir(filepath.Join(cwd, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".env", "sub/.env"} {
		if err := os.WriteFile(filepath.Join(cwd, name), []byte("DUMMY=fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, arg := range []string{"a sub", "a .", "go.mod main.go"} {
		assertDeferred(t, filter, arg, &harness.NormalizedToolCall{
			ToolName: "Bash", Cwd: cwd, Command: "git diff --no-index " + arg,
		})
	}
}

func TestTrustedNameOnlyGlobs(t *testing.T) {
	for _, command := range []string{"ls *.go", "echo *", "dir *.go", "which *", "where.exe *.exe"} {
		filter := NewFilter(&mockBoundaryChecker{contained: true}, nil)
		assertTrustedAllow(t, filter, command, &harness.NormalizedToolCall{ToolName: "Bash", Command: command})
	}
	for _, command := range []string{"ls /etc/*", "echo /etc/*", "dir /etc/*", "which /etc/*"} {
		filter := NewFilter(&mockBoundaryChecker{contained: false}, nil)
		assertDeferred(t, filter, command, &harness.NormalizedToolCall{ToolName: "Bash", Command: command})
	}
	for _, command := range []string{"git diff '*.go'", "git log '*.go'", "git show '*.go'"} {
		filter := NewFilter(&mockBoundaryChecker{contained: true}, nil)
		assertDeferred(t, filter, command, &harness.NormalizedToolCall{ToolName: "Bash", Command: command})
	}
}

func TestCommandArgsMayExpand(t *testing.T) {
	for _, args := range []string{`.en?`, `{a,b}`, `'*.go'`, `"[ab]"`} {
		if !commandArgsMayExpand(args) {
			t.Errorf("expected expansion for %q", args)
		}
	}
	for _, args := range []string{`main.go`, `sub\main.go`, `.e^nv`, `.e\nv`} {
		if commandArgsMayExpand(args) {
			t.Errorf("unexpected expansion for %q", args)
		}
	}
}

func TestTrustedCaretQuoteNames(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, nil)
	for _, arg := range []string{`sub/.e^"n"v`, `id_^"rsa`, `a.p^"e^"m`} {
		res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: "Bash", Command: "git log -p -- " + arg})
		if res == nil || res.Source != "fastpath_sensitive" {
			t.Errorf("%q: expected sensitive check, got %+v", arg, res)
		}
	}
	res := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: `cat ~/.jev^"g"uard/state`})
	if res == nil || res.Decision != harness.DecisionDeny {
		t.Fatalf("expected tampering DENY, got %+v", res)
	}
}

func TestTrustedImplicitNoIndex(t *testing.T) {
	t.Setenv("GIT_DIR", "")
	t.Setenv("GIT_WORK_TREE", "")
	cwd := t.TempDir()
	filter := NewFilter(&mockBoundaryChecker{contained: true}, nil)
	for _, name := range []string{"sub", "other"} {
		if err := os.Mkdir(filepath.Join(cwd, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"sub/.env", "other/x"} {
		if err := os.WriteFile(filepath.Join(cwd, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{"git diff sub other", "git diff other sub", "git diff . other"} {
		assertDeferred(t, filter, command, &harness.NormalizedToolCall{ToolName: "Bash", Cwd: cwd, Command: command})
	}
	if err := os.Mkdir(filepath.Join(cwd, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"git diff HEAD~1", "git diff HEAD@{1}", "git log stash@{0}", "git diff @{upstream}"} {
		assertTrustedAllow(t, filter, command, &harness.NormalizedToolCall{ToolName: "Bash", Cwd: cwd, Command: command})
	}
}

func TestInsideGitWorkTree(t *testing.T) {
	t.Setenv("GIT_DIR", "")
	t.Setenv("GIT_WORK_TREE", "")
	cwd := t.TempDir()
	if insideGitWorkTree(cwd) {
		t.Fatal("temporary directory is not a repository")
	}
	gitDir := t.TempDir()
	t.Setenv("GIT_DIR", gitDir)
	if !insideGitWorkTree(cwd) {
		t.Fatal("GIT_DIR should be honored")
	}
	t.Setenv("GIT_WORK_TREE", filepath.Join(cwd, "missing"))
	if insideGitWorkTree(cwd) {
		t.Fatal("lookup error must fail closed even with GIT_DIR")
	}
	t.Setenv("GIT_DIR", "")
	t.Setenv("GIT_WORK_TREE", cwd)
	if !insideGitWorkTree(cwd) {
		t.Fatal("GIT_WORK_TREE should be honored")
	}
	t.Setenv("GIT_WORK_TREE", "")
	if err := os.WriteFile(filepath.Join(cwd, ".git"), []byte("gitdir: "+gitDir), 0600); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(cwd, "sub")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if !insideGitWorkTree(child) {
		t.Fatal("parent worktree .git file should be recognized")
	}
}
