package fastpath

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	for _, args := range []string{`.en?`, `{a,b}`, `'*.go'`, `"[ab]"`, `sub\main.go`, `.e\nv`} {
		if !commandArgsMayExpand(args) {
			t.Errorf("expected expansion for %q", args)
		}
	}
	for _, args := range []string{`main.go`, `.e^nv`} {
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
	for _, setup := range []string{"no repository", "empty .git", "GIT_DIR", "GIT_WORK_TREE", "GIT_CEILING_DIRECTORIES", "real repository", "different owner"} {
		t.Run(setup, func(t *testing.T) {
			for _, key := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_CEILING_DIRECTORIES", "GIT_TEST_ASSUME_DIFFERENT_OWNER"} {
				t.Setenv(key, "")
			}
			cwd := t.TempDir()
			for _, name := range []string{"sub", "other", "Upper", "with space", "upstream", "u", "push"} {
				if err := os.Mkdir(filepath.Join(cwd, name), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(cwd, "file"), []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			switch setup {
			case "empty .git":
				if err := os.Mkdir(filepath.Join(cwd, ".git"), 0700); err != nil {
					t.Fatal(err)
				}
			case "GIT_DIR", "GIT_WORK_TREE", "GIT_CEILING_DIRECTORIES":
				t.Setenv(setup, cwd)
			case "real repository", "different owner":
				cmd := exec.Command("git", "init", cwd)
				for _, entry := range os.Environ() {
					if !strings.HasPrefix(entry, "GIT_") {
						cmd.Env = append(cmd.Env, entry)
					}
				}
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git init: %s: %v", out, err)
				}
				if setup == "different owner" {
					t.Setenv("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
				}
			}
			filter := NewFilter(&mockBoundaryChecker{contained: true}, nil)
			for _, command := range []string{"git diff sub other", "git diff other sub", "git diff . other", "git diff Upper file", "git diff file/child other", `git diff "with space" file`, "git diff -- sub other", `git diff s^ub other`} {
				assertDeferred(t, filter, command, &harness.NormalizedToolCall{ToolName: "Bash", Cwd: cwd, Command: command})
			}
			for _, command := range []string{"git diff HEAD~1", "git diff main...HEAD", "git diff --stat", "git diff HEAD@{1}", "git log stash@{0}", "git diff @{upstream}", "git diff @{-1}", "git diff @{u}", "git diff main@{push}", "git diff @{upstream} other", "git diff @{u} other"} {
				assertTrustedAllow(t, filter, command, &harness.NormalizedToolCall{ToolName: "Bash", Cwd: cwd, Command: command})
			}
		})
	}
}

func TestTrustedGitPathspecBackslashes(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, nil)
	for _, command := range []string{`git diff -- '.e\nv'`, `git diff -- ".e\nv"`, `git diff -- .e\\nv`, `git diff -- .e\\"n"v`, `git log -p -- 'sub/.e\nv'`, `git diff -- 'id_\rsa'`} {
		for _, tool := range []string{"Bash", "PowerShell"} {
			res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: tool, Command: command})
			if res != nil && res.Decision == harness.DecisionAllow {
				t.Errorf("%s %q: unsafe ALLOW: %+v", tool, command, res)
			}
		}
	}
}

// A directory whose name contains a reflog selector is still a filesystem
// operand: masking selectors must not hide it from the two-path check, or git's
// implicit no-index mode diffs it (and the secrets inside) under ALLOW.
func TestTrustedSelectorNamedDirectoryIsCounted(t *testing.T) {
	cwd := t.TempDir()
	for _, name := range []string{"x@{1}", "@{u}", "other"} {
		if err := os.Mkdir(filepath.Join(cwd, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cwd, "x@{1}", ".env"), []byte("S=1"), 0600); err != nil {
		t.Fatal(err)
	}
	filter := NewFilter(&mockBoundaryChecker{contained: true}, nil)
	for _, command := range []string{"git diff x@{1} other", "git diff other x@{1}", "git diff 'x@{1}' other", "git diff @{u} other"} {
		assertDeferred(t, filter, command, &harness.NormalizedToolCall{ToolName: "Bash", Cwd: cwd, Command: command})
	}
	// A selector that is not also an existing directory stays a revision.
	assertTrustedAllow(t, filter, "git diff HEAD@{1} other", &harness.NormalizedToolCall{ToolName: "Bash", Cwd: cwd, Command: "git diff HEAD@{1} other"})
}
