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
		for _, arg := range []string{`.e\nv`, `.e^nv`, ".e`nv"} {
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
