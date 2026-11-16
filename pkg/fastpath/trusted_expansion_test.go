package fastpath

import (
	"runtime"
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
				call := &harness.NormalizedToolCall{ToolName: tool, Command: "git diff --no-index go.mod " + arg}
				// Existing sensitive checks may ASK before the trusted-command check.
				if res := filter.Evaluate(call); res != nil && res.Decision == harness.DecisionAllow {
					t.Errorf("%s: expansion must not be fast-path ALLOWed, got %+v", tool, res)
				}
			}
		})
	}
	if runtime.GOOS != "windows" {
		assertDeferred(t, filter, "escaped sensitive filename", &harness.NormalizedToolCall{
			ToolName: "Bash", Command: `git diff --no-index go.mod .e\nv`,
		})
	}
	for _, command := range []string{"git diff --no-index go.mod main.go", "git status"} {
		assertTrustedAllow(t, filter, command, &harness.NormalizedToolCall{ToolName: "Bash", Command: command})
	}
	res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: "Bash", Command: "git diff --no-index go.mod .env"})
	if res == nil || res.Decision != harness.DecisionAsk || res.Source != "fastpath_sensitive" {
		t.Errorf("literal .env: expected sensitive ASK, got %+v", res)
	}
}

func TestCommandArgsMayExpand_Platform(t *testing.T) {
	for _, tc := range []struct {
		args string
		goos string
		want bool
	}{
		{`--no-index go.mod sub\main.go`, "windows", false},
		{`--no-index go.mod sub\main.go`, "linux", true},
		{`--no-index go.mod .e\nv`, "linux", true},
		{`--no-index go.mod sub\.en?`, "windows", true},
		{`--no-index go.mod 'sub\*.env'`, "windows", true},
		{`--no-index go.mod sub\[ab].go`, "windows", true},
	} {
		if got := commandArgsMayExpand(tc.args, tc.goos); got != tc.want {
			t.Errorf("%s %q: got %v, want %v", tc.goos, tc.args, got, tc.want)
		}
	}
	if runtime.GOOS == "windows" {
		filter := NewFilter(&mockBoundaryChecker{contained: true}, nil)
		assertTrustedAllow(t, filter, "Windows relative path", &harness.NormalizedToolCall{
			ToolName: "PowerShell", Command: `git diff --no-index go.mod sub\main.go`,
		})
	}
}
