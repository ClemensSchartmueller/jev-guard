package fastpath

import (
	"strings"
	"testing"
	"time"

	"jev-guard/pkg/harness"
)

func TestHookRoundSevenCommentsAndScopes(t *testing.T) {
	commands := []string{
		"# Let's reset the hooks\nrm .claude/settings.json",
		"# Let's reset the hooks\necho '{}' > .claude/settings.json",
		"echo hi # it's ok\necho '{}' > .claude/settings.json",
		"# Don't keep this\ncp /tmp/x .claude/settings.local.json",
		"# Let's reset\nsed -i 's/a/b/' .claude/settings.json",
		"# Let's reset\ntee .claude/settings.json < x",
		"# Let's reset\nRemove-Item .claude/settings.json",
		"cd .claude\n# it's fine\nrm settings.json",
		"(cd .claude\n# 2) remove old settings\nrm settings.json)",
		"(\n cd .claude || exit\n # step 1) drop local overrides\n rm settings.local.json\n)",
		"(cd .claude # done :)\nrm settings.json)",
		"cd .claude && cd /nope && true # (see note\nrm settings.json",
		"cd .claude && cd /nope && true # :(\nrm settings.json",
		"(cd .claude; case x in x) true;; esac; rm settings.json)",
		"(cd .claude; case x in x) rm settings.json;; esac)",
	}
	for _, tool := range []string{"", "Bash"} {
		for _, cmd := range commands {
			t.Run(tool+cmd, func(t *testing.T) {
				assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: tool, Command: cmd, Cwd: t.TempDir()})
			})
		}
	}
}

func TestHookRoundSevenDirectorySaturation(t *testing.T) {
	commands := []string{
		"cd a && make; cd b && make; cd c && make; cd d && make; cd e && make; cd f && make; cd g && make",
		"cd web && npm install && npm run build; cd ..; cd api && go build; cd ..; cd cli && cargo build; cd ..; cd sdk && npm test; cd ..; cd e2e && npm test; cd ..",
		"mkdir -p out && cd out && cmake .. && make -j8; cd ..\ncd docs && make html; cd ..\ncd api && make; cd ..\ncd cli && make; cd ..\ncd sdk && make; cd ..\ncd e2e && make; cd ..",
		"cd a || exit; make; cd b || exit; make; cd c || exit; make; cd d || exit; make; cd e || exit; make; cd f || exit; make;",
	}
	saturated := "cd .claude; " + "cd a; cd b; cd c; cd d; cd e; cd f; cd g; cd h; "
	commands = append(commands, saturated+"rm build.log", saturated+"rm /tmp/settings.json", saturated+"rm *log", saturated+"rm -rf .*unrelated", saturated+"cat settings.json", saturated+"rm ~/settings.json", saturated+"rm $HOME/settings.json", saturated+"rm -rf ?claude", saturated+"rm -rf [.]claude", saturated+"Remove-Item C:/tmp/settings.json")
	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			if got := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: cmd, Cwd: t.TempDir()}); got != nil {
				t.Fatalf("unexpected verdict: %+v", got)
			}
		})
	}
	for _, target := range []string{"settings.json", "settings.local.json", "hooks.json", "config.toml", ".claude", ".codex", ".agents", ".gemini", "settings.*", ".*", "../settings.json", "$HOME/.claude/settings.json", "~/.codex/hooks.json"} {
		assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: saturated + "rm -rf " + target, Cwd: t.TempDir()})
	}
	for _, cmd := range []string{"sh -c 'rm settings.json'", `python3 -c 'open("settings.json", "w")'`, `pwsh -Command '[IO.File]::Delete("settings.json")'`} {
		assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: saturated + cmd, Cwd: t.TempDir()})
	}
}

func TestHookRoundSevenAlternativesTiming(t *testing.T) {
	cmd := strings.Repeat("cd a&&cd b&&", 24000) + "true"
	start := time.Now()
	call := &harness.NormalizedToolCall{ToolName: "Bash", Command: cmd, Cwd: t.TempDir()}
	verdict := make(chan *harness.EvaluationResult, 1)
	go func() { verdict <- CheckAntiTampering(call) }()
	var got *harness.EvaluationResult
	select {
	case got = <-verdict:
	case <-time.After(2 * time.Second):
		t.Fatal("B1 produced no verdict within 2s")
	}
	elapsed := time.Since(start)
	t.Logf("B1: %d bytes in %s", len(cmd), elapsed)
	if got == nil || got.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK: %+v", got)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("B1 exceeded 2s: %s", elapsed)
	}
}

func TestHookRoundSevenCommentBoundaries(t *testing.T) {
	for _, prefix := range []string{"echo a#b", "echo ${#x}", "echo $#", "echo https://example.com/a#b", "echo $(true)#"} {
		assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: prefix + "; rm .claude/settings.json", Cwd: t.TempDir()})
	}
	for _, cmd := range []string{"echo hi # rm .claude/settings.json", "# Don't rm .claude/settings.json", "echo '# rm .claude/settings.json'", "(cd .claude; echo case); rm settings.json"} {
		if got := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: cmd, Cwd: t.TempDir()}); got != nil {
			t.Fatalf("%s: %+v", cmd, got)
		}
	}
	for _, tool := range []string{"PowerShell", ""} {
		assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: tool, Command: "<# Don't ) change state #>\nRemove-Item .claude/settings.json", Cwd: t.TempDir()})
		if got := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: tool, Command: "<# Don't rm .claude/settings.json #>\necho hi", Cwd: t.TempDir()}); got != nil {
			t.Fatalf("block comment: %+v", got)
		}
	}
}

// A '#' inside a backtick span or a $'...' string with an escaped quote is not a
// comment, so it must not hide a later write. A $PWD-relative target stays
// relative when the shell's directory is unknown.
func TestHookRoundSevenMaskingEdges(t *testing.T) {
	saturate := "cd .claude; cd a; cd b; cd c; cd d; cd e; cd f; cd g; "
	commands := []string{
		"echo `echo #x`; rm .claude/settings.json",
		`echo $'it\'s # x'; rm .claude/settings.json`,
		`printf '%s\n' $'line\'s #1' > /dev/null; rm .claude/settings.json`,
		saturate + "rm $PWD/settings.json",
		saturate + "rm ${PWD}/settings.local.json",
		saturate + `echo x > "$PWD/hooks.json"`,
	}
	for _, tool := range []string{"", "Bash"} {
		for _, cmd := range commands {
			t.Run(tool+cmd, func(t *testing.T) {
				assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: tool, Command: cmd, Cwd: t.TempDir()})
			})
		}
	}
	// PowerShell's backtick is an escape, not a quote: a later comment with an
	// apostrophe is still masked, so the write after it is still seen.
	assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "PowerShell", Command: "Write-Host \"a`tb\"\n# Let's reset\nRemove-Item .claude\\settings.json", Cwd: t.TempDir()})
}
