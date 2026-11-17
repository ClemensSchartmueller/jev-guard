package fastpath

import (
	"jev-guard/pkg/harness"
	"testing"
)

func TestHookRoundFiveDirectoryScopes(t *testing.T) {
	for _, command := range []string{
		`cd .claude && cd /nonexistent && true; rm settings.json`,
		"cd .claude && cd /nope && :\nrm settings.json",
		`cd ~/.claude && cd /nope && :; rm settings.json`,
		`cd .codex && cd /nope && :; rm hooks.json`,
		`cd .claude && (cd /tmp && true); rm settings.json`,
		`cd .claude && (cd / && ls) && rm settings.json`,
		`cd .claude && cd /nope && false || rm settings.json`,
		`cd .claude && cd /nope && true | rm settings.json`,
	} {
		t.Run(command, func(t *testing.T) {
			assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: t.TempDir()})
		})
	}
}

func TestHookRoundFiveReadersAndContinuations(t *testing.T) {
	for _, tool := range []string{"Bash", "exec_command"} {
		for _, command := range []string{
			`python3 -m json.tool --indent 2 .claude/settings.json`,
			`python3 -m json.tool --sort-keys .claude/settings.json`,
			`python3 -m json.tool --json-lines --no-ensure-ascii --compact --tab .claude/settings.json`,
			"rm -rf * \\\n  && echo ok", "rm -f * \\\n ; ls",
		} {
			t.Run(tool+command, func(t *testing.T) {
				if got := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: tool, Command: command, Cwd: t.TempDir()}); got != nil {
					t.Fatalf("unexpected verdict: %+v", got)
				}
			})
		}
	}
	for _, command := range []string{`python3 -m json.tool x .claude/settings.json`, `python3 -m json.tool --indent 2 x .claude/settings.json`} {
		assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: t.TempDir()})
	}
}

func TestHookRoundFiveBashUsesPOSIXGlobs(t *testing.T) {
	for _, command := range []string{`Remove-Item *`, `rm -rf * ordinary\text`, `(cd .claude); rm settings.json`, `((cd .claude)); rm settings.json`, `pushd src; (pushd .claude); popd; rm settings.json`} {
		if got := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: t.TempDir()}); got != nil {
			t.Fatalf("%s: %+v", command, got)
		}
	}
	assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: `pwsh -Command 'rm *'`, Cwd: t.TempDir()})
	assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: `pwsh -Command 'Remove-Item *'`, Cwd: t.TempDir()})
}
