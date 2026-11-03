package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"jev-guard/pkg/config"
	"jev-guard/pkg/fastpath"
	"jev-guard/pkg/harness"
)

// transcriptOnConfig is the built-in config with the opt-in turned on.
func transcriptOnConfig() *config.Config {
	on := true
	cfg := config.DefaultConfig()
	cfg.AntigravityTranscriptIntent = &on
	return cfg
}

func withFastpath(cfg *config.Config, enabled bool) *config.Config {
	cfg.FastpathEnabled = &enabled
	return cfg
}

// The transcript is not an intent source unless the user opts in.
func TestTranscriptIntentIsOffByDefault(t *testing.T) {
	for name, prompt := range map[string]string{"request": "delete the build folder", "stop": "stop"} {
		t.Run(name, func(t *testing.T) {
			_, path := agHome(t, "c1", userRecord(prompt))
			call := rmBuild(t, "c1", path)
			var stderr bytes.Buffer
			if hold := applySessionContext(call, config.DefaultConfig(), &stderr); hold != nil {
				t.Fatalf("unexpected hold: %+v", hold)
			}
			if call.UserIntent != "" || stderr.Len() != 0 {
				t.Fatalf("intent=%q stderr=%q", call.UserIntent, stderr.String())
			}
		})
	}
}

// With the setting off, none of the guard's denials or costs apply, to any agent.
func TestTranscriptGuardDoesNotRunWhenOff(t *testing.T) {
	_, canonical := agHome(t, "c1", userRecord("harmless"))
	work := t.TempDir()
	symlinkOrSkip(t, canonical, filepath.Join(work, "data"))
	// Only 4 KiB here, since the fast path is on: main's boundary resolver is itself quadratic on this shape,
	// which is not the guard's cost and would only slow this test down.
	long := "echo " + strings.Repeat("a/", 2<<10) + "z"
	huge := "echo " + strings.Repeat("x ", (1<<20)+1024)
	for name, call := range map[string]*harness.NormalizedToolCall{
		"commit message":     {ToolName: "Bash", Command: `git commit -m 'Document trans"cript.jsonl naming'`, Cwd: work},
		"text rule":          {ToolName: "Bash", Command: `git commit -m 'about transcript.jsonl and .system_generated and antigravity/brain'`, Cwd: work},
		"long path":          {ToolName: "Bash", Command: long, Cwd: work},
		"over every budget":  {ToolName: "Bash", Command: huge, Cwd: work},
		"alias in a command": {ToolName: "Bash", Command: "wc -c data", Cwd: work},
	} {
		for _, harnessType := range []harness.HarnessType{harness.HarnessClaudeCode, harness.HarnessCodex, harness.HarnessAntigravity} {
			for mode, fastpathOn := range map[string]bool{"fastpath on": true, "fastpath off": false} {
				t.Run(name+"/"+string(harnessType)+"/"+mode, func(t *testing.T) {
					c := *call
					c.Harness = harnessType
					trace := traceGateEvaluation(&c, withFastpath(config.DefaultConfig(), fastpathOn), true)
					if trace.Final != nil && (trace.Final.Source == "fastpath_tampering" || trace.Final.Source == "transcript_guard_limit") {
						t.Fatalf("guard ran with the setting off: %+v", trace.Final)
					}
				})
			}
		}
	}
	// With the fast path off nothing else walks a path, so the full reviewed shape passes straight through.
	t.Run("256 KiB path with the fast path off", func(t *testing.T) {
		call := &harness.NormalizedToolCall{ToolName: "Bash", Command: "echo " + strings.Repeat("a/", 128<<10) + "z", Cwd: work}
		trace := traceGateEvaluation(call, withFastpath(config.DefaultConfig(), false), true)
		if trace.Final != nil || !trace.WouldSendToJudge {
			t.Fatalf("expected it to reach the judge, got %+v", trace.Final)
		}
	})
}

// With the setting on, any agent could forge the transcript, so it applies to all of them.
func TestTranscriptGuardRunsForEveryAgentWhenOn(t *testing.T) {
	_, canonical := agHome(t, "c1", userRecord("harmless"))
	work := t.TempDir()
	symlinkOrSkip(t, canonical, filepath.Join(work, "data"))
	for _, harnessType := range []harness.HarnessType{harness.HarnessClaudeCode, harness.HarnessCodex, harness.HarnessAntigravity} {
		for mode, fastpathOn := range map[string]bool{"fastpath on": true, "fastpath off": false} {
			t.Run(string(harnessType)+"/"+mode, func(t *testing.T) {
				for _, call := range []*harness.NormalizedToolCall{
					{Harness: harnessType, ToolName: "Bash", Command: "cat data", Cwd: work},
					{Harness: harnessType, ToolName: "Write", TargetPath: "data", Cwd: work},
					{Harness: harnessType, ToolName: "Bash", Command: "cat x/transcript.jsonl", Cwd: work},
				} {
					final := traceGateEvaluation(call, withFastpath(transcriptOnConfig(), fastpathOn), true).Final
					if final == nil || final.Decision != harness.DecisionDeny || final.Source != "fastpath_tampering" {
						t.Errorf("%+v: got %+v", call, final)
					}
				}
			})
		}
	}
}

// An agent must not be able to turn the setting on itself.
func TestUserConfigStaysProtectedFromAgents(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	file := filepath.Join(home, ".jevguard", ".jevguard.json")
	for name, call := range map[string]*harness.NormalizedToolCall{
		"file tool": {ToolName: "Write", TargetPath: file, RawArgs: map[string]any{"file_path": file}},
		"tilde":     {ToolName: "Write", TargetPath: "~/.jevguard/.jevguard.json"},
		"command":   {ToolName: "Bash", Command: `echo '{"antigravity_transcript_intent":true}' > ~/.jevguard/.jevguard.json`},
	} {
		t.Run(name, func(t *testing.T) {
			for label, cfg := range map[string]*config.Config{"off": config.DefaultConfig(), "on": transcriptOnConfig()} {
				final := traceGateEvaluation(call, cfg, true).Final
				if final == nil || final.Decision != harness.DecisionDeny {
					t.Errorf("%s: expected DENY, got %+v", label, final)
				}
			}
		})
	}
}

// A real write through a whitespace-only name, then accepted forged intent: the guard has
// to stop the write, because the reader cannot tell it apart from Antigravity's.
func TestTranscriptWhitespaceOnlyAlias(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not keep names made only of spaces")
	}
	_, canonical := agHome(t, "c1", userRecord("harmless"))
	work := t.TempDir()
	symlinkOrSkip(t, canonical, filepath.Join(work, " "))
	symlinkOrSkip(t, canonical, filepath.Join(work, "\t"))
	symlinkOrSkip(t, filepath.Dir(canonical), filepath.Join(work, "  "))
	for name, call := range map[string]*harness.NormalizedToolCall{
		"target":            {TargetPath: " ", Cwd: work},
		"argument":          {TargetPath: "ok.txt", Cwd: work, RawArgs: map[string]any{"file_path": " "}},
		"unknown argument":  {Cwd: work, RawArgs: map[string]any{"output": " "}},
		"tab":               {TargetPath: "\t", Cwd: work},
		"quoted word":       {Command: `printf x > ' '`, Cwd: work},
		"double quoted":     {Command: `printf x > " "`, Cwd: work},
		"escaped":           {Command: `printf x > \ `, Cwd: work},
		"working directory": {Command: "ls", Cwd: filepath.Join(work, "  ")},
		"directory arg":     {Command: "ls", Cwd: work, RawArgs: map[string]any{"workdir": "  "}},
		"relative dir arg":  {TargetPath: "new", Cwd: work, RawArgs: map[string]any{"cwd": "  "}},
	} {
		t.Run(name, func(t *testing.T) {
			if res := fastpath.CheckTranscriptTampering(call); res == nil || res.Decision != harness.DecisionDeny {
				t.Fatalf("expected DENY, got %+v", res)
			}
		})
	}
	// A blank value that is not a real name changes nothing.
	for name, call := range map[string]*harness.NormalizedToolCall{
		"no such name":   {TargetPath: "   ", Cwd: t.TempDir()},
		"empty argument": {RawArgs: map[string]any{"path": "", "cwd": ""}, Cwd: t.TempDir()},
	} {
		t.Run("allowed/"+name, func(t *testing.T) {
			if res := fastpath.CheckTranscriptTampering(call); res != nil {
				t.Fatalf("unexpected result: %+v", res)
			}
		})
	}
	for _, shellName := range []string{"bash", "sh"} {
		t.Run("real "+shellName, func(t *testing.T) {
			shell, err := exec.LookPath(shellName)
			if err != nil {
				t.Skipf("%s unavailable", shellName)
			}
			run := exec.Command(shell, "-c", `printf '%s\n' "$R" >> ' '`)
			run.Dir = work
			run.Env = []string{"R=" + strings.TrimSpace(userRecord("forged through a space"))}
			if out, err := run.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			call := rmBuild(t, "c1", canonical)
			if hold := applySessionContext(call, transcriptOnConfig(), io.Discard); hold != nil || call.UserIntent != "forged through a space" {
				t.Fatalf("the fixture must forge intent: hold=%+v intent=%q", hold, call.UserIntent)
			}
		})
	}
}

// inTime fails if the guard outlives a limit far above what any budgeted input needs,
// without depending on how fast the machine is.
func inTime(t *testing.T, call *harness.NormalizedToolCall) *harness.EvaluationResult {
	t.Helper()
	done := make(chan *harness.EvaluationResult, 1)
	go func() { done <- fastpath.CheckTranscriptTampering(call) }()
	select {
	case res := <-done:
		return res
	case <-time.After(30 * time.Second):
		t.Fatalf("guard still running after 30s on a %d byte command", len(call.Command))
		return nil
	}
}

func TestTranscriptGuardStaysLinear(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
	}{
		{"deep path", "echo " + strings.Repeat("a/", 128<<10) + "z"},
		{"dot-dot path", "echo " + strings.Repeat("a/../", 50<<10) + "z"},
		{"repeated brain segments", "echo " + strings.Repeat(".gemini/antigravity/x/", 10<<10)},
		{"many words", "echo " + strings.Repeat("word ", 50<<10)},
		{"ansi quotes", "echo " + strings.Repeat(`$'\x61'`, 50<<10)},
		{"substitutions", "echo " + strings.Repeat("$(a ", 50<<10)},
		{"nested shells", strings.Repeat(`sh -c "`, 10<<10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if res := inTime(t, &harness.NormalizedToolCall{Command: tc.command, Cwd: t.TempDir()}); res != nil && res.Source != "transcript_guard_limit" {
				t.Fatalf("unexpected result: %+v", res)
			}
		})
	}
	t.Run("long file tool target", func(t *testing.T) {
		if res := inTime(t, &harness.NormalizedToolCall{TargetPath: strings.Repeat(".gemini/antigravity/brain/", 40<<10) + "x", Cwd: t.TempDir()}); res != nil && res.Source != "transcript_guard_limit" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}

func numbered(format string, count int) string {
	var b strings.Builder
	for i := range count {
		fmt.Fprintf(&b, format, i)
	}
	return b.String()
}

// Over budget is an explicit result, never a pass.
func TestTranscriptGuardBudgetFailsClosed(t *testing.T) {
	dir := t.TempDir()
	symlinkOrSkip(t, "loop", filepath.Join(dir, "loop"))
	for name, call := range map[string]*harness.NormalizedToolCall{
		"command too long":   {Command: "echo " + strings.Repeat("x", 3<<20), Cwd: dir},
		"too many words":     {Command: "echo " + numbered("w%d ", 60_000), Cwd: dir},
		"too many lookups":   {Command: "echo " + numbered("q%d/../", 70_000), Cwd: dir},
		"too many parts":     {Command: "echo " + strings.Repeat("a/", (2<<20)/2-16), Cwd: dir},
		"symlink loop":       {Command: "cat loop", Cwd: dir},
		"symlink loop, file": {TargetPath: "loop", Cwd: dir},
		"target too long":    {TargetPath: strings.Repeat("a/", 1<<20), Cwd: dir},
	} {
		t.Run(name, func(t *testing.T) {
			res := inTime(t, call)
			if res == nil || res.Source != "transcript_guard_limit" || res.Decision != harness.DecisionAsk || !strings.Contains(res.Reason, "could not be verified") {
				t.Fatalf("expected a stated ASK, got %+v", res)
			}
		})
	}
	// Through the gate, in both fast path settings.
	for mode, fastpathOn := range map[string]bool{"fastpath on": true, "fastpath off": false} {
		t.Run("gate/"+mode, func(t *testing.T) {
			call := &harness.NormalizedToolCall{ToolName: "Bash", Command: "echo " + strings.Repeat("x", 3<<20), Cwd: dir}
			final := traceGateEvaluation(call, withFastpath(transcriptOnConfig(), fastpathOn), true).Final
			if final == nil || final.Source != "transcript_guard_limit" {
				t.Fatalf("got %+v", final)
			}
		})
	}
}

// Quoted text stays text. Only strings a program will run are read as commands.
func TestLiteralContentIsNotReinterpreted(t *testing.T) {
	cwd := t.TempDir()
	for name, command := range map[string]string{
		"commit message":          `git commit -m 'Document trans"cript.jsonl naming'`,
		"echo single quoted":      `echo 'anti"gravity/brain'`,
		"double quoted literal":   `echo "trans'cript.jsonl"`,
		"system dir in message":   `git commit -m 'the .system_gen"erated dir'`,
		"quoted heredoc":          "cat <<'EOF' > notes.md\ntrans\"cript.jsonl\nEOF",
		"unquoted heredoc":        "cat <<EOF > notes.md\nanti\"gravity/brain\nEOF",
		"indented heredoc":        "cat <<-EOF > notes.md\n\ttrans'cript.jsonl\n\tEOF",
		"message then command":    `git commit -m 'a trans"cript.jsonl b' && git log`,
		"message mentions a path": `git commit -m 'see ~/.gemini/anti"gravity/brain for it'`,
	} {
		t.Run(name, func(t *testing.T) {
			if res := fastpath.CheckTranscriptTampering(&harness.NormalizedToolCall{Command: command, Cwd: cwd}); res != nil {
				t.Fatalf("unexpected denial of %q: %+v", command, res)
			}
		})
	}

	_, _, work := aliasFixture(t)
	for name, command := range map[string]string{
		"sh -c":                   `sh -c 'cat d\ata'`,
		"bash login shell":        `bash -lc 'cat d\ata'`,
		"bash separate flags":     `bash -l -c 'cat d\ata'`,
		"absolute shell":          `/bin/sh -c 'cat d\ata'`,
		"wrapped in env":          `env FOO=1 sh -c 'cat d\ata'`,
		"nested":                  `bash -c "sh -c 'cat d\\ata'"`,
		"cmd /c":                  "cmd /c type d^ata",
		"cmd.exe /C upper":        "cmd.exe /C type d^ata",
		"powershell -Command":     "powershell -Command Get-Content d`ata",
		"pwsh short":              "pwsh -c Get-Content d`ata",
		"eval":                    `eval 'cat d\ata'`,
		"python -c":               `python3 -c "open('data','w')"`,
		"node -e":                 `node -e "require('fs').writeFileSync('data','x')"`,
		"perl -e":                 `perl -e 'open(F,">data")'`,
		"substitution in quotes":  `echo "$(cat d\ata)"`,
		"backtick in quotes":      "echo \"`cat d\\ata`\"",
		"text rule in sh -c":      `sh -c 'cat trans"cript".jsonl'`,
		"shell reading a heredoc": "bash <<EOF\ncat d\\ata\nEOF",
		"quoted heredoc marker":   "echo '<<X'\ncat d\\ata\nX",
		"comment heredoc marker":  "# <<X\ncat d\\ata\nX",
		"after a heredoc":         "cat <<EOF\nbody\nEOF\ncat d\\ata",
	} {
		t.Run("denied/"+name, func(t *testing.T) {
			if res := fastpath.CheckTranscriptTampering(&harness.NormalizedToolCall{Command: command, Cwd: work}); res == nil {
				t.Fatalf("%q not denied", command)
			}
		})
	}
	// The text rule still sees a spelled-out name outside any heredoc.
	for name, command := range map[string]string{
		"comment marker hides text":  "# <<X\ncat trans\"cript\".jsonl\nX",
		"quoted marker hides text":   "echo '<<X'\ncat trans\"cript\".jsonl\nX",
		"after heredoc":              "cat <<EOF\nbody\nEOF\ncat trans\"cript\".jsonl",
		"unterminated heredoc words": "cat trans\"cript\".jsonl <<EOF\nbody",
	} {
		t.Run("text denied/"+name, func(t *testing.T) {
			if res := fastpath.CheckTranscriptTampering(&harness.NormalizedToolCall{Command: command, Cwd: cwd}); res == nil {
				t.Fatalf("%q not denied", command)
			}
		})
	}
}

// On Windows the backslash in d\\ata is a separator for cmd.exe and PowerShell, but an escape
// for Git Bash, which also spells drives as /c/Users. So both Git Bash spellings must be caught.
func TestGitBashPathsOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	_, _, work := aliasFixture(t)
	slashed := filepath.ToSlash(work)
	msys := "/" + slashed[:1] + slashed[2:]
	other := t.TempDir()
	for name, command := range map[string]string{
		"forward slashes, escaped name": "cat " + slashed + `/d\ata`,
		"drive as a directory":          "cat " + msys + "/data",
		"drive as a directory, escaped": "cat " + msys + `/d\ata`,
	} {
		t.Run(name, func(t *testing.T) {
			if res := fastpath.CheckTranscriptTampering(&harness.NormalizedToolCall{Command: command, Cwd: other}); res == nil {
				t.Fatalf("%q not denied", command)
			}
		})
	}
	// A real Git Bash, when the runner has one, shows the spelling reaches the alias.
	shell := `C:\Program Files\Git\bin\bash.exe`
	if _, err := os.Stat(shell); err != nil {
		t.Skip("Git Bash unavailable")
	}
	_, canonical, work2 := aliasFixture(t)
	command := "printf forged >> " + filepath.ToSlash(work2) + `/d\ata`
	run := exec.Command(shell, "--noprofile", "--norc", "-c", command)
	run.Env = append(os.Environ(), "MSYS=winsymlinks:nativestrict")
	if out, err := run.CombinedOutput(); err != nil {
		t.Skipf("Git Bash could not run the fixture: %v: %s", err, out)
	}
	data, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "forged") {
		t.Skip("Git Bash did not write through this native symlink on this runner")
	}
	t.Log("Git Bash wrote through the alias with an escaped name")
}

// An argument list gets the same size limit as a command string, for one word and in total.
func TestTranscriptGuardBudgetCoversCommandLists(t *testing.T) {
	for name, list := range map[string][]string{
		"one oversized word":  {"echo", strings.Repeat("x", 3<<20)},
		"many words in total": {"echo", strings.Repeat("x", 3000), strings.Repeat("y z", 1<<20)},
		"oversized in total":  {"echo", strings.Repeat("x", 3<<19), strings.Repeat("y", 3<<19)},
	} {
		t.Run(name, func(t *testing.T) {
			res := fastpath.CheckTranscriptTampering(&harness.NormalizedToolCall{
				ToolName: "run_command",
				Cwd:      t.TempDir(),
				RawArgs:  map[string]interface{}{"command": list},
			})
			if res == nil || res.Source != "transcript_guard_limit" || res.Decision != harness.DecisionAsk {
				t.Fatalf("expected a stated ASK, got %+v", res)
			}
		})
	}
}

// Audit mode reports every verdict without enforcing it (docs/configuration.md), and the
// limit's ASK is no exception. The rewritten reason has to say what would have happened.
func TestTranscriptGuardLimitIsReportedInAuditMode(t *testing.T) {
	for mode, fastpathOn := range map[string]bool{"fastpath on": true, "fastpath off": false} {
		t.Run(mode, func(t *testing.T) {
			cfg := withFastpath(transcriptOnConfig(), fastpathOn)
			cfg.Mode = "audit"
			call := &harness.NormalizedToolCall{ToolName: "Bash", Command: "echo " + strings.Repeat("x", 3<<20), Cwd: t.TempDir()}
			final := traceGateEvaluation(call, cfg, true).Final
			if final == nil || final.Decision != harness.DecisionAllow || final.Source != "transcript_guard_limit" || !strings.HasPrefix(final.Reason, "[AUDIT-MODE: ask] ") {
				t.Fatalf("got %+v", final)
			}
		})
	}
}
