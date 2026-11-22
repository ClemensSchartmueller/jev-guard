package fastpath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jev-guard/pkg/harness"
)

func TestHookConfigChanges(t *testing.T) {
	home, ws := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	// Explicit expectations intentionally cover every install and override path.
	project := []string{".claude/settings.json", ".claude/settings.local.json", ".codex/hooks.json", ".codex/config.toml", ".agents/hooks.json"}
	user := []string{".claude/settings.json", ".claude/settings.local.json", ".codex/hooks.json", ".codex/config.toml", ".gemini/config/hooks.json"}
	paths := append([]string{}, project...)
	for _, path := range user {
		paths = append(paths, filepath.Join(home, path), "~/"+path)
	}
	for _, path := range project {
		paths = append(paths, "./"+path, filepath.Join(ws, path))
	}
	for _, path := range paths {
		for _, tool := range []string{"Write", "Edit", "MultiEdit", "NotebookEdit", "write_to_file", "replace_file_content", "multi_replace_file_content"} {
			call := &harness.NormalizedToolCall{ToolName: tool, TargetPath: path, Cwd: ws, UserIntent: "disable the guard"}
			assertHookConfigAsk(t, call)
		}
		for _, header := range []string{"Add File", "Update File", "Delete File", "Move to"} {
			call := &harness.NormalizedToolCall{ToolName: "apply_patch", Cwd: ws, RawArgs: map[string]interface{}{"input": "*** Begin Patch\n*** " + header + ": " + path + "\n*** End Patch"}}
			assertHookConfigAsk(t, call)
		}
		for _, command := range []string{"echo {} > " + path, "sed -i 's/jev-guard/other/g' " + path, "rm " + path, "mv " + path + " backup", "mv replacement " + path, "echo {} | tee " + path} {
			assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: ws})
		}
	}
	assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "exec_command", Cwd: ws, RawArgs: map[string]interface{}{"cmd": []interface{}{"bash", "-c", "rm .claude/settings.json"}}})
	for _, command := range []string{"rm -rf .claude", "mv .codex backup", "rm -rf .agents", "rm -rf ~/.gemini/config"} {
		assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: ws})
	}
	assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "MultiEdit", Cwd: ws, RawArgs: map[string]interface{}{"edits": []interface{}{map[string]interface{}{"file_path": ".codex/hooks.json"}}}})
	for _, call := range []*harness.NormalizedToolCall{
		{ToolName: "Write", TargetPath: ".claude/commands/foo.md", Cwd: ws},
		{ToolName: "Edit", TargetPath: "main.go", Cwd: ws},
		{ToolName: "Read", TargetPath: ".claude/settings.json", Cwd: ws},
		{ToolName: "Bash", Command: "cat .claude/settings.json", Cwd: ws},
		{ToolName: "Bash", Command: "echo hello > main.go", Cwd: ws},
	} {
		if result := CheckAntiTampering(call); result != nil {
			t.Errorf("negative control %+v: %+v", call, result)
		}
	}
}

func assertHookConfigAsk(t *testing.T, call *harness.NormalizedToolCall) {
	t.Helper()
	if result := CheckAntiTampering(call); result == nil || result.Decision != harness.DecisionAsk || result.Source != SourceHookConfig {
		t.Fatalf("%+v: got %+v; want hook-config ASK", call, result)
	}
}

func TestHookConfigSymlinks(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(ws, ".claude/settings.json")
	if err := os.WriteFile(config, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(ws, "alias")
	if err := os.Symlink(config, alias); err != nil {
		t.Skip(err)
	}
	assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Edit", TargetPath: alias, Cwd: ws})
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(ws, "ordinary.json")
	if err := os.Symlink(destination, config); err != nil {
		t.Fatal(err)
	}
	assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Write", TargetPath: destination, Cwd: ws})
}

func TestHookConfigReviewControls(t *testing.T) {
	ws := t.TempDir()
	for _, command := range []string{"ls .claude", "ls .agents", "git diff .claude/settings.json", "git log -p -- .claude/settings.json", "rg jev-guard .claude", "cat -n .claude/settings.json", "head -n 10 .claude/settings.json", "tail -n 10 .claude/settings.json", "jq . .claude/settings.json", "cat .claude/settings.json | jq .hooks", "wc -l .claude/settings.json", "stat .claude/settings.json", "file .claude/settings.json", "diff old .claude/settings.json", "git show HEAD:.claude/settings.json", "git status -- .claude/settings.json", "git blame .claude/settings.json"} {
		if got := checkHookConfigChanges(&harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: ws}); got != nil {
			t.Errorf("%s: %+v", command, got)
		}
	}
	if got := checkHookConfigChanges(&harness.NormalizedToolCall{ToolName: "WebFetch", TargetPath: "https://docs.example.com/.claude/settings.json", Cwd: ws}); got != nil {
		t.Fatal(got)
	}
	for _, command := range []string{"echo x > .claude/settings.js*", "echo x > .claude/setting?.json", "echo x > .claude/settings.{json,x}", "cd .cl* && echo x > settings.json", "ln -s .cl?ude c", "cp -r replacement .claude"} {
		assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: ws})
	}
}

func TestHookConfigEnvironmentRoots(t *testing.T) {
	for variable, files := range map[string][]string{"CODEX_HOME": {"hooks.json", "config.toml"}, "CLAUDE_CONFIG_DIR": {"settings.json", "settings.local.json"}} {
		root := t.TempDir()
		t.Setenv(variable, root)
		for _, file := range files {
			assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Write", TargetPath: filepath.Join(root, file), Cwd: t.TempDir()})
			for _, prefix := range []string{"$" + variable, "${" + variable + "}", root} {
				assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: "echo x > " + prefix + "/" + file, Cwd: t.TempDir()})
			}
		}
	}
}

func TestHookConfigReviewWriteTargets(t *testing.T) {
	ws := t.TempDir()
	writes := []string{
		`bash -c 'rm .claude/settings.json'`, `sh -c 'rm .claude/settings.json'`, `cmd /c 'del .claude/settings.json'`, `powershell -c 'Clear-Content .claude/settings.json'`,
		`/bin/rm .claude/settings.json`, `/usr/bin/cp /dev/null .claude/settings.json`, `\rm .claude/settings.json`,
		`git checkout HEAD~1 -- .claude/settings.json`, `git restore .claude/settings.json`, `git checkout .claude`,
		`unlink .claude/settings.json`, `shred -u .claude/settings.json`, `curl -o .claude/settings.json URL`, `wget -O .claude/settings.json URL`, `rsync x .claude/settings.json`, `sort -o .claude/settings.json x`, `uniq x .claude/settings.json`, `yq -i .hooks .claude/settings.json`, `vim .claude/settings.json`, `ed .claude/settings.json`,
		`Rename-Item .claude/settings.json backup`, `Clear-Content .claude/settings.json`, `New-Item -Force .claude/settings.json`,
		`copy x .claude/settings.json`, `move .claude/settings.json x`, `del .claude/settings.json`, `erase .claude/settings.json`, `ren .claude/settings.json x`, `xcopy x .claude/settings.json`, `robocopy x .claude/settings.json`,
		`git diff --output=.claude/settings.json`, `cd .claude && echo x > settings.json`, `cd .codex; echo x > hooks.json`, `cd ~/.claude; echo x > settings.json`, `cd .claude/commands; rm ../settings.json`,
		`mv .claude/settings.json /tmp/bak`, `awk '{print > ".claude/settings.json"}' x`,
	}
	for _, command := range writes {
		t.Run(command, func(t *testing.T) {
			assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: ws})
		})
	}
	reads := []string{`cat .claude/settings.json > /tmp/out`, `git diff .claude/settings.json > /tmp/p.diff`, `jq .hooks .claude/settings.json > hooks.txt`, `cp .claude/settings.json /tmp/bak.json`, `cat .claude/settings.json; echo hi > log.txt`, `python3 -c "print(1)"; cat .claude/settings.json`, `sed -n 1,5p .claude/settings.json`, `awk 1 .claude/settings.json`, `git diff --output=/tmp/out .claude/settings.json`}
	for _, command := range reads {
		t.Run(command, func(t *testing.T) {
			if got := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: ws}); got != nil {
				t.Fatalf("want no verdict, got %+v", got)
			}
		})
	}
}

func TestHookConfigDeepPatternTiming(t *testing.T) {
	for _, tc := range []struct {
		depth, words int
		suffix       string
	}{{200, 50, ""}, {200, 200, ""}, {33, 600, "; echo x > .claude/settings.json"}} {
		cwd := t.TempDir()
		for i := 0; i < tc.depth; i++ {
			cwd = filepath.Join(cwd, "d")
		}
		if err := os.MkdirAll(cwd, 0700); err != nil {
			t.Fatal(err)
		}
		var input strings.Builder
		input.WriteString("rm ")
		for i := 0; i < tc.words; i++ {
			fmt.Fprintf(&input, "{a,b,c,d,e,f,g,h}*%d ", i)
		}
		command := input.String() + tc.suffix
		start := time.Now()
		got := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: cwd})
		elapsed := time.Since(start)
		t.Logf("depth=%d words=%d bytes=%d elapsed=%s", tc.depth, tc.words, len(command), elapsed)
		if elapsed > 2*time.Second {
			t.Fatalf("analysis took %s", elapsed)
		}
		if got == nil || got.Decision != harness.DecisionAsk {
			t.Fatalf("want ASK, got %+v", got)
		}
	}
}
