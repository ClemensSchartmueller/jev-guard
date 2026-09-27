package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallAgentHooksPreservesSettingsAndIsIdempotent(t *testing.T) {
	for _, agent := range initAgents {
		t.Run(agent, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hooks.json")
			original := `{"unrelated":{"keep":true},"hooks":{"PreToolUse":[{"matcher":"Other","hooks":[{"type":"command","command":"other-hook"}]}]},"jev-guard":{"Stop":[{"command":"other-stop"}]}}`
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			changed, err := installAgentHooks(path, agent, `"/some path/jev-guard"`)
			if err != nil || !changed {
				t.Fatalf("first install: changed=%v err=%v", changed, err)
			}
			first, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed, err = installAgentHooks(path, agent, `"/some path/jev-guard"`)
			if err != nil || changed {
				t.Fatalf("second install: changed=%v err=%v", changed, err)
			}
			second, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(first, second) {
				t.Fatal("idempotent run modified settings")
			}
			var root map[string]interface{}
			if err := json.Unmarshal(second, &root); err != nil {
				t.Fatal(err)
			}
			if !root["unrelated"].(map[string]interface{})["keep"].(bool) {
				t.Fatal("unrelated key lost")
			}
			if !bytes.Contains(second, []byte("other-hook")) || !bytes.Contains(second, []byte("other-stop")) {
				t.Fatal("existing hooks lost")
			}
			if agent == "antigravity" {
				section := root["jev-guard"].(map[string]interface{})
				if _, ok := section["PreInvocation"]; ok {
					t.Fatal("unexpected Antigravity PreInvocation hook without prompt data")
				}
				if _, ok := section["PreToolUse"]; !ok {
					t.Fatal("missing Antigravity gate hook")
				}
			} else {
				section := root["hooks"].(map[string]interface{})
				if _, ok := section["PreToolUse"]; !ok {
					t.Fatal("missing gate hook")
				}
				if agent == "claude" {
					if _, ok := section["UserPromptSubmit"]; !ok {
						t.Fatal("missing Claude intent hook")
					}
				}
			}
		})
	}
}

func TestInstallAgentHooksRejectsMalformedSettingsWithoutEditing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	original := []byte(`{"hooks":{"PreToolUse":{}}}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := installAgentHooks(path, "codex", `"/bin/jev-guard"`); err == nil {
		t.Fatal("expected schema error")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, after) {
		t.Fatal("malformed settings were modified")
	}
}

func TestInstallAgentHooksMigratesLegacyCommandWithoutDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	legacy := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"jev-guard"}]}],"UserPromptSubmit":[{"matcher":".*","hooks":[{"type":"command","command":"jev-guard ingest"}]}]}}`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := installAgentHooks(path, "claude", `"/new path/jev-guard"`)
	if err != nil || !changed {
		t.Fatalf("migration: changed=%v err=%v", changed, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	hooks := root["hooks"].(map[string]interface{})
	for _, event := range []string{"PreToolUse", "UserPromptSubmit"} {
		entries := hooks[event].([]interface{})
		if len(entries) != 1 {
			t.Fatalf("%s has %d entries after migration", event, len(entries))
		}
		command := entries[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})["command"].(string)
		if !strings.HasPrefix(command, `"/new path/jev-guard"`) {
			t.Fatalf("%s command not migrated: %q", event, command)
		}
	}
}

func TestInstallAgentHooksWidensDedicatedMatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	command := `"/new path/jev-guard"`
	original := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"\"/new path/jev-guard\""}]}]}}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := installAgentHooks(path, "codex", command)
	if err != nil || !changed {
		t.Fatalf("install: changed=%v err=%v", changed, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	entries := root["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
	if len(entries) != 1 {
		t.Fatalf("got %d hook entries, want one", len(entries))
	}
	if got := entries[0].(map[string]interface{})["matcher"]; got != "Bash|exec_command|apply_patch|view_file|read_file|list_dir" {
		t.Fatalf("matcher remains too narrow: %v", got)
	}
}

func TestInstallAgentHooksPreservesSharedMatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	command := `"/new path/jev-guard"`
	original := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"jev-guard"},{"type":"command","command":"other-hook"}]}]}}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := installAgentHooks(path, "codex", command)
	if err != nil || !changed {
		t.Fatalf("install: changed=%v err=%v", changed, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	entries := root["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
	if len(entries) != 2 {
		t.Fatalf("got %d hook entries, want two", len(entries))
	}
	shared := entries[0].(map[string]interface{})
	if shared["matcher"] != "Bash" {
		t.Fatal("shared matcher changed")
	}
	remaining := shared["hooks"].([]interface{})
	if len(remaining) != 1 || remaining[0].(map[string]interface{})["command"] != "other-hook" {
		t.Fatal("other hook changed")
	}
	dedicated := entries[1].(map[string]interface{})
	if dedicated["matcher"] != "Bash|exec_command|apply_patch|view_file|read_file|list_dir" {
		t.Fatal("new jev-guard matcher is too narrow")
	}
	if dedicated["hooks"].([]interface{})[0].(map[string]interface{})["command"] != command {
		t.Fatal("new command missing")
	}
	changed, err = installAgentHooks(path, "codex", command)
	if err != nil || changed {
		t.Fatalf("repeat install: changed=%v err=%v", changed, err)
	}
}

func TestInstallAgentHooksEnablesAntigravityGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	original := `{"jev-guard":{"enabled":false,"PreInvocation":[{"type":"command","command":"jev-guard ingest"},{"type":"command","command":"custom-hook"}],"PreToolUse":[{"matcher":"run_command","hooks":[{"type":"command","command":"jev-guard"}]}]}}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := installAgentHooks(path, "antigravity", `"/bin/jev-guard"`)
	if err != nil || !changed {
		t.Fatalf("install: changed=%v err=%v", changed, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	section := root["jev-guard"].(map[string]interface{})
	if section["enabled"] != true {
		t.Fatal("Antigravity group remains disabled")
	}
	preInvocation := section["PreInvocation"].([]interface{})
	if len(preInvocation) != 1 || preInvocation[0].(map[string]interface{})["command"] != "custom-hook" {
		t.Fatalf("managed PreInvocation ingest hook was not removed while preserving other hooks: %#v", preInvocation)
	}
	changed, err = installAgentHooks(path, "antigravity", `"/bin/jev-guard"`)
	if err != nil || changed {
		t.Fatalf("repeat install: changed=%v err=%v", changed, err)
	}
}

func TestInitAutoDetectsPresentAgents(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(cwd, ".codex"), 0700); err != nil {
		t.Fatal(err)
	}
	got := selectInitAgents("", "project", cwd, home)
	if len(got) != 1 || got[0] != "codex" {
		t.Fatalf("detected %v, want codex", got)
	}
	got = selectInitAgents("", "project", t.TempDir(), home)
	if len(got) != 3 {
		t.Fatalf("no detection returned %v, want all three", got)
	}
}

func TestInitCommandRejectsInvalidOptions(t *testing.T) {
	for _, args := range [][]string{{"init", "--scope", "bad"}, {"init", "--agent", "bad"}, {"init", "--agent"}, {"init", "--mystery"}} {
		var stdout, stderr bytes.Buffer
		runner := NewRunner(&stdout, &stderr, func() bool { return false })
		action, code := runner.EvaluateArgs(args)
		if action != ActionHandled || code != 1 || !strings.Contains(stderr.String(), "Error:") {
			t.Fatalf("args %v: action=%v code=%d stderr=%q", args, action, code, stderr.String())
		}
	}
}

func TestQuoteHookExecutableForOS(t *testing.T) {
	unixPath := `/tmp/a' b$HOME;$(touch bad)/jev-guard`
	quoted, err := quoteHookExecutableForOS(unixPath, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if quoted != `'/tmp/a'"'"' b$HOME;$(touch bad)/jev-guard'` {
		t.Fatalf("unsafe Unix quoting: %q", quoted)
	}
	windowsPath := `C:\Users\Alice Smith\.jevguard\bin\jev-guard.exe`
	quoted, err = quoteHookExecutableForOS(windowsPath, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if quoted != `"C:\Users\Alice Smith\.jevguard\bin\jev-guard.exe"` {
		t.Fatalf("unexpected Windows quoting: %q", quoted)
	}
	for _, path := range []string{`C:\Users\%USERNAME%\jev-guard.exe`, `C:\Users\A!B\jev-guard.exe`, `C:\Users\$name\jev-guard.exe`, "/tmp/line\nbreak"} {
		if _, err := quoteHookExecutableForOS(path, "windows"); err == nil {
			t.Fatalf("accepted unsafe path %q", path)
		}
	}
}
