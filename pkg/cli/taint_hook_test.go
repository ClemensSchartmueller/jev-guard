package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jev-guard/pkg/config"
)

func TestInstallAgentHooksAddsClaudePostToolUseOnly(t *testing.T) {
	for _, agent := range initAgents {
		t.Run(agent, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hooks.json")
			if _, err := installAgentHooks(path, agent, `"/bin/jev-guard"`); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var root map[string]map[string]interface{}
			if err := json.Unmarshal(data, &root); err != nil {
				t.Fatal(err)
			}
			_, hasPost := root["hooks"]["PostToolUse"]
			if hasPost != (agent == "claude") {
				t.Fatalf("PostToolUse installed=%t for %s:\n%s", hasPost, agent, data)
			}
			if agent == "claude" && !strings.Contains(string(data), claudePostToolUseMatcher) {
				t.Fatalf("PostToolUse matcher %q missing:\n%s", claudePostToolUseMatcher, data)
			}
		})
	}
}

func TestDoctorReportsPostToolUse(t *testing.T) {
	dir, home := t.TempDir(), t.TempDir()
	exe := filepath.Join(dir, "jev-guard")
	if err := os.WriteFile(exe, []byte("x"), 0700); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(dir, ".claude", "settings.json")
	if _, err := installAgentHooks(settings, "claude", `"`+exe+`"`); err != nil {
		t.Fatal(err)
	}
	out, _ := doctorRun(t, &Runner{}, doctorConfig(t), dir, home, true)
	if !strings.Contains(out, "[OK]   Taint (claude): PostToolUse registered") || !strings.Contains(out, "taint_mode audit") {
		t.Fatalf("PostToolUse not reported:\n%s", out)
	}

	// A PreToolUse-only setup (installed before this hook existed) warns.
	hooks := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"\"` + strings.ReplaceAll(exe, `\`, `\\`) + `\""}]}]}}`
	if err := os.WriteFile(settings, []byte(hooks), 0600); err != nil {
		t.Fatal(err)
	}
	out, code := doctorRun(t, &Runner{}, doctorConfig(t), dir, home, true)
	if code != 0 || !strings.Contains(out, "[WARN] Taint (claude): no jev-guard PostToolUse entry") {
		t.Fatalf("missing PostToolUse should warn, exit %d:\n%s", code, out)
	}

	cfg := doctorConfig(t)
	cfg.TaintMode = config.TaintModeOff
	out, _ = doctorRun(t, &Runner{}, cfg, dir, home, true)
	if !strings.Contains(out, "[OK]   Taint (claude): off") {
		t.Fatalf("off mode not reported:\n%s", out)
	}
}
