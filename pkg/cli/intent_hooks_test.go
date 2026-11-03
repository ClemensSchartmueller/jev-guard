package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jev-guard/pkg/session"
)

// writeHooks writes a hook settings file, creating its directory.
func writeHooks(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorWarnsWhenCodexLacksIntentHooks(t *testing.T) {
	dir, home := t.TempDir(), t.TempDir()
	path := initSettingsPath("codex", "project", dir, home)
	if _, err := installAgentHooks(path, "codex", "jev-guard"); err != nil {
		t.Fatal(err)
	}

	out, _ := doctorRun(t, &Runner{}, doctorConfig(t), dir, home, true)
	if !strings.Contains(out, "[OK]   Intent (codex): UserPromptSubmit and Stop registered") {
		t.Fatalf("init-generated Codex hooks should report intent:\n%s", out)
	}

	// A pre-existing PreToolUse-only file, as older releases generated.
	writeHooks(t, path, `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"jev-guard"}]}]}}`)
	out, _ = doctorRun(t, &Runner{}, doctorConfig(t), dir, home, true)
	if !strings.Contains(out, "[WARN] Intent (codex): no jev-guard UserPromptSubmit or Stop hook") {
		t.Fatalf("missing intent hooks should warn:\n%s", out)
	}
}

func TestDoctorFindsIntentHooksInEitherScope(t *testing.T) {
	dir, home := t.TempDir(), t.TempDir()
	writeHooks(t, initSettingsPath("claude", "project", dir, home), `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"jev-guard"}]}]}}`)
	writeHooks(t, initSettingsPath("claude", "user", dir, home), `{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"jev-guard ingest"}]}],"Stop":[{"hooks":[{"type":"command","command":"jev-guard end-turn"}]}]}}`)
	out, _ := doctorRun(t, &Runner{}, doctorConfig(t), dir, home, true)
	if !strings.Contains(out, "[OK]   Intent (claude)") {
		t.Fatalf("user-scope intent hooks should count:\n%s", out)
	}
}

func TestDoctorReportsTranscriptIntentSetting(t *testing.T) {
	dir, home := t.TempDir(), t.TempDir()
	on, off := true, false

	out, _ := doctorRun(t, &Runner{}, doctorConfig(t), dir, home, true)
	if !strings.Contains(out, "[OK]   Antigravity transcript intent: off") {
		t.Fatalf("default not reported as off, even with no Antigravity hooks:\n%s", out)
	}

	cfg := doctorConfig(t)
	cfg.AntigravityTranscriptIntent = &on
	out, _ = doctorRun(t, &Runner{}, cfg, dir, home, true)
	if !strings.Contains(out, "[WARN] Antigravity transcript intent: on") || !strings.Contains(out, "forge") {
		t.Fatalf("opt-in not reported with its risk:\n%s", out)
	}

	cfg.ContextAwarenessEnabled = &off
	out, _ = doctorRun(t, &Runner{}, cfg, dir, home, true)
	if !strings.Contains(out, "context awareness is off") {
		t.Fatalf("on without context awareness reads nothing, and must say so:\n%s", out)
	}
}

func TestStatusReportsTranscriptIntentSetting(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	runner, stdout, _ := newStdinRunner("")
	if _, code := runner.EvaluateArgs([]string{"status"}); code != 0 {
		t.Fatalf("status exit %d", code)
	}
	if !strings.Contains(stdout.String(), "Antigravity transcript intent: off") {
		t.Fatalf("setting missing:\n%s", stdout.String())
	}
}

// The obsolete Antigravity PreInvocation hook must stay removed even though Antigravity now has intent.
func TestInitAntigravityInstallsNoIntentHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	writeHooks(t, path, `{"jev-guard":{"PreInvocation":[{"type":"command","command":"jev-guard ingest"}]}}`)
	if _, err := installAgentHooks(path, "antigravity", "jev-guard"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"PreInvocation", "UserPromptSubmit", "Stop"} {
		if strings.Contains(string(data), event) {
			t.Errorf("%s must not be installed for Antigravity:\n%s", event, data)
		}
	}
	if !strings.Contains(string(data), "PreToolUse") {
		t.Errorf("PreToolUse missing:\n%s", data)
	}
}

func TestStatusShowsCodexTurnKey(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	if err := session.SaveSession(&session.SessionState{SessionID: "codex-s", TurnKey: "turn-abc", Prompt: "do it"}); err != nil {
		t.Fatal(err)
	}
	runner, stdout, _ := newStdinRunner("")
	if _, code := runner.EvaluateArgs([]string{"status"}); code != 0 {
		t.Fatalf("status exit %d", code)
	}
	if !strings.Contains(stdout.String(), "Turn: turn-abc") {
		t.Fatalf("turn key missing:\n%s", stdout.String())
	}
}

func TestIngestBlankTurnKeyFlagIsUnusable(t *testing.T) {
	for _, args := range [][]string{{"--turn-key=", "--prompt", "build it"}, {"--turn-key=  ", "--prompt", "build it"}} {
		t.Setenv("JEV_GUARD_HOME", t.TempDir())
		runner, _, stderr := newStdinRunner("")
		if _, code := runner.EvaluateArgs(append([]string{"ingest", "--session", "s"}, args...)); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		state, err := session.LoadSession("s")
		if err != nil || state == nil || !state.TurnUnusable {
			t.Fatalf("state=%+v err=%v", state, err)
		}
	}
}
