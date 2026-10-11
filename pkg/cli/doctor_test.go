package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"jev-guard/pkg/config"
)

func doctorRun(t *testing.T, r *Runner, cfg *config.Config, cwd, home string, offline bool) (string, int) {
	t.Helper()
	var out bytes.Buffer
	r.Stdout = &out
	code := r.runDoctor(cfg, cwd, home, offline)
	return out.String(), code
}

func doctorConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.UserConfigPath = filepath.Join(t.TempDir(), ".jevguard.json")
	return cfg
}

func TestDoctorNoAPIKeyWarns(t *testing.T) {
	out, code := doctorRun(t, &Runner{}, doctorConfig(t), t.TempDir(), t.TempDir(), true)
	if !strings.Contains(out, "[WARN] API key: not configured") {
		t.Fatalf("expected API key warning, got:\n%s", out)
	}
	if code != 0 {
		t.Fatalf("warnings must not fail, got exit %d", code)
	}
}

func TestDoctorMasksAPIKey(t *testing.T) {
	cfg := doctorConfig(t)
	cfg.APIKey = "sk-supersecret"
	cfg.Sources["api_key"] = "TYPESAFE_API_KEY environment variable"
	out, _ := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), true)
	if strings.Contains(out, "supersecret") || !strings.Contains(out, "sk-***") {
		t.Fatalf("key not masked correctly:\n%s", out)
	}
}

func TestDoctorDetectsHooks(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	exe := filepath.Join(dir, "jev-guard")
	if err := os.WriteFile(exe, []byte("x"), 0700); err != nil {
		t.Fatal(err)
	}
	hooks := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"\"` + strings.ReplaceAll(exe, `\`, `\\`) + `\""}]}]}}`
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte(hooks), 0600); err != nil {
		t.Fatal(err)
	}
	out, code := doctorRun(t, &Runner{}, doctorConfig(t), dir, home, true)
	if !strings.Contains(out, "[OK]   Hooks (claude): PreToolUse registered in project scope") {
		t.Fatalf("claude hook not detected:\n%s", out)
	}
	if !strings.Contains(out, "[WARN] Hooks (codex)") {
		t.Fatalf("missing codex hook should warn:\n%s", out)
	}
	if code != 0 {
		t.Fatalf("exit %d", code)
	}

	// Missing command target is a failure.
	os.Remove(exe)
	out, code = doctorRun(t, &Runner{}, doctorConfig(t), dir, home, true)
	if code != 1 || !strings.Contains(out, "[FAIL] Hooks (claude)") {
		t.Fatalf("expected failure for missing command, exit %d:\n%s", code, out)
	}
}

func TestDoctorOfflineSkipsNetwork(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	cfg := doctorConfig(t)
	cfg.BaseURL = srv.URL
	out, _ := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), true)
	if hit || !strings.Contains(out, "Network: skipped") {
		t.Fatalf("offline should skip network (hit=%t):\n%s", hit, out)
	}
}

func TestDoctorNetworkReachable(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		auth = req.Header.Get("Authorization")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	cfg := doctorConfig(t)
	cfg.BaseURL = srv.URL
	cfg.APIKey = "sk-secret"
	out, _ := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), false)
	if !strings.Contains(out, "[OK]   Network: "+srv.URL+" reachable (HTTP 404") {
		t.Fatalf("expected reachable, got:\n%s", out)
	}
	if auth != "" {
		t.Fatalf("API key must not be sent, got %q", auth)
	}
}

func TestDoctorNetworkUnreachableFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	cfg := doctorConfig(t)
	cfg.BaseURL = url
	out, code := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), false)
	if code != 1 || !strings.Contains(out, "[FAIL] Network") {
		t.Fatalf("expected failure, exit %d:\n%s", code, out)
	}
}

func writeClaudeSettings(t *testing.T, dir string, commands ...string) {
	t.Helper()
	var hooks []string
	for _, c := range commands {
		b, _ := json.Marshal(c)
		hooks = append(hooks, `{"type":"command","command":`+string(b)+`}`)
	}
	data := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[` + strings.Join(hooks, ",") + `]}]}}`
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func fakeGuardExe(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "jev-guard")
	if err := os.WriteFile(exe, []byte("x"), 0700); err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestDoctorIgnoresUnrelatedHook(t *testing.T) {
	cwd := t.TempDir()
	writeClaudeSettings(t, cwd, "prettier-check")
	out, _ := doctorRun(t, &Runner{}, doctorConfig(t), cwd, t.TempDir(), true)
	if strings.Contains(out, "[OK]   Hooks (claude)") || !strings.Contains(out, "[WARN] Hooks (claude): no jev-guard PreToolUse entry") {
		t.Fatalf("unrelated hook must not count as jev-guard:\n%s", out)
	}

	// An unrelated hook listed before the jev-guard hook must be skipped.
	exe := fakeGuardExe(t)
	writeClaudeSettings(t, cwd, "prettier-check", `"`+exe+`"`)
	out, _ = doctorRun(t, &Runner{}, doctorConfig(t), cwd, t.TempDir(), true)
	if !strings.Contains(out, "[OK]   Hooks (claude): PreToolUse registered in project scope") || !strings.Contains(out, exe) || strings.Contains(out, "prettier-check") {
		t.Fatalf("expected jev-guard hook after unrelated hook:\n%s", out)
	}
}

func TestDoctorDetectsUserScopeHooks(t *testing.T) {
	home := t.TempDir()
	exe := fakeGuardExe(t)
	writeClaudeSettings(t, home, `"`+exe+`"`)
	out, code := doctorRun(t, &Runner{}, doctorConfig(t), t.TempDir(), home, true)
	if code != 0 || !strings.Contains(out, "[OK]   Hooks (claude): PreToolUse registered in user scope") {
		t.Fatalf("user-scope hook not detected, exit %d:\n%s", code, out)
	}
}

func doctorConfigWithFile(t *testing.T, diagnostics ...string) *config.Config {
	t.Helper()
	cfg := doctorConfig(t)
	if err := os.WriteFile(cfg.UserConfigPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Diagnostics = diagnostics
	return cfg
}

func TestDoctorProjectConfigDiagnosticWarns(t *testing.T) {
	cfg := doctorConfigWithFile(t, "project config at /repo/.jevguard.json is not trusted; built-in defaults and any valid user settings remain active")
	out, code := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), true)
	if code != 0 || strings.Contains(out, "[FAIL] User config") || !strings.Contains(out, "[OK]   User config:") ||
		!strings.Contains(out, "[WARN] Project config: project config at /repo/.jevguard.json is not trusted") {
		t.Fatalf("project config diagnostic should warn, exit %d:\n%s", code, out)
	}
}

func TestDoctorUserConfigDiagnosticFails(t *testing.T) {
	cfg := doctorConfigWithFile(t, "user config mode ignored: expected enforcing or audit")
	out, code := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), true)
	if code != 1 || !strings.Contains(out, "[FAIL] User config:") {
		t.Fatalf("user config diagnostic should fail, exit %d:\n%s", code, out)
	}
}

func TestDoctorAuditLogMissingDirIsOK(t *testing.T) {
	cfg := doctorConfig(t)
	cfg.AuditLogPath = filepath.Join(t.TempDir(), "logs", "jev", "audit.jsonl")
	out, code := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), true)
	if code != 0 || !strings.Contains(out, "[OK]   Audit log: directory for "+cfg.AuditLogPath+" will be created on first write") {
		t.Fatalf("missing audit dir should be OK, exit %d:\n%s", code, out)
	}
}

func TestDoctorAuditLogNotDirFails(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := doctorConfig(t)
	cfg.AuditLogPath = filepath.Join(f, "audit.jsonl")
	out, code := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), true)
	if code != 1 || !strings.Contains(out, "[FAIL] Audit log:") {
		t.Fatalf("non-directory audit path should fail, exit %d:\n%s", code, out)
	}
}

func TestHookExecutable(t *testing.T) {
	cases := []struct{ in, want string }{
		{`'/tmp/it'"'"'s/jev-guard'`, `/tmp/it's/jev-guard`},
		{`'/usr/local/bin/jev-guard' ingest`, `/usr/local/bin/jev-guard`},
		{`"C:\Program Files\jev-guard\jev-guard.exe"`, `C:\Program Files\jev-guard\jev-guard.exe`},
		{`jev-guard ingest`, `jev-guard`},
		{`  jev-guard  `, `jev-guard`},
		{``, ``},
	}
	for _, c := range cases {
		if got := hookExecutable(c.in); got != c.want {
			t.Errorf("hookExecutable(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDoctorRejectsNonExecutableAbsoluteHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not use Unix execute permissions")
	}
	exe := fakeGuardExe(t)
	if err := os.Chmod(exe, 0600); err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	writeClaudeSettings(t, cwd, `"`+exe+`"`)
	out, code := doctorRun(t, &Runner{}, doctorConfig(t), cwd, t.TempDir(), true)
	if code != 1 || !strings.Contains(out, "[FAIL] Hooks (claude)") || !strings.Contains(out, "not executable") {
		t.Fatalf("non-executable hook should fail, exit %d:\n%s", code, out)
	}
}

func TestDoctorAntigravityEnabledState(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			cwd := t.TempDir()
			path := filepath.Join(cwd, ".agents", "hooks.json")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			exe, _ := json.Marshal(fakeGuardExe(t))
			data := `{"jev-guard":{"enabled":` + strconv.FormatBool(enabled) + `,"PreToolUse":[{"hooks":[{"type":"command","command":` + string(exe) + `}]}]}}`
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			out, code := doctorRun(t, &Runner{}, doctorConfig(t), cwd, t.TempDir(), true)
			if enabled {
				if code != 0 || !strings.Contains(out, "[OK]   Hooks (antigravity)") {
					t.Fatalf("enabled integration should pass, exit %d:\n%s", code, out)
				}
			} else if code != 1 || !strings.Contains(out, "[FAIL] Hooks (antigravity)") || !strings.Contains(out, "integration disabled") {
				t.Fatalf("disabled integration should fail, exit %d:\n%s", code, out)
			}
		})
	}
}

func TestDoctorAuditTargetDirectoryFails(t *testing.T) {
	cfg := doctorConfig(t)
	cfg.AuditLogPath = t.TempDir()
	out, code := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), true)
	if code != 1 || !strings.Contains(out, "[FAIL] Audit log:") {
		t.Fatalf("directory audit target should fail, exit %d:\n%s", code, out)
	}
}

func TestDoctorAuditTargetReadOnlyFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte("existing audit data\n"), 0400); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err == nil {
		f.Close()
		t.Skip("current user can write read-only files")
	}
	cfg := doctorConfig(t)
	cfg.AuditLogPath = path
	out, code := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), true)
	if code != 1 || !strings.Contains(out, "[FAIL] Audit log:") {
		t.Fatalf("read-only audit target should fail, exit %d:\n%s", code, out)
	}
}

func TestDoctorAuditTargetPreservesContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	want := "existing audit data\n"
	if err := os.WriteFile(path, []byte(want), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := doctorConfig(t)
	cfg.AuditLogPath = path
	out, code := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), true)
	if code != 0 || !strings.Contains(out, "[OK]   Audit log:") {
		t.Fatalf("writable audit target should pass, exit %d:\n%s", code, out)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("audit contents changed: %q, %v", got, err)
	}
}
