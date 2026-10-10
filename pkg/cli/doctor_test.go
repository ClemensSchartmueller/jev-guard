package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jev-guard/pkg/config"
)

func doctorRun(t *testing.T, r *Runner, cfg *config.Config, cwd string, offline bool) (string, int) {
	t.Helper()
	var out bytes.Buffer
	r.Stdout = &out
	code := r.runDoctor(cfg, cwd, offline)
	return out.String(), code
}

func doctorConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.UserConfigPath = filepath.Join(t.TempDir(), ".jevguard.json")
	return cfg
}

func TestDoctorNoAPIKeyWarns(t *testing.T) {
	out, code := doctorRun(t, &Runner{}, doctorConfig(t), t.TempDir(), true)
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
	out, _ := doctorRun(t, &Runner{}, cfg, t.TempDir(), true)
	if strings.Contains(out, "supersecret") || !strings.Contains(out, "sk-***") {
		t.Fatalf("key not masked correctly:\n%s", out)
	}
}

func TestDoctorDetectsHooks(t *testing.T) {
	dir := t.TempDir()
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
	out, code := doctorRun(t, &Runner{}, doctorConfig(t), dir, true)
	if !strings.Contains(out, "[OK]   Hooks (claude): PreToolUse registered") {
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
	out, code = doctorRun(t, &Runner{}, doctorConfig(t), dir, true)
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
	out, _ := doctorRun(t, &Runner{}, cfg, t.TempDir(), true)
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
	out, _ := doctorRun(t, &Runner{}, cfg, t.TempDir(), false)
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
	out, code := doctorRun(t, &Runner{}, cfg, t.TempDir(), false)
	if code != 1 || !strings.Contains(out, "[FAIL] Network") {
		t.Fatalf("expected failure, exit %d:\n%s", code, out)
	}
}