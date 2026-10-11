package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoctorReportsProviderSettings(t *testing.T) {
	var probedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probedPath = r.URL.Path
		if r.Header.Get("Authorization") != "" || r.Header.Get("x-api-key") != "" {
			t.Errorf("doctor sent credentials to the endpoint")
		}
	}))
	defer srv.Close()

	cfg := doctorConfig(t)
	cfg.Provider, cfg.Model, cfg.BaseURL = "anthropic", "claude-test", srv.URL+"/v1"
	out, _ := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), false)
	for _, line := range []string{
		"[WARN] API key: not configured (set ANTHROPIC_API_KEY or api_key in user config)",
		"[OK]   Provider: anthropic; model: claude-test; fastpath: true; context awareness: true",
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("missing %q in:\n%s", line, out)
		}
	}
	if probedPath != "/v1" {
		t.Errorf("probed %q, want the configured API root", probedPath)
	}
}

func TestDoctorFailsWithoutModelForLLMProvider(t *testing.T) {
	cfg := doctorConfig(t)
	cfg.Provider = "openai"
	out, code := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), true)
	if !strings.Contains(out, "[FAIL] Model: not configured for provider openai (set model in user config)\n") || code != 1 {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}
}

func TestDoctorFailsForUnsupportedProvider(t *testing.T) {
	cfg := doctorConfig(t)
	cfg.Provider, cfg.Model = "gemini", "m"
	out, code := doctorRun(t, &Runner{}, cfg, t.TempDir(), t.TempDir(), false)
	if !strings.Contains(out, "[FAIL] Network: no endpoint for unsupported provider \"gemini\"\n") || code != 1 {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}
	if !strings.Contains(out, "[WARN] API key: not configured (set api_key in user config)\n") {
		t.Errorf("unexpected API key line:\n%s", out)
	}
}
