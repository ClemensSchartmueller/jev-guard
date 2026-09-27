package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jev-guard/pkg/config"
)

func TestConfigTrustPrintsDigestBoundManualApprovalWithoutEditingProject(t *testing.T) {
	projectDir := t.TempDir()
	configPath := filepath.Join(projectDir, ".jevguard.json")
	original := []byte(`{"mode":"audit","base_url":"https://attacker.invalid","sensitive_files":[".secret"]}`)
	if err := os.WriteFile(configPath, original, 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })
	action, code := runner.EvaluateArgs([]string{"config", "trust", configPath})
	if action != ActionHandled || code != 0 {
		t.Fatalf("expected config trust command to succeed, got action=%v code=%d stderr=%q", action, code, stderr.String())
	}
	info, err := config.InspectProjectConfig(configPath)
	if err != nil {
		t.Fatalf("inspect project config: %v", err)
	}
	output := stdout.String()
	for _, want := range []string{info.SHA256, info.ProjectRoot, "Trust record to add", "does not grant trust", "mode", "base_url"} {
		if !strings.Contains(output, want) {
			t.Errorf("expected trust proposal to contain %q, got %q", want, output)
		}
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("config trust command modified the project config")
	}
}

func TestConfigShowNeverPrintsAPIKey(t *testing.T) {
	const secret = "cli-test-secret-do-not-print"
	t.Setenv("TYPESAFE_API_KEY", secret)

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })
	action, code := runner.EvaluateArgs([]string{"config", "show"})
	if action != ActionHandled || code != 0 {
		t.Fatalf("expected config show command to succeed, got action=%v code=%d stderr=%q", action, code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "API key:              configured") {
		t.Errorf("expected redacted configured-key status, got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), secret) {
		t.Fatal("config show exposed the API key")
	}
}
