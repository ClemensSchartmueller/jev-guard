package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	resolvedRoot, err := filepath.EvalSymlinks(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	resolvedConfigPath, err := filepath.EvalSymlinks(configPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(original)
	sha := hex.EncodeToString(digest[:])
	wantInfo := &config.ProjectConfigInfo{
		ProjectRoot:    resolvedRoot,
		ConfigPath:     resolvedConfigPath,
		SHA256:         sha,
		SensitiveFiles: []string{".secret"},
		IgnoredKeys:    []string{"base_url", "mode"},
		TrustRecord: config.ProjectConfigTrust{
			ProjectRoot: resolvedRoot,
			ConfigPath:  resolvedConfigPath,
			SHA256:      sha,
		},
	}
	var stubbedPath string
	originalInspect := inspectProjectConfig
	inspectProjectConfig = func(path string) (*config.ProjectConfigInfo, error) {
		stubbedPath = path
		return wantInfo, nil
	}
	t.Cleanup(func() { inspectProjectConfig = originalInspect })

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })
	action, code := runner.EvaluateArgs([]string{"config", "trust", configPath})
	if action != ActionHandled || code != 0 {
		t.Fatalf("expected config trust command to succeed, got action=%v code=%d stderr=%q", action, code, stderr.String())
	}
	if stubbedPath != configPath {
		t.Fatalf("inspectProjectConfig received %q, want %q", stubbedPath, configPath)
	}
	output := stdout.String()
	for _, want := range []string{sha, resolvedRoot, "Trust record to add to " + trustRegistryPath(), "does not grant trust", "mode", "base_url"} {
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
	if want := "  Trust registry:       " + trustRegistryPath() + "\n"; !strings.Contains(stdout.String(), want) {
		t.Errorf("expected trust registry line %q, got %q", want, stdout.String())
	}
	if strings.Contains(stdout.String(), secret) {
		t.Fatal("config show exposed the API key")
	}
}
