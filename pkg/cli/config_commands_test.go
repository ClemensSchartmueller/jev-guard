package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	wantRecord := config.ProjectConfigTrust{
		ProjectRoot: resolvedRoot,
		ConfigPath:  resolvedConfigPath,
		SHA256:      sha,
	}
	recordJSON, err := json.MarshalIndent(wantRecord, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	runConfig := func(args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		runner := NewRunner(&stdout, &stderr, func() bool { return false })
		action, code := runner.EvaluateArgs(append([]string{"config"}, args...))
		if action != ActionHandled || code != 0 {
			t.Fatalf("expected config %v to succeed, got action=%v code=%d stderr=%q", args, action, code, stderr.String())
		}
		return stdout.String()
	}

	// Before approval the temp registry does not exist, so the digest is not trusted.
	output := runConfig("trust", configPath)
	for _, want := range []string{
		"SHA-256: " + sha,
		"Project root: " + resolvedRoot,
		"Project config: " + resolvedConfigPath,
		"Additive sensitive_files: [.secret]",
		"Ignored project keys: base_url, mode",
		"Existing trust registry status: trust registry does not exist",
		"Trust record to add to " + trustRegistryPath() + ":\n" + string(recordJSON),
		"does not grant trust",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("expected trust proposal to contain %q, got %q", want, output)
		}
	}
	if _, err := os.Stat(trustRegistryPath()); !os.IsNotExist(err) {
		t.Fatalf("config trust must not create the trust registry, stat err=%v", err)
	}

	// Approve the printed record in the temp registry. The exact digest is now trusted.
	writeTrustRegistry(t, wantRecord)
	if output := runConfig("untrust", configPath); !strings.Contains(output, "Current digest "+sha+" is trusted.") {
		t.Errorf("expected the approved digest to be trusted, got %q", output)
	}

	// The same project with a stale digest is not trusted.
	writeTrustRegistry(t, config.ProjectConfigTrust{ProjectRoot: resolvedRoot, ConfigPath: resolvedConfigPath, SHA256: strings.Repeat("0", 64)})
	if output := runConfig("untrust", configPath); !strings.Contains(output, "Current digest is not trusted.") {
		t.Errorf("expected a stale digest not to be trusted, got %q", output)
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

// writeTrustRegistry replaces the temp trust registry installed by TestMain with the
// given entries and removes it when the test ends.
func writeTrustRegistry(t *testing.T, entries ...config.ProjectConfigTrust) {
	t.Helper()
	path := trustRegistryPath()
	data, err := json.Marshal(map[string]any{"version": 1, "entries": entries})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
}
