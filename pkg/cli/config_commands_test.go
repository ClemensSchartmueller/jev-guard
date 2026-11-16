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
	// The command reports the inspected spelling, but the proposed record binds the
	// symlink-resolved directory. On macOS t.TempDir() is under /var (a symlink to
	// /private/var) and on Windows it may be an 8.3 short name.
	inspectedRoot, err := filepath.Abs(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	inspectedConfigPath := filepath.Join(inspectedRoot, ".jevguard.json")
	resolvedRoot, err := filepath.EvalSymlinks(inspectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	resolvedConfigPath := filepath.Join(resolvedRoot, ".jevguard.json")
	digest := sha256.Sum256(original)
	sha := hex.EncodeToString(digest[:])
	wantRecord := config.ProjectConfigTrust{
		ProjectRoot: resolvedRoot,
		ConfigPath:  resolvedConfigPath,
		SHA256:      sha,
		Canonical:   true,
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
		"Project root: " + inspectedRoot,
		"Project config: " + inspectedConfigPath,
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

// symlinkedProjectAlias creates a project config reached through a symlinked parent and
// approves the symlinked spelling in the temp registry. It returns both spellings.
func symlinkedProjectAlias(t *testing.T) (realRepo, linkRepo string) {
	t.Helper()
	root, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realRepo = filepath.Join(root, "real", "repo")
	linkRepo = filepath.Join(root, "link", "repo")
	if err := os.MkdirAll(realRepo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(realRepo), filepath.Dir(linkRepo)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realRepo, ".jevguard.json"), []byte(`{"sensitive_files":[".x"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := inspectProjectConfig(linkRepo)
	if err != nil {
		t.Fatal(err)
	}
	// Approve the symlinked spelling as config trust proposed it before it resolved
	// symlinks. Such a record stays bound to that exact spelling.
	writeTrustRegistry(t, config.ProjectConfigTrust{ProjectRoot: info.ProjectRoot, ConfigPath: info.ConfigPath, SHA256: info.SHA256})
	return realRepo, linkRepo
}

func TestConfigUntrustNamesRecordForAnotherSpellingOfThePath(t *testing.T) {
	realRepo, linkRepo := symlinkedProjectAlias(t)
	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })
	if action, code := runner.EvaluateArgs([]string{"config", "untrust", realRepo}); action != ActionHandled || code != 0 {
		t.Fatalf("config untrust failed: code=%d stderr=%q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"Current digest is not trusted.",
		"Registry entry for another spelling of this path: " + filepath.Join(linkRepo, ".jevguard.json") + " (the current digest).",
		"It does not apply to " + filepath.Join(realRepo, ".jevguard.json") + ` because it has no "canonical": true`,
	} {
		if !strings.Contains(output, want) {
			t.Errorf("expected untrust output to contain %q, got %q", want, output)
		}
	}

	stdout.Reset()
	if _, code := runner.EvaluateArgs([]string{"config", "untrust", linkRepo}); code != 0 {
		t.Fatalf("config untrust failed: stderr=%q", stderr.String())
	}
	if strings.Contains(stdout.String(), "another spelling") {
		t.Errorf("the exact approved path must not report itself as an alias, got %q", stdout.String())
	}
	if strings.Contains(output, "config trust") {
		t.Errorf("untrust must not suggest approving a spelling, got %q", output)
	}

	// When both spellings are approved, revoking one still names the other.
	realInfo, err := inspectProjectConfig(realRepo)
	if err != nil {
		t.Fatal(err)
	}
	linkInfo, err := inspectProjectConfig(linkRepo)
	if err != nil {
		t.Fatal(err)
	}
	legacyLink := config.ProjectConfigTrust{ProjectRoot: linkInfo.ProjectRoot, ConfigPath: linkInfo.ConfigPath, SHA256: linkInfo.SHA256}
	writeTrustRegistry(t, legacyLink, realInfo.TrustRecord)
	stdout.Reset()
	if _, code := runner.EvaluateArgs([]string{"config", "untrust", realRepo}); code != 0 {
		t.Fatalf("config untrust failed: stderr=%q", stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "is trusted.") || !strings.Contains(out, "another spelling of this path: "+linkInfo.ConfigPath) {
		t.Errorf("expected untrust of a trusted path to also name the alias record, got %q", out)
	}
}

func TestConfigTrustExplainsExactSpellingFallback(t *testing.T) {
	info := &config.ProjectConfigInfo{ProjectRoot: "/repo", ConfigPath: "/repo/.jevguard.json", SHA256: strings.Repeat("a", 64)}
	record := config.ProjectConfigTrust{ProjectRoot: info.ProjectRoot, ConfigPath: info.ConfigPath, SHA256: info.SHA256}
	var out bytes.Buffer
	printTrustProposal(&out, info, record, "resolving the real directory did not finish in time, so the record is bound to this exact path")
	got := out.String()
	for _, want := range []string{
		"The record applies only to the exact path /repo/.jevguard.json: resolving the real directory did not finish in time",
		`"sha256": "` + info.SHA256 + "\"\n}",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected trust proposal to contain %q, got %q", want, got)
		}
	}
	if strings.Contains(got, "canonical") {
		t.Errorf("a fallback record must not be marked canonical, got %q", got)
	}
}

func TestTrustAliasHintsNoteSkippedAliasCheck(t *testing.T) {
	hints := trustAliasHints(&config.ProjectConfigInfo{ConfigPath: "/repo/.jevguard.json", TrustAliasCheckSkipped: true}, true)
	if len(hints) != 1 || !strings.Contains(hints[0], "Skipped the registry lookups that check the filesystem") {
		t.Fatalf("expected a skipped-check note, got %q", hints)
	}
}

func TestConfigUntrustThroughAnotherSpellingNamesTheEffectiveRecord(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realRepo := filepath.Join(root, "real", "repo")
	linkRepo := filepath.Join(root, "link", "repo")
	if err := os.MkdirAll(realRepo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(realRepo), filepath.Dir(linkRepo)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realRepo, ".jevguard.json"), []byte(`{"sensitive_files":[".x"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// config trust through the symlink proposes the real directory.
	info, err := inspectProjectConfig(linkRepo)
	if err != nil {
		t.Fatal(err)
	}
	record, note := proposeTrustRecord(info)
	if !record.Canonical || record.ConfigPath != filepath.Join(realRepo, ".jevguard.json") {
		t.Fatalf("expected a canonical record for the real directory, got %+v (%s)", record, note)
	}
	writeTrustRegistry(t, record)

	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr, func() bool { return false })
	if _, code := runner.EvaluateArgs([]string{"config", "untrust", linkRepo}); code != 0 {
		t.Fatalf("config untrust failed: stderr=%q", stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"is trusted.",
		"Registry entries that apply to this config file",
		"config_path=" + record.ConfigPath + " sha256=" + info.SHA256 + " canonical=true",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("expected untrust output to contain %q, got %q", want, output)
		}
	}
	if strings.Contains(output, "another spelling") {
		t.Errorf("an effective record must not be described as an alias that does not apply, got %q", output)
	}

	// Removing the named record revokes trust for both spellings.
	writeTrustRegistry(t)
	for _, dir := range []string{linkRepo, realRepo} {
		if info, err := inspectProjectConfig(dir); err != nil || info.Trusted {
			t.Errorf("expected %s to be untrusted after removing the record, got info=%+v err=%v", dir, info, err)
		}
	}
}
