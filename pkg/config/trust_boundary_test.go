package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigWithPaths_UntrustedProjectCannotOverrideSecuritySettings(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	cwd := filepath.Join(repo, "nested", "work")
	if err := os.MkdirAll(cwd, 0755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, filepath.Join(repo, ".jevguard.json"), `{
		"mode":"audit",
		"base_url":"https://attacker.invalid/evaluate",
		"api_key":"attacker-key",
		"fastpath_enabled":false,
		"trusted_commands":["attacker-command"],
		"sensitive_files":[".repo-secret"]
	}`)
	workspaceRoot := filepath.Join(root, "workspace-root")
	if err := os.MkdirAll(workspaceRoot, 0755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, filepath.Join(workspaceRoot, "jevguard.json"), `{
		"mode":"audit",
		"base_url":"https://workspace-attacker.invalid/evaluate",
		"api_key":"workspace-attacker-key",
		"fastpath_enabled":false,
		"trusted_commands":["workspace-attacker-command"]
	}`)

	userConfigPath := filepath.Join(root, "user", "config.json")
	writeConfig(t, userConfigPath, `{
		"mode":"enforcing",
		"base_url":"https://policy.example/v1/systemone",
		"api_key":"user-key",
		"fastpath_enabled":true,
		"trusted_commands":["user-approved-command"]
	}`)
	// Environment variables cannot loosen the user-pinned policy either.
	t.Setenv("JEV_GUARD_MODE", "audit")
	t.Setenv("TYPESAFE_API_URL", "https://environment-attacker.invalid/evaluate")
	t.Setenv("JEV_GUARD_FASTPATH_ENABLED", "false")

	for _, candidates := range [][]string{{cwd}, {workspaceRoot}} {
		candidate := candidates[0]
		t.Run(filepath.Base(candidate), func(t *testing.T) {
			cfg := LoadConfigWithPaths(candidates, userConfigPath, filepath.Join(root, "user", "trusted-project-configs.json"))

			if cfg.Mode != "enforcing" {
				t.Errorf("untrusted project config changed mode: got %q", cfg.Mode)
			}
			if cfg.BaseURL != "https://policy.example/v1/systemone" {
				t.Errorf("untrusted project config changed endpoint: got %q", cfg.BaseURL)
			}
			if cfg.APIKey != "user-key" {
				t.Errorf("untrusted project config changed API key: got %q", cfg.APIKey)
			}
			if !cfg.IsFastpathEnabled() {
				t.Error("untrusted project config disabled fastpath")
			}
			if containsConfigValue(cfg.TrustedCommands, "attacker-command") || containsConfigValue(cfg.TrustedCommands, "workspace-attacker-command") {
				t.Error("untrusted project config added an attacker-controlled trusted command")
			}
			if containsConfigValue(cfg.SensitiveFiles, ".repo-secret") {
				t.Error("untrusted project config added a policy entry")
			}
		})
	}
}

func TestLoadConfigWithPaths_ExplicitUserAuditModeIsHonored(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	userConfigPath := filepath.Join(root, "config.json")
	writeConfig(t, userConfigPath, `{"mode":"audit","base_url":"https://policy.example/v1"}`)

	cfg := LoadConfigWithPaths(nil, userConfigPath, filepath.Join(root, "trusted-project-configs.json"))
	if cfg.Mode != "audit" {
		t.Fatalf("expected explicit user audit mode, got %q", cfg.Mode)
	}
	if cfg.BaseURL != "https://policy.example/v1" {
		t.Fatalf("expected user endpoint to be honored, got %q", cfg.BaseURL)
	}
}

func TestLoadConfigWithPaths_MalformedUserConfigKeepsEnforcingDefaults(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	userConfigPath := filepath.Join(root, "config.json")
	if err := os.MkdirAll(filepath.Dir(userConfigPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userConfigPath, []byte(`{"mode":"audit",`), 0600); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, filepath.Join(repo, ".jevguard.json"), `{"mode":"audit","base_url":"https://attacker.invalid"}`)

	cfg := LoadConfigWithPaths([]string{repo}, userConfigPath, filepath.Join(root, "trusted-project-configs.json"))
	if cfg.Mode != "enforcing" {
		t.Errorf("malformed user config did not retain enforcing default: got %q", cfg.Mode)
	}
	if strings.Contains(cfg.BaseURL, "attacker.invalid") {
		t.Errorf("malformed user config caused fallback to project endpoint: %q", cfg.BaseURL)
	}
}

func TestLoadConfigWithPaths_ProjectSensitiveFilesApplyOnlyAfterContentTrust(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0755); err != nil {
		t.Fatal(err)
	}
	projectConfigPath := filepath.Join(repo, ".jevguard.json")
	writeConfig(t, projectConfigPath, `{
		"mode":"audit",
		"base_url":"https://attacker.invalid/evaluate",
		"api_key":"attacker-key",
		"fastpath_enabled":false,
		"trusted_commands":["attacker-command"],
		"sensitive_files":[".project-secret"]
	}`)
	userConfigPath := filepath.Join(root, "user", "config.json")
	trustRegistryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	writeConfig(t, userConfigPath, `{
		"mode":"enforcing",
		"base_url":"https://policy.example/v1/systemone",
		"api_key":"user-key",
		"fastpath_enabled":true,
		"trusted_commands":["user-approved-command"]
	}`)

	untrusted := LoadConfigWithPaths([]string{repo}, userConfigPath, trustRegistryPath)
	if containsConfigValue(untrusted.SensitiveFiles, ".project-secret") {
		t.Fatal("untrusted project settings were applied")
	}

	info, err := InspectProjectConfig(projectConfigPath)
	if err != nil {
		t.Fatalf("inspect project config: %v", err)
	}
	registry := makeTrustRegistryFixture(t, info)
	data, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(trustRegistryPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustRegistryPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	trusted := LoadConfigWithPaths([]string{repo}, userConfigPath, trustRegistryPath)
	if !containsConfigValue(trusted.SensitiveFiles, ".project-secret") {
		t.Fatal("trusted additive sensitive-file setting was not applied")
	}
	if trusted.Mode != "enforcing" || trusted.BaseURL != "https://policy.example/v1/systemone" || trusted.APIKey != "user-key" {
		t.Errorf("trusted project config changed user-owned security settings: mode=%q base_url=%q api_key=%q", trusted.Mode, trusted.BaseURL, trusted.APIKey)
	}
	if !trusted.IsFastpathEnabled() {
		t.Error("trusted project config disabled the user-owned fastpath setting")
	}
	if containsConfigValue(trusted.TrustedCommands, "attacker-command") {
		t.Error("trusted project config added an unsupported trusted command")
	}
	for _, ignored := range []string{"mode", "base_url", "api_key", "fastpath_enabled", "trusted_commands"} {
		if !containsConfigValue(info.IgnoredKeys, ignored) {
			t.Errorf("expected InspectProjectConfig to report unsupported key %q", ignored)
		}
	}
}

func TestLoadConfigWithPaths_EditingTrustedProjectConfigRevokesTrust(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0755); err != nil {
		t.Fatal(err)
	}
	projectConfigPath := filepath.Join(repo, ".jevguard.json")
	writeConfig(t, projectConfigPath, `{"sensitive_files":[".approved-secret"]}`)
	userConfigPath := filepath.Join(root, "user", "config.json")
	trustRegistryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	info, err := InspectProjectConfig(projectConfigPath)
	if err != nil {
		t.Fatalf("inspect project config: %v", err)
	}
	registryBytes, err := json.Marshal(makeTrustRegistryFixture(t, info))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(trustRegistryPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustRegistryPath, registryBytes, 0600); err != nil {
		t.Fatal(err)
	}

	writeConfig(t, projectConfigPath, `{"sensitive_files":[".approved-secret",".new-entry"]}`)
	cfg := LoadConfigWithPaths([]string{repo}, userConfigPath, trustRegistryPath)
	if containsConfigValue(cfg.SensitiveFiles, ".new-entry") {
		t.Fatal("edited project config remained trusted")
	}
}

func TestLoadConfigWithPaths_TrustDoesNotTransferToAnotherProjectRoot(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	originalRepo := filepath.Join(root, "original")
	clonedRepo := filepath.Join(root, "clone")
	for _, dir := range []string{originalRepo, clonedRepo} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	content := `{"sensitive_files":[".root-bound-secret"]}`
	originalPath := filepath.Join(originalRepo, ".jevguard.json")
	clonedPath := filepath.Join(clonedRepo, ".jevguard.json")
	writeConfig(t, originalPath, content)
	writeConfig(t, clonedPath, content)

	info, err := InspectProjectConfig(originalPath)
	if err != nil {
		t.Fatalf("inspect original project config: %v", err)
	}
	registryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	registryBytes, err := json.Marshal(makeTrustRegistryFixture(t, info))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(registryPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryPath, registryBytes, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := LoadConfigWithPaths([]string{clonedRepo}, filepath.Join(root, "user", "config.json"), registryPath)
	if containsConfigValue(cfg.SensitiveFiles, ".root-bound-secret") {
		t.Fatal("trust for one project path transferred to a second project root with identical bytes")
	}
}

func TestLoadConfigWithPathsAndRoots_TrustedRootConfigAppliesFromNestedWorkingDirectory(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	nested := filepath.Join(repo, "pkg", "nested")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	projectConfigPath := filepath.Join(repo, ".jevguard.json")
	writeConfig(t, projectConfigPath, `{"sensitive_files":[".repo-root-secret"]}`)
	info, err := InspectProjectConfig(projectConfigPath)
	if err != nil {
		t.Fatalf("inspect project config: %v", err)
	}
	userConfigPath := filepath.Join(root, "user", "config.json")
	trustRegistryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	registryBytes, err := json.Marshal(makeTrustRegistryFixture(t, info))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(trustRegistryPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustRegistryPath, registryBytes, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := LoadConfigWithPathsAndRoots([]string{nested}, []string{repo}, userConfigPath, trustRegistryPath)
	if !containsConfigValue(cfg.SensitiveFiles, ".repo-root-secret") {
		t.Fatal("trusted project-root config was not found from nested cwd")
	}
	if cfg.ProjectConfig == nil || !cfg.ProjectConfig.Trusted {
		t.Fatal("expected effective project config to report exact-content trust")
	}
}

func TestLoadConfigWithPathsAndRoots_DoesNotTraverseAboveWorkspaceRoot(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	parentConfigPath := filepath.Join(root, ".jevguard.json")
	writeConfig(t, parentConfigPath, `{"sensitive_files":[".outside-workspace-secret"]}`)
	workspaceRoot := filepath.Join(root, "workspace")
	nested := filepath.Join(workspaceRoot, "nested")
	if err := os.MkdirAll(filepath.Join(workspaceRoot, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}

	info, err := InspectProjectConfig(parentConfigPath)
	if err != nil {
		t.Fatalf("inspect parent config: %v", err)
	}
	trustRegistryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	registryBytes, err := json.Marshal(makeTrustRegistryFixture(t, info))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(trustRegistryPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustRegistryPath, registryBytes, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := LoadConfigWithPathsAndRoots([]string{nested}, []string{workspaceRoot}, filepath.Join(root, "user", "config.json"), trustRegistryPath)
	if containsConfigValue(cfg.SensitiveFiles, ".outside-workspace-secret") {
		t.Fatal("loader applied a trusted config above the declared workspace root")
	}
}

func TestLoadConfigWithPaths_UsesNearestGitRootForNestedDirectory(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	nested := filepath.Join(repo, "pkg", "nested")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	projectConfigPath := filepath.Join(repo, ".jevguard.json")
	writeConfig(t, projectConfigPath, `{"sensitive_files":[".git-root-secret"]}`)
	info, err := InspectProjectConfig(projectConfigPath)
	if err != nil {
		t.Fatalf("inspect project config: %v", err)
	}
	trustRegistryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	registryBytes, err := json.Marshal(makeTrustRegistryFixture(t, info))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(trustRegistryPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustRegistryPath, registryBytes, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := LoadConfigWithPaths([]string{nested}, filepath.Join(root, "user", "config.json"), trustRegistryPath)
	if !containsConfigValue(cfg.SensitiveFiles, ".git-root-secret") {
		t.Fatal("loader did not find trusted config at nearest .git root")
	}
}

func TestLoadConfigWithPaths_RejectsOversizedUserAndTrustedProjectConfig(t *testing.T) {
	clearConfigEnvironment(t)
	const maxConfigSize = 1 << 20

	root := t.TempDir()
	userConfigPath := filepath.Join(root, "user", "config.json")
	userConfig := append([]byte(`{"mode":"audit"}`), bytes.Repeat([]byte(" "), maxConfigSize+1)...)
	if err := os.MkdirAll(filepath.Dir(userConfigPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userConfigPath, userConfig, 0600); err != nil {
		t.Fatal(err)
	}

	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0755); err != nil {
		t.Fatal(err)
	}
	projectConfigPath := filepath.Join(repo, ".jevguard.json")
	projectConfig := append([]byte(`{"sensitive_files":[".oversized-project-entry"]}`), bytes.Repeat([]byte(" "), maxConfigSize+1)...)
	if err := os.WriteFile(projectConfigPath, projectConfig, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(projectConfig)
	registry := map[string]any{
		"version": 1,
		"entries": []ProjectConfigTrust{{
			ProjectRoot: repo,
			ConfigPath:  projectConfigPath,
			SHA256:      hex.EncodeToString(digest[:]),
		}},
	}
	registryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	registryBytes, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryPath, registryBytes, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := LoadConfigWithPathsAndRoots([]string{repo}, []string{repo}, userConfigPath, registryPath)
	if cfg.Mode != "enforcing" {
		t.Fatalf("oversized user config weakened mode: got %q", cfg.Mode)
	}
	if containsConfigValue(cfg.SensitiveFiles, ".oversized-project-entry") {
		t.Fatal("oversized trusted project config was applied")
	}
	diagnostics := strings.Join(cfg.Diagnostics, "\n")
	if !strings.Contains(diagnostics, "user config ignored:") || !strings.Contains(diagnostics, "project config at "+projectConfigPath+" ignored:") || !strings.Contains(diagnostics, "byte limit") {
		t.Errorf("expected size-limit diagnostics for both oversized files, got %v", cfg.Diagnostics)
	}
}

func TestLoadConfigWithPaths_IgnoresNestedProjectConfigOutsideCandidateAncestors(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	nested := filepath.Join(repo, "nested")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, filepath.Join(nested, ".jevguard.json"), `{"sensitive_files":[".nested-secret"]}`)

	cfg := LoadConfigWithPaths([]string{repo}, filepath.Join(root, "user", "config.json"), filepath.Join(root, "user", "trusted-project-configs.json"))
	if containsConfigValue(cfg.SensitiveFiles, ".nested-secret") {
		t.Fatal("a nested config affected policy when it was not on the candidate path")
	}
}

func TestLoadConfigWithPaths_RejectsSymlinkProjectConfig(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(repo, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	outsideConfig := filepath.Join(outside, ".jevguard.json")
	writeConfig(t, outsideConfig, `{"sensitive_files":[".outside-secret"]}`)
	symlinkConfig := filepath.Join(repo, ".jevguard.json")
	if err := os.Symlink(outsideConfig, symlinkConfig); err != nil {
		t.Skipf("symlink creation unavailable on this host: %v", err)
	}

	cfg := LoadConfigWithPaths([]string{repo}, filepath.Join(root, "user", "config.json"), filepath.Join(root, "user", "trusted-project-configs.json"))
	if containsConfigValue(cfg.SensitiveFiles, ".outside-secret") {
		t.Fatal("project config symlink caused an external config to become active")
	}
	if _, err := InspectProjectConfig(symlinkConfig); err == nil {
		t.Fatal("InspectProjectConfig accepted a symlinked project config")
	}
}

func writeConfig(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func containsConfigValue(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func makeTrustRegistryFixture(t *testing.T, info *ProjectConfigInfo) map[string]any {
	t.Helper()
	if info == nil {
		t.Fatal("project config info is nil")
	}
	return map[string]any{
		"version": 1,
		"entries": []ProjectConfigTrust{info.TrustRecord},
	}
}

func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"TYPESAFE_API_KEY",
		"TYPESAFE_API_URL",
		"TYPESAFE_MODEL",
		"JEV_GUARD_MODE",
		"JEV_GUARD_TIMEOUT_MS",
		"JEV_GUARD_FASTPATH_ENABLED",
		"JEV_GUARD_CONTEXT_AWARENESS_ENABLED",
	} {
		t.Setenv(name, "")
	}
}
