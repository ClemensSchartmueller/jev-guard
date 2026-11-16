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
	"time"
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

	info, err := inspectProjectConfigIsolated(t, projectConfigPath)
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
	info, err := inspectProjectConfigIsolated(t, projectConfigPath)
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

	info, err := inspectProjectConfigIsolated(t, originalPath)
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

// A project reached through a symlinked parent (like macOS /var -> /private/var) must be trusted
// when inspected and loaded through the same path, and must fail closed through any alias.
// symlinkedParentFixture creates root/real/repo with a project config and a symlink
// root/link -> root/real. root is symlink-resolved, so realRepo is the canonical spelling
// (on macOS t.TempDir() is under /var, a symlink to /private/var).
func symlinkedParentFixture(t *testing.T, contents string) (root, realRepo, linkRepo string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realRepo = filepath.Join(root, "real", "repo")
	linkRepo = filepath.Join(root, "link", "repo")
	if err := os.MkdirAll(realRepo, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	writeConfig(t, filepath.Join(realRepo, ".jevguard.json"), contents)
	return root, realRepo, linkRepo
}

func writeTrustRegistryFile(t *testing.T, path string, entries ...ProjectConfigTrust) {
	t.Helper()
	registryBytes, err := json.Marshal(map[string]any{"version": 1, "entries": entries})
	if err != nil {
		t.Fatal(err)
	}
	writeConfig(t, path, string(registryBytes))
}

func assertProjectTrust(t *testing.T, dir, registryPath, marker string, want bool) {
	t.Helper()
	info, err := inspectProjectConfigWithRegistry(dir, registryPath)
	if err != nil {
		t.Fatalf("inspect %s: %v", dir, err)
	}
	if info.Trusted != want {
		t.Errorf("inspect %s: trusted=%t, want %t (matches=%+v)", dir, info.Trusted, want, info.TrustMatches)
	}
	userConfigPath := filepath.Join(filepath.Dir(registryPath), "config.json")
	cfg := LoadConfigWithPaths([]string{dir}, userConfigPath, registryPath)
	if got := containsConfigValue(cfg.SensitiveFiles, marker); got != want {
		t.Errorf("runtime lookup for %s: applied=%t, want %t (diagnostics=%v)", dir, got, want, cfg.Diagnostics)
	}
}

func TestLoadConfigWithPaths_TrustThroughSymlinkedParentBindsTheRealDirectory(t *testing.T) {
	clearConfigEnvironment(t)
	root, realRepo, linkRepo := symlinkedParentFixture(t, `{"sensitive_files":[".symlinked-secret"]}`)

	info, err := inspectProjectConfigIsolated(t, linkRepo)
	if err != nil {
		t.Fatalf("inspect project config through symlinked parent: %v", err)
	}
	if info.ConfigPath != filepath.Join(linkRepo, ".jevguard.json") {
		t.Fatalf("expected inspection to report the inspected spelling, got %q", info.ConfigPath)
	}
	proposal := proposeCanonicalRecord(t, info)
	if proposal.ProjectRoot != realRepo || proposal.ConfigPath != filepath.Join(realRepo, ".jevguard.json") {
		t.Fatalf("expected the proposal to bind the symlink-resolved path %q, got %+v", realRepo, proposal)
	}
	registryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, proposal)

	// Approval through the symlinked spelling is honored for both spellings.
	assertProjectTrust(t, linkRepo, registryPath, ".symlinked-secret", true)
	assertProjectTrust(t, realRepo, registryPath, ".symlinked-secret", true)

	// The digest is still checked: an edited config is not trusted under either spelling.
	writeConfig(t, filepath.Join(realRepo, ".jevguard.json"), `{"sensitive_files":[".symlinked-secret",".edited"]}`)
	assertProjectTrust(t, linkRepo, registryPath, ".symlinked-secret", false)
	assertProjectTrust(t, realRepo, registryPath, ".symlinked-secret", false)
}

func TestLoadConfigWithPaths_SwappedSymlinkDoesNotInheritTrust(t *testing.T) {
	clearConfigEnvironment(t)
	const contents = `{"sensitive_files":[".swapped-secret"]}`
	root, realRepo, linkRepo := symlinkedParentFixture(t, contents)
	otherRepo := filepath.Join(root, "other", "repo")
	writeConfig(t, filepath.Join(otherRepo, ".jevguard.json"), contents)

	approved, err := inspectProjectConfigIsolated(t, linkRepo)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, proposeCanonicalRecord(t, approved))
	assertProjectTrust(t, linkRepo, registryPath, ".swapped-secret", true)

	// Repoint the symlink at another directory holding byte-identical config. The digest
	// matches, but the approval named the real directory, so trust must not follow the link.
	if err := os.Remove(filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "other"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	assertProjectTrust(t, linkRepo, registryPath, ".swapped-secret", false)
	assertProjectTrust(t, otherRepo, registryPath, ".swapped-secret", false)
	assertProjectTrust(t, realRepo, registryPath, ".swapped-secret", true)
}

func TestLoadConfigWithPaths_LegacyRecordForSymlinkedSpellingKeepsExactBinding(t *testing.T) {
	clearConfigEnvironment(t)
	const contents = `{"sensitive_files":[".legacy-secret"]}`
	root, realRepo, linkRepo := symlinkedParentFixture(t, contents)
	approved, err := inspectProjectConfigIsolated(t, linkRepo)
	if err != nil {
		t.Fatal(err)
	}
	// Records written before trust followed file identity name the spelling as given.
	legacy := ProjectConfigTrust{
		ProjectRoot: linkRepo,
		ConfigPath:  filepath.Join(linkRepo, ".jevguard.json"),
		SHA256:      approved.SHA256,
	}
	registryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, legacy)

	// The legacy record keeps working for its exact spelling.
	assertProjectTrust(t, linkRepo, registryPath, ".legacy-secret", true)
	// It goes through a symlink, so it is not extended to other spellings: the link could
	// have pointed elsewhere when it was approved. It is reported as an alias instead.
	assertProjectTrust(t, realRepo, registryPath, ".legacy-secret", false)
	info, err := inspectProjectConfigWithRegistry(realRepo, registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.TrustMatches) != 0 || len(info.TrustAliases) != 1 || info.TrustAliases[0] != legacy {
		t.Fatalf("expected the legacy record as an alias only, got matches=%+v aliases=%+v", info.TrustMatches, info.TrustAliases)
	}

	// A legacy record that names the real directory is also bound to its exact spelling;
	// only a canonical record, which config trust now proposes, covers other spellings.
	legacyReal := ProjectConfigTrust{
		ProjectRoot: realRepo,
		ConfigPath:  filepath.Join(realRepo, ".jevguard.json"),
		SHA256:      approved.SHA256,
	}
	writeTrustRegistryFile(t, registryPath, legacyReal)
	assertProjectTrust(t, linkRepo, registryPath, ".legacy-secret", false)
	assertProjectTrust(t, realRepo, registryPath, ".legacy-secret", true)
	info, err = inspectProjectConfigWithRegistry(linkRepo, registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.TrustMatches) != 0 || len(info.TrustAliases) != 1 || info.TrustAliases[0] != legacyReal {
		t.Fatalf("expected the legacy real-directory record as an alias only, got matches=%+v aliases=%+v", info.TrustMatches, info.TrustAliases)
	}

	canonical := legacyReal
	canonical.Canonical = true
	writeTrustRegistryFile(t, registryPath, canonical)
	assertProjectTrust(t, linkRepo, registryPath, ".legacy-secret", true)
	assertProjectTrust(t, realRepo, registryPath, ".legacy-secret", true)
}

func TestInspectProjectConfig_TrustMatchesNameEveryRecordToRevoke(t *testing.T) {
	clearConfigEnvironment(t)
	root, realRepo, linkRepo := symlinkedParentFixture(t, `{"sensitive_files":[".revoke-secret"]}`)
	approved, err := inspectProjectConfigIsolated(t, realRepo)
	if err != nil {
		t.Fatal(err)
	}
	current := proposeCanonicalRecord(t, approved)
	older := current
	older.SHA256 = strings.Repeat("0", 64)
	unrelated := ProjectConfigTrust{
		ProjectRoot: filepath.Join(root, "unrelated"),
		ConfigPath:  filepath.Join(root, "unrelated", ".jevguard.json"),
		SHA256:      approved.SHA256,
	}
	registryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, unrelated, current, older)

	// Untrust through the symlinked spelling names the records for the real directory,
	// including older digests, so removing them revokes trust under every spelling.
	info, err := inspectProjectConfigWithRegistry(linkRepo, registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Trusted || len(info.TrustMatches) != 2 || info.TrustMatches[0] != current || info.TrustMatches[1] != older {
		t.Fatalf("expected both records for the real directory, got trusted=%t matches=%+v", info.Trusted, info.TrustMatches)
	}
	writeTrustRegistryFile(t, registryPath, unrelated)
	assertProjectTrust(t, linkRepo, registryPath, ".revoke-secret", false)
	assertProjectTrust(t, realRepo, registryPath, ".revoke-secret", false)
}

func TestLoadConfigWithPaths_HardLinkInAnotherDirectoryDoesNotShareTrust(t *testing.T) {
	clearConfigEnvironment(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(root, "repo")
	other := filepath.Join(root, "other")
	writeConfig(t, filepath.Join(repo, ".jevguard.json"), `{"sensitive_files":[".hardlink-secret"]}`)
	if err := os.MkdirAll(other, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(repo, ".jevguard.json"), filepath.Join(other, ".jevguard.json")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	approved, err := inspectProjectConfigIsolated(t, repo)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, proposeCanonicalRecord(t, approved))
	assertProjectTrust(t, repo, registryPath, ".hardlink-secret", true)
	assertProjectTrust(t, other, registryPath, ".hardlink-secret", false)
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
	info, err := inspectProjectConfigIsolated(t, projectConfigPath)
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

	info, err := inspectProjectConfigIsolated(t, parentConfigPath)
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
	info, err := inspectProjectConfigIsolated(t, projectConfigPath)
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
	if _, err := inspectProjectConfigIsolated(t, symlinkConfig); err == nil {
		t.Fatal("InspectProjectConfig accepted a symlinked project config")
	}
}

// inspectProjectConfigIsolated inspects a project config against an empty temporary trust
// registry so tests never read the operating system user's registry.
func inspectProjectConfigIsolated(t *testing.T, path string) (*ProjectConfigInfo, error) {
	t.Helper()
	return inspectProjectConfigWithRegistry(path, filepath.Join(t.TempDir(), "trusted-project-configs.json"))
}

// proposeCanonicalRecord returns what config trust proposes for info and fails unless it is
// a canonical record.
func proposeCanonicalRecord(t *testing.T, info *ProjectConfigInfo) ProjectConfigTrust {
	t.Helper()
	record, note := ProposeTrustRecord(info)
	if !record.Canonical || note != "" {
		t.Fatalf("expected a canonical trust proposal, got %+v (%s)", record, note)
	}
	return record
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

func TestInspectProjectConfigReportsMissingTrustRegistry(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), ".jevguard.json")
	writeConfig(t, configPath, `{"sensitive_files":[".secret"]}`)
	info, err := inspectProjectConfigIsolated(t, configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Trusted || info.TrustIssue != "trust registry does not exist" {
		t.Fatalf("expected an untrusted config with a missing-registry issue, got trusted=%t issue=%q", info.Trusted, info.TrustIssue)
	}
}

func TestInspectProjectConfig_ReportsTrustRecordForAnotherSpellingWithoutTrustingIt(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	linkParent := filepath.Join(root, "link")
	realRepo := filepath.Join(realParent, "repo")
	linkRepo := filepath.Join(linkParent, "repo")
	if err := os.MkdirAll(realRepo, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	writeConfig(t, filepath.Join(realRepo, ".jevguard.json"), `{"sensitive_files":[".alias-secret"]}`)

	approved, err := inspectProjectConfigIsolated(t, linkRepo)
	if err != nil {
		t.Fatal(err)
	}
	// A record that names the symlinked spelling (as config trust proposed before it
	// resolved symlinks) stays bound to that spelling.
	approved.TrustRecord = ProjectConfigTrust{
		ProjectRoot: approved.ProjectRoot,
		ConfigPath:  approved.ConfigPath,
		SHA256:      approved.SHA256,
	}
	gone := ProjectConfigTrust{
		ProjectRoot: filepath.Join(root, "deleted"),
		ConfigPath:  filepath.Join(root, "deleted", ".jevguard.json"),
		SHA256:      approved.SHA256,
	}
	registryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	registryBytes, err := json.Marshal(map[string]any{
		"version": 1,
		"entries": []ProjectConfigTrust{gone, approved.TrustRecord},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeConfig(t, registryPath, string(registryBytes))

	alias, err := inspectProjectConfigWithRegistry(realRepo, registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if alias.Trusted {
		t.Fatalf("a record for another spelling must not trust this path, got %+v", alias)
	}
	if alias.TrustAliasCheckSkipped || len(alias.TrustAliases) != 1 || alias.TrustAliases[0] != approved.TrustRecord {
		t.Fatalf("expected the symlinked-path record as the only alias, got %+v", alias.TrustAliases)
	}

	exact, err := inspectProjectConfigWithRegistry(linkRepo, registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !exact.Trusted || len(exact.TrustAliases) != 0 {
		t.Fatalf("the exact record must not be reported as its own alias, got %+v", exact)
	}

	// A record naming a symlinked config file could never be approved, so it is not an alias.
	symlinkRepo := filepath.Join(root, "symlink-file")
	if err := os.MkdirAll(symlinkRepo, 0755); err != nil {
		t.Fatal(err)
	}
	symlinkConfig := filepath.Join(symlinkRepo, ".jevguard.json")
	if err := os.Symlink(filepath.Join(realRepo, ".jevguard.json"), symlinkConfig); err != nil {
		t.Skipf("file symlinks unavailable: %v", err)
	}
	registryBytes, err = json.Marshal(map[string]any{
		"version": 1,
		"entries": []ProjectConfigTrust{{ProjectRoot: symlinkRepo, ConfigPath: symlinkConfig, SHA256: approved.SHA256}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeConfig(t, registryPath, string(registryBytes))
	if info, err := inspectProjectConfigWithRegistry(realRepo, registryPath); err != nil || len(info.TrustAliases) != 0 {
		t.Fatalf("a symlinked config file record must not be reported as an alias, got info=%+v err=%v", info, err)
	}
}

func TestInspectProjectConfig_BoundsTrustAliasScanOnUnreachableEntry(t *testing.T) {
	clearConfigEnvironment(t)

	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	writeConfig(t, filepath.Join(repo, ".jevguard.json"), `{"sensitive_files":[".slow-secret"]}`)
	approved, err := inspectProjectConfigIsolated(t, repo)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a stale network mount: lookups under unreachable/ block until the test ends.
	unreachable := filepath.Join(root, "unreachable")
	release := make(chan struct{})
	slow := func(real func(string) (os.FileInfo, error)) func(string) (os.FileInfo, error) {
		return func(path string) (os.FileInfo, error) {
			if strings.HasPrefix(path, unreachable) {
				<-release
			}
			return real(path)
		}
	}
	origStat, origLstat, origTimeout := trustAliasStat, trustAliasLstat, trustAliasScanTimeout
	trustAliasStat, trustAliasLstat, trustAliasScanTimeout = slow(os.Stat), slow(os.Lstat), 50*time.Millisecond
	t.Cleanup(func() {
		trustAliasStat, trustAliasLstat, trustAliasScanTimeout = origStat, origLstat, origTimeout
		close(release)
	})

	stale := ProjectConfigTrust{
		ProjectRoot: filepath.Join(unreachable, "repo"),
		ConfigPath:  filepath.Join(unreachable, "repo", ".jevguard.json"),
		SHA256:      approved.SHA256,
	}
	for _, tc := range []struct {
		name    string
		entries []ProjectConfigTrust
		trusted bool
	}{
		{name: "untrusted", entries: []ProjectConfigTrust{stale}, trusted: false},
		{name: "trusted", entries: []ProjectConfigTrust{stale, approved.TrustRecord}, trusted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registryPath := filepath.Join(root, tc.name, "trusted-project-configs.json")
			registryBytes, err := json.Marshal(map[string]any{"version": 1, "entries": tc.entries})
			if err != nil {
				t.Fatal(err)
			}
			writeConfig(t, registryPath, string(registryBytes))

			// Inspect asynchronously so a regression fails at the watchdog instead of
			// hanging until the blocked lookups are released in cleanup.
			type result struct {
				info *ProjectConfigInfo
				err  error
			}
			done := make(chan result, 1)
			go func() {
				info, err := inspectProjectConfigWithRegistry(repo, registryPath)
				done <- result{info, err}
			}()
			var info *ProjectConfigInfo
			select {
			case r := <-done:
				info, err = r.info, r.err
			case <-time.After(5 * time.Second):
				t.Fatal("alias scan was not bounded: inspection did not return within 5s")
			}
			if err != nil {
				t.Fatal(err)
			}
			if info.Trusted != tc.trusted || info.TrustIssue != "" {
				t.Fatalf("a timed-out alias scan must not change the trust decision, got trusted=%t issue=%q", info.Trusted, info.TrustIssue)
			}
			if !info.TrustAliasCheckSkipped || len(info.TrustAliases) != 0 {
				t.Fatalf("expected a skipped alias scan with no aliases, got skipped=%t aliases=%+v", info.TrustAliasCheckSkipped, info.TrustAliases)
			}
		})
	}
}
