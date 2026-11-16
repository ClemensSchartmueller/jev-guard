package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// identityOnlyTrustFixture writes a project config and returns a trust record that applies to
// it only by file identity: its config_path spells the directory with a "." component, so it
// never matches the inspected spelling exactly but names the same file and directory.
func identityOnlyTrustFixture(t *testing.T) (root, repo string, record ProjectConfigTrust) {
	t.Helper()
	clearConfigEnvironment(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo = filepath.Join(root, "repo")
	writeConfig(t, filepath.Join(repo, ".jevguard.json"), `{"sensitive_files":[".identity-secret"]}`)
	info, err := inspectProjectConfigIsolated(t, repo)
	if err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.Separator)
	configPath := root + sep + "." + sep + "repo" + sep + ".jevguard.json"
	record = ProjectConfigTrust{ProjectRoot: filepath.Dir(configPath), ConfigPath: configPath, SHA256: info.SHA256}
	if record.ConfigPath == info.ConfigPath {
		t.Fatalf("fixture record must not be an exact match: %+v", record)
	}
	return root, repo, record
}

// blockTrustLookups makes the registry-entry lookups block for paths that block reports,
// until the test ends, and sets the scan deadline.
func blockTrustLookups(t *testing.T, timeout time.Duration, block func(string) bool) {
	t.Helper()
	release := make(chan struct{})
	slow := func(real func(string) (os.FileInfo, error)) func(string) (os.FileInfo, error) {
		return func(path string) (os.FileInfo, error) {
			if block(path) {
				<-release
			}
			return real(path)
		}
	}
	origStat, origLstat, origTimeout := trustAliasStat, trustAliasLstat, trustAliasScanTimeout
	trustAliasStat, trustAliasLstat, trustAliasScanTimeout = slow(os.Stat), slow(os.Lstat), timeout
	t.Cleanup(func() {
		trustAliasStat, trustAliasLstat, trustAliasScanTimeout = origStat, origLstat, origTimeout
		close(release)
	})
}

// within runs fn on a goroutine and fails, rather than hangs, if it does not return in time.
func within[T any](t *testing.T, limit time.Duration, what string, fn func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- fn() }()
	select {
	case v := <-done:
		return v
	case <-time.After(limit):
		t.Fatalf("%s did not return within %s; registry lookups are not bounded", what, limit)
		panic("unreachable")
	}
}

func loadTrustedProjectConfig(root, repo, registryPath string) *Config {
	return LoadConfigWithPaths([]string{repo}, filepath.Join(root, "user-config.json"), registryPath)
}

func TestLoadConfig_IdentityTrustMatchFailsClosedWhenLookupBlocks(t *testing.T) {
	root, repo, record := identityOnlyTrustFixture(t)
	registryPath := filepath.Join(root, "registry", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, record)

	// Without a blocked lookup the record applies, so the timeout below is what denies trust.
	if cfg := loadTrustedProjectConfig(root, repo, registryPath); cfg.ProjectConfig == nil {
		t.Fatalf("expected the identity-matching record to trust the config, diagnostics=%q", cfg.Diagnostics)
	}

	marker := string(filepath.Separator) + "." + string(filepath.Separator)
	blockTrustLookups(t, 50*time.Millisecond, func(path string) bool { return strings.Contains(path, marker) })
	cfg := within(t, 5*time.Second, "LoadConfigWithPaths", func() *Config {
		return loadTrustedProjectConfig(root, repo, registryPath)
	})
	if cfg.ProjectConfig != nil || slices.Contains(cfg.SensitiveFiles, ".identity-secret") {
		t.Fatalf("a timed-out identity lookup must leave the config untrusted, got %+v", cfg.ProjectConfig)
	}
	if !slices.ContainsFunc(cfg.Diagnostics, func(d string) bool {
		return strings.Contains(d, "is not trusted") && strings.Contains(d, "did not finish in time")
	}) {
		t.Fatalf("expected a diagnostic naming the incomplete lookup, got %q", cfg.Diagnostics)
	}
}

func TestLoadConfig_ExactTrustRecordIgnoresBlockedUnrelatedEntry(t *testing.T) {
	root, repo, _ := identityOnlyTrustFixture(t)
	info, err := inspectProjectConfigIsolated(t, repo)
	if err != nil {
		t.Fatal(err)
	}
	exact := ProjectConfigTrust{ProjectRoot: info.ProjectRoot, ConfigPath: info.ConfigPath, SHA256: info.SHA256}
	unreachable := filepath.Join(root, "unreachable")
	stale := ProjectConfigTrust{
		ProjectRoot: filepath.Join(unreachable, "repo"),
		ConfigPath:  filepath.Join(unreachable, "repo", ".jevguard.json"),
		SHA256:      info.SHA256,
	}
	registryPath := filepath.Join(root, "registry", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, stale, exact)

	// A deadline far beyond the watchdog proves the exact record is honored without waiting
	// on the blocked entry at all.
	blockTrustLookups(t, time.Hour, func(path string) bool { return strings.HasPrefix(path, unreachable) })
	cfg := within(t, 5*time.Second, "LoadConfigWithPaths", func() *Config {
		return loadTrustedProjectConfig(root, repo, registryPath)
	})
	if cfg.ProjectConfig == nil || !slices.Contains(cfg.SensitiveFiles, ".identity-secret") {
		t.Fatalf("expected the exact record to trust the config, diagnostics=%q", cfg.Diagnostics)
	}
}

func TestInspectProjectConfig_ReportsIncompleteIdentityMatch(t *testing.T) {
	root, repo, record := identityOnlyTrustFixture(t)
	registryPath := filepath.Join(root, "registry", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, record)

	info, err := inspectProjectConfigWithRegistry(repo, registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Trusted || info.TrustAliasCheckSkipped || len(info.TrustMatches) != 1 || info.TrustMatches[0] != record {
		t.Fatalf("expected the identity record to match without a timeout, got %+v", info)
	}

	marker := string(filepath.Separator) + "." + string(filepath.Separator)
	blockTrustLookups(t, 50*time.Millisecond, func(path string) bool { return strings.Contains(path, marker) })
	type result struct {
		info *ProjectConfigInfo
		err  error
	}
	r := within(t, 5*time.Second, "inspectProjectConfigWithRegistry", func() result {
		info, err := inspectProjectConfigWithRegistry(repo, registryPath)
		return result{info, err}
	})
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.info.Trusted || len(r.info.TrustMatches) != 0 || len(r.info.TrustAliases) != 0 {
		t.Fatalf("a timed-out identity lookup must fail closed, got %+v", r.info)
	}
	if !r.info.TrustAliasCheckSkipped {
		t.Fatalf("expected the inspection to report an incomplete check, got %+v", r.info)
	}
}
