package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// identityOnlyTrustFixture writes a project config under root/real/repo, links root/link to
// root/real, and returns the linked spelling of the repository with a canonical trust record
// for the real one, which applies to the linked spelling only through a pinned lookup.
func identityOnlyTrustFixture(t *testing.T) (root, repo string, record ProjectConfigTrust) {
	t.Helper()
	clearConfigEnvironment(t)
	root, realRepo, linkRepo := symlinkedParentFixture(t, `{"sensitive_files":[".identity-secret"]}`)
	info, err := inspectProjectConfigIsolated(t, linkRepo)
	if err != nil {
		t.Fatal(err)
	}
	record = proposeCanonicalRecord(t, info)
	if record.ProjectRoot != realRepo || record.ConfigPath == info.ConfigPath {
		t.Fatalf("fixture record must name the real directory, not the inspected spelling: %+v", record)
	}
	return root, linkRepo, record
}

// blockTrustLookups makes the registry-entry lookups (stat calls and pinned lookups) and the
// post-read check of the inspected directory spelling block
// for paths that block reports, until the test ends, and sets the scan deadline.
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
	slowPin := func(real pinFunc) pinFunc {
		return func(projectRoot, name string, step func(string)) (pinnedConfig, error) {
			if block(projectRoot) {
				<-release
			}
			return real(projectRoot, name, step)
		}
	}
	origStat, origLstat, origTimeout := trustAliasStat, trustAliasLstat, trustAliasScanTimeout
	origRecorded, origDirStat := trustPinRecorded, trustInspectedDirStat
	trustAliasStat, trustAliasLstat, trustAliasScanTimeout = slow(os.Stat), slow(os.Lstat), timeout
	trustPinRecorded, trustInspectedDirStat = slowPin(pinRecordedConfig), slow(os.Stat)
	t.Cleanup(func() {
		trustAliasStat, trustAliasLstat, trustAliasScanTimeout = origStat, origLstat, origTimeout
		trustPinRecorded, trustInspectedDirStat = origRecorded, origDirStat
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

	marker := string(filepath.Separator) + "real" + string(filepath.Separator)
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
		Canonical:   true,
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

	marker := string(filepath.Separator) + "real" + string(filepath.Separator)
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

// blockInspectedDirCheck makes only the post-read check of the inspected directory spelling
// (verifyInspectedDir) block, as if the alias had been redirected to an unreachable network
// location after the config was read. It returns a counter of those checks.
func blockInspectedDirCheck(t *testing.T, timeout time.Duration) *atomic.Int32 {
	t.Helper()
	release := make(chan struct{})
	var calls atomic.Int32
	origDirStat, origTimeout := trustInspectedDirStat, trustAliasScanTimeout
	trustInspectedDirStat = func(string) (os.FileInfo, error) {
		calls.Add(1)
		<-release
		return nil, errors.New("unreachable")
	}
	trustAliasScanTimeout = timeout
	t.Cleanup(func() {
		trustInspectedDirStat, trustAliasScanTimeout = origDirStat, origTimeout
		close(release)
	})
	return &calls
}

// The check that the inspected spelling still names the directory the config was read from
// runs after the read and can block on an unreachable path. On the hook path it must run
// under the lookup deadline: a canonical record then does not apply, and the diagnostic
// names the incomplete check.
func TestLoadConfig_BlockedInspectedDirCheckFailsClosed(t *testing.T) {
	root, repo, record := identityOnlyTrustFixture(t)
	registryPath := filepath.Join(root, "registry", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, record)

	calls := blockInspectedDirCheck(t, 50*time.Millisecond)
	cfg := within(t, 5*time.Second, "LoadConfigWithPaths", func() *Config {
		return loadTrustedProjectConfig(root, repo, registryPath)
	})
	if calls.Load() == 0 {
		t.Fatal("expected the post-read directory check to run")
	}
	if cfg.ProjectConfig != nil || slices.Contains(cfg.SensitiveFiles, ".identity-secret") {
		t.Fatalf("a blocked directory check must leave the config untrusted, got %+v", cfg.ProjectConfig)
	}
	if !slices.ContainsFunc(cfg.Diagnostics, func(d string) bool {
		return strings.Contains(d, "is not trusted") && strings.Contains(d, "did not finish in time")
	}) {
		t.Fatalf("expected a diagnostic naming the incomplete check, got %q", cfg.Diagnostics)
	}
}

// Inspection reports the same blocked check as incomplete, and exact records still apply
// without it: they never need the directory check at all.
func TestInspectProjectConfig_BlockedInspectedDirCheckKeepsExactRecords(t *testing.T) {
	root, repo, record := identityOnlyTrustFixture(t)
	info, err := inspectProjectConfigIsolated(t, repo)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(root, "registry", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, record)

	calls := blockInspectedDirCheck(t, 50*time.Millisecond)
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
	if r.info.Trusted || len(r.info.TrustMatches) != 0 || !r.info.TrustAliasCheckSkipped {
		t.Fatalf("a blocked directory check must fail closed and be reported, got %+v", r.info)
	}

	// With an exact record, the hook answers without the check.
	writeTrustRegistryFile(t, registryPath, record, info.TrustRecord)
	before := calls.Load()
	cfg := within(t, 5*time.Second, "LoadConfigWithPaths", func() *Config {
		return loadTrustedProjectConfig(root, repo, registryPath)
	})
	if cfg.ProjectConfig == nil || !slices.Contains(cfg.SensitiveFiles, ".identity-secret") {
		t.Fatalf("expected the exact record to trust the config, diagnostics=%q", cfg.Diagnostics)
	}
	if n := calls.Load() - before; n != 0 {
		t.Fatalf("an exact record must not wait for the directory check, saw %d checks", n)
	}
}
