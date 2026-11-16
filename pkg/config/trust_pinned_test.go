package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// replacedDirectoryFixture creates root/repo with an approved project config and root/other
// with byte-identical config. replace renames root/repo away and puts a symlink to
// root/other in its place, which is the attack a canonical record must not follow.
func replacedDirectoryFixture(t *testing.T, marker string) (root, repo, other string, info *ProjectConfigInfo, replace func()) {
	t.Helper()
	clearConfigEnvironment(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	contents := `{"sensitive_files":["` + marker + `"]}`
	repo = filepath.Join(root, "repo")
	other = filepath.Join(root, "other")
	writeConfig(t, filepath.Join(repo, ".jevguard.json"), contents)
	writeConfig(t, filepath.Join(other, ".jevguard.json"), contents)
	if err := os.Symlink(other, filepath.Join(root, "probe")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "probe")); err != nil {
		t.Fatal(err)
	}
	info, err = inspectProjectConfigIsolated(t, repo)
	if err != nil {
		t.Fatal(err)
	}
	replace = func() {
		if err := os.Rename(repo, filepath.Join(root, "moved")); err != nil {
			t.Fatalf("rename approved directory: %v", err)
		}
		if err := os.Symlink(other, repo); err != nil {
			t.Fatalf("replace approved directory with a symlink: %v", err)
		}
	}
	return root, repo, other, info, replace
}

func TestCanonicalRecordDoesNotFollowDirectoryReplacedBySymlink(t *testing.T) {
	root, repo, other, info, replace := replacedDirectoryFixture(t, ".replaced-secret")
	record := proposeCanonicalRecord(t, info)
	if record.ProjectRoot != repo {
		t.Fatalf("expected the proposal to name %s exactly, got %+v", repo, record)
	}
	registryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, record)
	assertProjectTrust(t, repo, registryPath, ".replaced-secret", true)

	// The recorded directory itself becomes a symlink to a directory with byte-identical
	// config. The record names the inspected spelling exactly, but it is canonical, so it
	// must be reached without a link and no longer applies anywhere.
	replace()
	// Inspect the config file: the directory path itself is now a symlink, which inspection
	// rejects before it reaches the trust lookup.
	assertProjectTrust(t, filepath.Join(repo, ".jevguard.json"), registryPath, ".replaced-secret", false)
	assertProjectTrust(t, other, registryPath, ".replaced-secret", false)
}

// Records without canonical keep the exact-spelling behavior of earlier versions, without
// filesystem checks. This pins the documented compatibility exception: such a record follows
// a directory replaced by a symlink, which is why config trust now proposes canonical records.
func TestLegacyExactRecordKeepsDocumentedExactSpellingBehavior(t *testing.T) {
	root, repo, other, info, replace := replacedDirectoryFixture(t, ".legacy-replaced-secret")
	registryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, info.TrustRecord)
	replace()
	assertProjectTrust(t, filepath.Join(repo, ".jevguard.json"), registryPath, ".legacy-replaced-secret", true)
	assertProjectTrust(t, other, registryPath, ".legacy-replaced-secret", false)
}

// A pinned lookup must not be fooled by a directory swapped for a symlink between its steps,
// which a walk followed by separate stat calls would be. The swap runs from the test hook
// before each open in turn, so the test is deterministic and needs no sleeps.
func TestCanonicalRecordRejectsDirectorySwappedBetweenPinnedSteps(t *testing.T) {
	root, repo, other, info, _ := replacedDirectoryFixture(t, ".race-secret")
	record := proposeCanonicalRecord(t, info)
	registryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, record)
	// The attacker's directory is not trusted while the approved directory is in place.
	assertProjectTrust(t, other, registryPath, ".race-secret", false)

	var steps []string
	setTrustPinStep(t, func(path string) { steps = append(steps, path) })
	if _, err := inspectProjectConfigWithRegistry(other, registryPath); err != nil {
		t.Fatal(err)
	}
	if len(steps) < 3 {
		t.Fatalf("expected the pinned lookups to report their steps, got %q", steps)
	}

	moved := filepath.Join(root, "moved")
	for swapAt := range steps {
		var calls, swapped int
		setTrustPinStep(t, func(path string) {
			calls++
			if calls-1 == swapAt {
				if err := os.Rename(repo, moved); err != nil {
					t.Logf("step %d (%s): the held directory could not be renamed: %v", swapAt, path, err)
					return
				}
				if err := os.Symlink(other, repo); err != nil {
					t.Errorf("step %d: symlink: %v", swapAt, err)
					return
				}
				swapped++
			}
		})
		got, err := inspectProjectConfigWithRegistry(other, registryPath)
		if err != nil {
			t.Fatal(err)
		}
		if got.Trusted || len(got.TrustMatches) != 0 {
			t.Errorf("swap before step %d (%s) moved trust to %s: %+v", swapAt, steps[swapAt], other, got.TrustMatches)
		}
		if swapped == 1 {
			// After the swap the recorded path does name the attacker's file, so a lookup
			// that resolved the path again by name would have matched.
			linked, err := os.Stat(record.ConfigPath)
			if err != nil || !os.SameFile(linked, got.file) {
				t.Fatalf("step %d: expected the recorded path to resolve to %s after the swap", swapAt, other)
			}
		}
		// Restore the approved directory for the next step.
		setTrustPinStep(t, nil)
		if swapped == 1 {
			if err := os.Remove(repo); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(moved, repo); err != nil {
				t.Fatal(err)
			}
		}
		assertProjectTrust(t, repo, registryPath, ".race-secret", true)
	}
}

func setTrustPinStep(t *testing.T, step func(string)) {
	t.Helper()
	orig := trustPinStep
	trustPinStep = step
	t.Cleanup(func() { trustPinStep = orig })
}

// countTrustProposals counts trustEvalSymlinks calls, which only ProposeTrustRecord makes.
func countTrustProposals(t *testing.T) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	orig := trustEvalSymlinks
	trustEvalSymlinks = func(path string) (string, error) {
		calls.Add(1)
		return orig(path)
	}
	t.Cleanup(func() { trustEvalSymlinks = orig })
	return &calls
}

// countPinnedLookups counts the pinned lookups that canonical records need.
func countPinnedLookups(t *testing.T) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	origRecorded, origInspected := trustPinRecorded, trustPinInspected
	counted := func(real pinFunc) pinFunc {
		return func(projectRoot, name string, step func(string)) (pinnedConfig, error) {
			calls.Add(1)
			return real(projectRoot, name, step)
		}
	}
	trustPinRecorded, trustPinInspected = counted(origRecorded), counted(origInspected)
	t.Cleanup(func() { trustPinRecorded, trustPinInspected = origRecorded, origInspected })
	return &calls
}

func TestHookPathNeverProposesATrustRecord(t *testing.T) {
	root, linkRepo, record := identityOnlyTrustFixture(t)
	registryPath := filepath.Join(root, "registry", "trusted-project-configs.json")
	proposals := countTrustProposals(t)

	writeTrustRegistryFile(t, registryPath, record)
	if cfg := loadTrustedProjectConfig(root, linkRepo, registryPath); cfg.ProjectConfig == nil {
		t.Fatalf("expected the canonical record to trust the config, diagnostics=%q", cfg.Diagnostics)
	}
	info, err := inspectProjectConfigWithRegistry(linkRepo, registryPath)
	if err != nil || !info.Trusted {
		t.Fatalf("expected inspection to report trust, got %+v, %v", info, err)
	}
	if n := proposals.Load(); n != 0 {
		t.Fatalf("the hook path and inspection proposed a trust record %d times", n)
	}

	// The proposal is computed only when asked for.
	if got := proposeCanonicalRecord(t, info); got != record {
		t.Fatalf("expected the proposal %+v, got %+v", record, got)
	}
	if n := proposals.Load(); n != 1 {
		t.Fatalf("expected one proposal, got %d", n)
	}
}

func TestHookPathHonorsLegacyExactRecordWithoutFilesystemLookups(t *testing.T) {
	root, linkRepo, canonical := identityOnlyTrustFixture(t)
	info, err := inspectProjectConfigIsolated(t, linkRepo)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(root, "registry", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, canonical, info.TrustRecord)
	pins := countPinnedLookups(t)
	proposals := countTrustProposals(t)
	if cfg := loadTrustedProjectConfig(root, linkRepo, registryPath); cfg.ProjectConfig == nil {
		t.Fatalf("expected the exact record to trust the config, diagnostics=%q", cfg.Diagnostics)
	}
	if n, p := pins.Load(), proposals.Load(); n != 0 || p != 0 {
		t.Fatalf("expected no filesystem lookups for an exact record, got %d pinned lookups and %d proposals", n, p)
	}
}

func TestProposeTrustRecordFallsBackToExactSpellingWhenPinningFails(t *testing.T) {
	_, linkRepo, _ := identityOnlyTrustFixture(t)
	info, err := inspectProjectConfigIsolated(t, linkRepo)
	if err != nil {
		t.Fatal(err)
	}
	origRecorded := trustPinRecorded
	trustPinRecorded = func(string, string, func(string)) (pinnedConfig, error) {
		return pinnedConfig{}, errors.New("simulated link")
	}
	t.Cleanup(func() { trustPinRecorded = origRecorded })

	record, note := ProposeTrustRecord(info)
	if record != info.TrustRecord || record.Canonical {
		t.Fatalf("expected the exact-spelling record without canonical, got %+v", record)
	}
	if !strings.Contains(note, "could not be verified") {
		t.Fatalf("expected a note naming the failed verification, got %q", note)
	}
}

func TestProposeTrustRecordIsBounded(t *testing.T) {
	_, linkRepo, _ := identityOnlyTrustFixture(t)
	info, err := inspectProjectConfigIsolated(t, linkRepo)
	if err != nil {
		t.Fatal(err)
	}
	blockTrustLookups(t, 50*time.Millisecond, func(string) bool { return true })
	type result struct {
		record ProjectConfigTrust
		note   string
	}
	r := within(t, 5*time.Second, "ProposeTrustRecord", func() result {
		record, note := ProposeTrustRecord(info)
		return result{record, note}
	})
	if r.record != info.TrustRecord || !strings.Contains(r.note, "did not finish in time") {
		t.Fatalf("expected a bounded fallback to the exact record, got %+v (%s)", r.record, r.note)
	}
}

func TestCanonicalRecordWithLinkInPathNeverApplies(t *testing.T) {
	root, linkRepo, record := identityOnlyTrustFixture(t)
	viaLink := ProjectConfigTrust{
		ProjectRoot: linkRepo,
		ConfigPath:  filepath.Join(linkRepo, ".jevguard.json"),
		SHA256:      record.SHA256,
		Canonical:   true,
	}
	registryPath := filepath.Join(root, "registry", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, viaLink)
	// Even the exact spelling is not trusted: a canonical record must be reached without a link.
	assertProjectTrust(t, linkRepo, registryPath, ".identity-secret", false)
	info, err := inspectProjectConfigWithRegistry(filepath.Join(root, "real", "repo"), registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Trusted || len(info.TrustAliases) != 1 || info.TrustAliases[0] != viaLink {
		t.Fatalf("expected the linked canonical record as an alias only, got %+v", info)
	}
}
