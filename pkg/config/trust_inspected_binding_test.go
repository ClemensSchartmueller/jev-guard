package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// switchingAliasFixture creates root/a/repo and root/b/repo and a directory symlink
// root/alias pointing at root/b. point repoints the alias. The inspected spelling is
// root/alias/repo, which legitimately goes through a link.
func switchingAliasFixture(t *testing.T) (root, repoA, repoB, inspected string, point func(target string)) {
	t.Helper()
	clearConfigEnvironment(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repoA = filepath.Join(root, "a", "repo")
	repoB = filepath.Join(root, "b", "repo")
	for _, dir := range []string{repoA, repoB} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "alias")
	point = func(target string) {
		t.Helper()
		if err := os.Remove(alias); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove alias: %v", err)
		}
		if err := os.Symlink(filepath.Dir(target), alias); err != nil {
			t.Fatalf("point alias at %s: %v", target, err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "b"), alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	return root, repoA, repoB, filepath.Join(alias, "repo"), point
}

// inspectedOpener has the signature of openInspectedConfig.
type inspectedOpener func(projectRoot, name string, step func(string)) (*os.File, os.FileInfo, error)

// openInspectedByPathAfterDir reproduces the macOS lookup this branch replaced: it opens and
// stats the directory, then opens the config by its full path in a second, independent
// lookup. The test below must reject it.
func openInspectedByPathAfterDir(projectRoot, name string, step func(string)) (*os.File, os.FileInfo, error) {
	step(projectRoot)
	dir, err := os.Open(projectRoot)
	if err != nil {
		return nil, nil, err
	}
	dirInfo, err := dir.Stat()
	_ = dir.Close()
	if err != nil {
		return nil, nil, err
	}
	configPath := filepath.Join(projectRoot, name)
	step(configPath)
	file, err := os.Open(configPath)
	return file, dirInfo, err
}

// inspectedBindingViolation switches the inspected alias to repoA just before the directory
// is opened and to repoB just before the config file is opened, and reports whether open
// returned a file that is not in the directory whose identity it returned.
func inspectedBindingViolation(t *testing.T, open inspectedOpener) error {
	t.Helper()
	_, repoA, repoB, inspected, point := switchingAliasFixture(t)
	writeConfig(t, filepath.Join(repoA, ".jevguard.json"), `{"sensitive_files":[".a"]}`)
	writeConfig(t, filepath.Join(repoB, ".jevguard.json"), `{"sensitive_files":[".b"]}`)
	var steps []string
	file, dir, err := open(inspected, ".jevguard.json", func(path string) {
		steps = append(steps, path)
		switch path {
		case inspected:
			point(repoA)
		case filepath.Join(inspected, ".jevguard.json"):
			point(repoB)
		}
	})
	if err != nil {
		return fmt.Errorf("open failed: %w", err)
	}
	defer file.Close()
	if len(steps) != 2 {
		t.Fatalf("expected a directory step and a file step, got %q", steps)
	}
	fileInfo, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	dirA, _ := os.Stat(repoA)
	fileA, _ := os.Stat(filepath.Join(repoA, ".jevguard.json"))
	if !os.SameFile(dir, dirA) {
		t.Fatalf("the directory was opened before the alias moved back to b, so it must be a")
	}
	if !os.SameFile(fileInfo, fileA) {
		return fmt.Errorf("directory identity is %s but the file read is not %s/.jevguard.json", repoA, repoA)
	}
	return nil
}

// The file whose bytes are hashed must be the file under the config name in the directory
// whose identity is compared with canonical records, even if a link in the inspected
// spelling is switched between opening the directory and opening the file. This runs the
// shared openat implementation on Linux and FreeBSD, the same source file macOS compiles
// (trust_pin_at.go); only the darwin openat binding (trust_pin_darwin.go) and the Windows
// implementation are compile-checked here.
func TestInspectedConfigIsBoundToTheOpenedDirectory(t *testing.T) {
	if !trustPinningSupported {
		t.Skip("no bound inspected open on this platform; canonical records never apply")
	}
	if err := inspectedBindingViolation(t, openInspectedConfig); err != nil {
		t.Fatal(err)
	}
}

// The check above must catch a lookup that opens the directory and the file independently,
// which is what pinInspectedConfig did on macOS before this test was added.
func TestInspectedBindingCheckRejectsIndependentLookups(t *testing.T) {
	err := inspectedBindingViolation(t, openInspectedByPathAfterDir)
	if err == nil || !strings.Contains(err.Error(), "the file read is not") {
		t.Fatalf("expected the binding check to reject an independent file lookup, got %v", err)
	}
}

// The attack from the review of #77: a is approved with a canonical record; b, which is not
// approved, holds a hard link to a's config. The hook inspects alias/repo while the attacker
// points alias at a just before the directory is opened and back at b just before the file
// is opened. Trust must not be granted. Every other schedule of the alias over the
// inspection steps is checked too: trust is granted only when the config was read from a's
// directory handle and the inspected spelling still named a afterwards, which is the same
// as inspecting alias/repo while it legitimately points at a.
func TestCanonicalRecordNotGrantedWhenInspectedAliasSwitchesBetweenSteps(t *testing.T) {
	root, repoA, repoB, inspected, point := switchingAliasFixture(t)
	writeConfig(t, filepath.Join(repoA, ".jevguard.json"), `{"sensitive_files":[".switch-secret"]}`)
	if err := os.Link(filepath.Join(repoA, ".jevguard.json"), filepath.Join(repoB, ".jevguard.json")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	approved, err := inspectProjectConfigIsolated(t, repoA)
	if err != nil {
		t.Fatal(err)
	}
	record := proposeCanonicalRecord(t, approved)
	registryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	writeTrustRegistryFile(t, registryPath, record)
	assertProjectTrust(t, inspected, registryPath, ".switch-secret", false)
	point(repoA)
	if !trustPinningSupported {
		assertProjectTrust(t, inspected, registryPath, ".switch-secret", false)
		return
	}
	assertProjectTrust(t, inspected, registryPath, ".switch-secret", true)

	// Discover the inspection steps on the inspected spelling: open the directory, open the
	// file, and check the spelling again after reading.
	point(repoB)
	var aliasSteps []string
	setTrustPinStep(t, func(path string) {
		if path == inspected || strings.HasPrefix(path, inspected+string(filepath.Separator)) {
			aliasSteps = append(aliasSteps, path)
		}
	})
	if _, err := inspectProjectConfigWithRegistry(inspected, registryPath); err != nil {
		t.Fatal(err)
	}
	if len(aliasSteps) != 3 {
		t.Fatalf("expected three inspection steps on %s, got %q", inspected, aliasSteps)
	}

	name := map[string]string{repoA: "a", repoB: "b"}
	for mask := 0; mask < 1<<len(aliasSteps); mask++ {
		schedule := make([]string, len(aliasSteps))
		for i := range schedule {
			schedule[i] = repoB
			if mask&(1<<i) != 0 {
				schedule[i] = repoA
			}
		}
		label := ""
		for _, target := range schedule {
			label += name[target]
		}
		t.Run(label, func(t *testing.T) {
			point(repoB)
			seen := 0
			setTrustPinStep(t, func(path string) {
				if path == inspected || strings.HasPrefix(path, inspected+string(filepath.Separator)) {
					point(schedule[seen])
					seen++
				}
			})
			got, err := inspectProjectConfigWithRegistry(inspected, registryPath)
			setTrustPinStep(t, nil)
			if err != nil {
				t.Fatal(err)
			}
			if seen != len(schedule) {
				t.Fatalf("expected %d inspection steps, saw %d", len(schedule), seen)
			}
			// The directory is opened at step 0 and the spelling is checked again at
			// step 2; the file is opened relative to the directory handle at step 1, so
			// where the alias points then does not matter.
			want := schedule[0] == repoA && schedule[2] == repoA
			if got.Trusted != want {
				t.Fatalf("schedule %s: trusted=%t, want %t (matches %+v)", label, got.Trusted, want, got.TrustMatches)
			}
		})
	}
}
