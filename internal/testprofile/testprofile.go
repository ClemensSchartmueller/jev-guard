// Package testprofile keeps package tests away from the real user profile.
//
// Production config paths come from the OS account (user.Current), so changing HOME
// alone does not isolate them. Run therefore forbids the account lookup in-process
// (accountprofile.ForbidForTesting): any test that reaches config.UserConfigPath or
// config.TrustRegistryPath, directly or through LoadConfig, LoadConfigForCall,
// InspectProjectConfig or EnsureUserConfig, panics before touching the real profile.
// Tests must pass explicit temp paths instead. Run also points HOME, USERPROFILE and
// JEV_GUARD_HOME at a temp profile for the whole test binary, and, as extra
// detection, fails the run if the real user config or trust registry changed.
//
// The in-process guard does not reach subprocesses. A test that runs a production
// jev-guard binary would resolve the real account profile, because main calls
// EnsureUserConfig. No test does this today. Such a test must run in a sandbox or a
// disposable OS account, never under the real account.
//
// Set JEV_GUARD_TEST_USER_CONFIG to a fixture file to seed the temp profile's user
// config, so the suite can be run once with an enforcing and once with an audit user
// config. A relative path is resolved against the module root, so the same value
// works for every package:
//
//	JEV_GUARD_TEST_USER_CONFIG=internal/testprofile/testdata/enforcing.json go test -count=1 ./...
package testprofile

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jev-guard/internal/accountprofile"
)

// Run forbids account-backed profile lookups, isolates the process environment in a
// temp profile, calls setup with the temp home directory so the package can point its
// seams there, and runs the tests. It returns the exit code for os.Exit: non-zero if
// the tests failed or any watched real profile file changed.
func Run(m *testing.M, setup func(home string)) int {
	watched := realProfileFiles()
	before := snapshot(watched)
	accountprofile.ForbidForTesting()

	home, err := os.MkdirTemp("", "jevguard-test-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "testprofile:", err)
		return 1
	}
	defer os.RemoveAll(home)
	for key, value := range map[string]string{
		"HOME":           home,
		"USERPROFILE":    home,
		"JEV_GUARD_HOME": filepath.Join(home, ".jevguard"),
	} {
		if err := os.Setenv(key, value); err != nil {
			fmt.Fprintln(os.Stderr, "testprofile:", err)
			return 1
		}
	}
	if fixture := os.Getenv("JEV_GUARD_TEST_USER_CONFIG"); fixture != "" {
		if err := seedUserConfig(home, fixture); err != nil {
			fmt.Fprintln(os.Stderr, "testprofile:", err)
			return 1
		}
	}
	if setup != nil {
		setup(home)
	}

	code := m.Run()

	if changed := diff(before, snapshot(watched)); len(changed) > 0 {
		fmt.Fprintf(os.Stderr, "testprofile: FAIL: tests changed the real user profile: %s\n", strings.Join(changed, "; "))
		return 1
	}
	return code
}

// seedUserConfig copies a user config fixture into the temp profile. A relative
// fixture path is resolved against the module root, because each test binary runs
// in its own package directory.
func seedUserConfig(home, fixture string) error {
	if !filepath.IsAbs(fixture) {
		root, err := moduleRoot()
		if err != nil {
			return fmt.Errorf("resolve user config fixture %s: %w", fixture, err)
		}
		fixture = filepath.Join(root, fixture)
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		return fmt.Errorf("read user config fixture: %w", err)
	}
	dir := filepath.Join(home, ".jevguard")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ".jevguard.json"), data, 0o600)
}

// moduleRoot returns the nearest ancestor of the working directory that holds go.mod.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found above the working directory")
		}
		dir = parent
	}
}

// realProfileFiles returns the user-owned files the production code resolves through
// user.Current: the user config and the project trust registry.
func realProfileFiles() []string {
	current, err := user.Current()
	if err != nil || strings.TrimSpace(current.HomeDir) == "" {
		return nil
	}
	dir := filepath.Join(current.HomeDir, ".jevguard")
	return []string{
		filepath.Join(dir, ".jevguard.json"),
		filepath.Join(dir, "trusted-project-configs.json"),
	}
}

// fileState is metadata only. The guard never reads real profile contents.
type fileState struct {
	exists  bool
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func snapshot(paths []string) map[string]fileState {
	states := make(map[string]fileState, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			states[path] = fileState{}
			continue
		}
		states[path] = fileState{exists: true, size: info.Size(), mode: info.Mode(), modTime: info.ModTime()}
	}
	return states
}

func diff(before, after map[string]fileState) []string {
	var changed []string
	for path, was := range before {
		if now := after[path]; now != was {
			changed = append(changed, fmt.Sprintf("%s (before %+v, after %+v)", path, was, now))
		}
	}
	return changed
}
