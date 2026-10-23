package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"jev-guard/pkg/config"
)

// TestMain points config loading, the trust registry, and the home directory at
// an empty temp profile so CLI tests never read the real ~/.jevguard user config,
// trust registry, or agent hook settings.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "jevguard-cli-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	loadConfig = func(candidateDirs ...string) *config.Config {
		return config.LoadConfigWithPaths(candidateDirs,
			filepath.Join(home, ".jevguard", ".jevguard.json"),
			filepath.Join(home, ".jevguard", "trusted-project-configs.json"))
	}
	trustRegistryPath = func() string {
		return filepath.Join(home, ".jevguard", "trusted-project-configs.json")
	}
	userHomeDir = func() (string, error) {
		return home, nil
	}
	// The real inspectProjectConfig reads the OS user's trust registry through
	// config.InspectProjectConfig, which cannot be redirected without changes in
	// pkg/config. Tests that need it install their own stub. This can switch to
	// config.InspectProjectConfigWithRegistry once PR #42 lands.
	inspectProjectConfig = func(string) (*config.ProjectConfigInfo, error) {
		return nil, errors.New("inspectProjectConfig not stubbed for this test")
	}
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}
