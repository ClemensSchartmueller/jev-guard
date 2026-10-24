package cli

import (
	"os"
	"path/filepath"
	"testing"

	"jev-guard/internal/testprofile"
	"jev-guard/pkg/config"
)

// TestMain points config loading, the trust registry, project config inspection,
// and the home directory at an empty temp profile so CLI tests never read the real
// ~/.jevguard user config, trust registry, sessions, or agent hook settings.
// testprofile.Run makes config's account-backed loaders panic, and fails the run
// if the real user config or trust registry changed.
func TestMain(m *testing.M) {
	os.Exit(testprofile.Run(m, func(home string) {
		userConfig := filepath.Join(home, ".jevguard", ".jevguard.json")
		registry := filepath.Join(home, ".jevguard", "trusted-project-configs.json")
		loadConfig = func(candidateDirs ...string) *config.Config {
			return config.LoadConfigWithPaths(candidateDirs, userConfig, registry)
		}
		trustRegistryPath = func() string { return registry }
		inspectProjectConfig = func(path string) (*config.ProjectConfigInfo, error) {
			return config.InspectProjectConfigWithRegistry(path, registry)
		}
		userHomeDir = func() (string, error) { return home, nil }
	}))
}
