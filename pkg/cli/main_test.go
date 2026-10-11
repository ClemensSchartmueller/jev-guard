package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"jev-guard/pkg/config"
)

// TestMain points config loading at an empty temp profile so CLI tests never
// read the real ~/.jevguard user config or trust registry.
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
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}
