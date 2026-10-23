package config

import (
	"os"
	"testing"

	"jev-guard/internal/testprofile"
)

// TestMain runs the package in a temp profile. Tests must still pass explicit user
// config and trust registry paths: UserConfigPath and TrustRegistryPath resolve
// through user.Current, which the temp HOME does not redirect. The run fails if
// the real user config or trust registry changed.
func TestMain(m *testing.M) {
	os.Exit(testprofile.Run(m, nil))
}
