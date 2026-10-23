package fastpath

import (
	"errors"
	"os"
	"testing"
)

// errHomeNotStubbed is returned by the default userHomeDir seam in tests.
var errHomeNotStubbed = errors.New("userHomeDir not stubbed for this test")

// TestMain clears XDG_CONFIG_HOME so NewFilter never derives sensitive
// patterns from the host environment. Tests that need it use t.Setenv.
//
// It also replaces the userHomeDir seam with one that fails, so the Claude
// tool-result matcher never resolves the real user home. Tests that exercise
// it install a temp profile through setupToolResultEnv.
func TestMain(m *testing.M) {
	os.Unsetenv("XDG_CONFIG_HOME")
	userHomeDir = func() (string, error) { return "", errHomeNotStubbed }
	os.Exit(m.Run())
}
