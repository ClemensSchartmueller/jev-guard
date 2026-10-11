package fastpath

import (
	"os"
	"testing"
)

// TestMain clears XDG_CONFIG_HOME so NewFilter never derives sensitive
// patterns from the host environment. Tests that need it use t.Setenv.
func TestMain(m *testing.M) {
	os.Unsetenv("XDG_CONFIG_HOME")
	os.Exit(m.Run())
}
