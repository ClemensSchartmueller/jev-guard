package session

import (
	"os"
	"testing"

	"jev-guard/internal/testprofile"
)

// TestMain points JEV_GUARD_HOME at a temp profile so a test that forgets
// setupTestJevguardDir still cannot write sessions under the real ~/.jevguard.
func TestMain(m *testing.M) {
	os.Exit(testprofile.Run(m, nil))
}
