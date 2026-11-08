package boundary

import (
	"os"
	"testing"

	"jev-guard/internal/testprofile"
)

// TestMain runs the package in a temp profile, like every other package, so a
// resolver test can never touch the real ~/.jevguard.
func TestMain(m *testing.M) {
	os.Exit(testprofile.Run(m, nil))
}
