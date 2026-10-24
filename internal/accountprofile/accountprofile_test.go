package accountprofile

import (
	"fmt"
	"strings"
	"testing"
)

func TestForbidForTestingMakesHomeDirPanic(t *testing.T) {
	// Before the guard, HomeDir only looks up the account; it opens no files.
	_ = HomeDir()

	ForbidForTesting()
	defer func() {
		message := fmt.Sprint(recover())
		if !strings.Contains(message, "accountprofile.TestForbidForTestingMakesHomeDirPanic") {
			t.Fatalf("expected the panic to name the caller, got %q", message)
		}
	}()
	HomeDir()
}
