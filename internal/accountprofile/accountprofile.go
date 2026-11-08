// Package accountprofile resolves the OS account's home directory, which holds the
// user-owned jev-guard config and trust registry.
//
// The home comes from user.Current, never from HOME or other environment variables
// that a repository or hook process can override. Tests can forbid the lookup with
// ForbidForTesting so that any code path reaching the real account profile fails
// fast instead of reading or writing it.
package accountprofile

import (
	"fmt"
	"os/user"
	"runtime"
	"strings"
	"sync/atomic"
)

var forbidden atomic.Bool

// ForbidForTesting makes every later HomeDir call panic. It is test-only: only
// in-process code can call it, and nothing in the environment or on disk turns it
// on. internal/testprofile calls it for every guarded test binary.
func ForbidForTesting() {
	forbidden.Store(true)
}

// HomeDir returns the OS account's home directory, or "" if it is unavailable.
// It panics, naming the caller, after ForbidForTesting.
func HomeDir() string {
	if forbidden.Load() {
		panic(fmt.Sprintf("accountprofile: %s resolved the real account profile in a test; use an explicit temp user config or trust registry path", caller()))
	}
	current, err := user.Current()
	if err != nil || strings.TrimSpace(current.HomeDir) == "" {
		return ""
	}
	return current.HomeDir
}

// caller names HomeDir's caller and the function that called it, for example
// "jev-guard/pkg/config.UserConfigPath, called from jev-guard/pkg/config.LoadConfig".
func caller() string {
	pcs := make([]uintptr, 2)
	n := runtime.Callers(3, pcs)
	if n == 0 {
		return "unknown caller"
	}
	frames := runtime.CallersFrames(pcs[:n])
	var names []string
	for {
		frame, more := frames.Next()
		names = append(names, frame.Function)
		if !more {
			break
		}
	}
	return strings.Join(names, ", called from ")
}
