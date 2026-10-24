//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || windows)

package session

import (
	"errors"
	"os"
)

// tryLockFile fails on platforms without a supported advisory lock, so
// session writers report an error (and taint/abort fall back to their marker
// files) instead of writing without mutual exclusion.
func tryLockFile(*os.File) (bool, error) {
	return false, errors.New("session locking is not supported on this platform")
}

func unlockFile(*os.File) error { return nil }
