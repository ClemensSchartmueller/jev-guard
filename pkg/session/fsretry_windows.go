//go:build windows

package session

import (
	"errors"
	"syscall"
)

// Windows error codes that can appear transiently while another process or
// goroutine holds the session file open (e.g. a concurrent rename or read).
const (
	errorAccessDenied     syscall.Errno = 5  // ERROR_ACCESS_DENIED
	errorSharingViolation syscall.Errno = 32 // ERROR_SHARING_VIOLATION
	errorLockViolation    syscall.Errno = 33 // ERROR_LOCK_VIOLATION
)

// isTransientFSError reports whether err is a Windows file-sharing error that
// is worth retrying. All other errors are treated as permanent.
func isTransientFSError(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case errorAccessDenied, errorSharingViolation, errorLockViolation:
		return true
	}
	return false
}
