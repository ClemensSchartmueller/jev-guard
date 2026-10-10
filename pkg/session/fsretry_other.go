//go:build !windows

package session

// isTransientFSError reports whether err is worth retrying. On POSIX systems
// rename(2) atomically replaces the target even while readers hold it open,
// so no filesystem error is considered transient.
func isTransientFSError(err error) bool {
	return false
}
