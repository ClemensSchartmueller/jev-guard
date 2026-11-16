//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package session

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// tryLockFile takes a non-blocking exclusive flock on f. It reports false
// with a nil error when another open file description holds the lock.
func tryLockFile(f *os.File) (bool, error) {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK):
			return false, nil
		default:
			return false, err
		}
	}
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// touchLockFile sets the lock file's modification time to now.
func touchLockFile(f *os.File) error {
	tv := syscall.NsecToTimeval(time.Now().UnixNano())
	return syscall.Futimes(int(f.Fd()), []syscall.Timeval{tv, tv})
}

// removeLockedFile unlinks the lock file while still holding its lock, then
// releases it. A process that opened the file before the unlink and locks it
// afterwards finds that the path no longer names it and retries (verifyLock).
// Errors are ignored: a lock file that stays is harmless.
func removeLockedFile(path string, f *os.File) {
	_ = os.Remove(path)
	_ = unlockFile(f)
	_ = f.Close()
}
