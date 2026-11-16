//go:build windows

package session

import (
	"errors"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
)

// tryLockFile takes a non-blocking exclusive LockFileEx lock on the first
// byte of f. It reports false with a nil error when another handle holds it.
func tryLockFile(f *os.File) (bool, error) {
	var ol syscall.Overlapped
	r, _, err := procLockFileEx.Call(f.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r != 0 {
		return true, nil
	}
	if errors.Is(err, errorLockViolation) || errors.Is(err, syscall.ERROR_IO_PENDING) {
		return false, nil
	}
	return false, err
}

func unlockFile(f *os.File) error {
	var ol syscall.Overlapped
	r, _, err := procUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r == 0 {
		return err
	}
	return nil
}

// touchLockFile sets the lock file's modification time to now, through the
// open handle (opening the path again would hit a sharing violation).
func touchLockFile(f *os.File) error {
	ft := syscall.NsecToFiletime(time.Now().UnixNano())
	return syscall.SetFileTime(syscall.Handle(f.Fd()), nil, nil, &ft)
}

// removeLockedFile releases the lock and then deletes the lock file. Windows
// cannot delete a file while any handle is open on it, because Go opens files
// without FILE_SHARE_DELETE, so the deletion has to come after the close. A
// process that opens the file in between holds a handle, and the deletion
// then fails, which is ignored: the file stays and that process keeps a valid
// lock. verifyLock also covers a file pending deletion. Errors are ignored.
func removeLockedFile(path string, f *os.File) {
	_ = unlockFile(f)
	_ = f.Close()
	_ = os.Remove(path)
}
