package session

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Session lock parameters. Variables so tests can shorten them.
var (
	lockTimeout = 2 * time.Second
	lockPoll    = 5 * time.Millisecond
	lockSleep   = time.Sleep

	// lockTouchInterval is how stale a lock file's modification time may get
	// before a holder refreshes it, so its age measures idleness (see sweep.go).
	lockTouchInterval = time.Hour

	// afterLockHook runs after the OS lock is taken and before the path is
	// verified. Tests use it to unlink the lock file at that point.
	afterLockHook func(path string)

	// openLockFile opens a lock file and statLockPath stats its path for the
	// verification. Tests replace them to simulate open and verification
	// failures.
	openLockFile = os.OpenFile
	statLockPath = os.Stat
)

// sessionLockPath is the lock file guarding a session's read-modify-write.
// It does not end in ".json", so session scans ignore it.
func sessionLockPath(sessionID string) string {
	return SessionFilePath(sessionID) + ".lock"
}

// withSessionLock runs fn while holding an exclusive OS advisory lock on the
// session's lock file (flock on Unix, LockFileEx on Windows). Hook processes
// for one session (ingest, PostToolUse taint, end-turn, parallel subagents)
// run concurrently, so every writer that depends on the current state takes
// this lock.
//
// The operating system releases the lock when its holder exits, so a crashed
// process never leaves the session locked and no lock is ever broken by age:
// a live but slow holder keeps it. Acquisition gives up after lockTimeout.
//
// Lock files are removed only by the sweep (sweep.go), and only while it
// holds the lock itself. A process may have opened the old file just before
// the removal and lock it just after, so every acquisition verifies, while
// holding the lock, that the path still names the locked file, and retries on
// a fresh file otherwise. Two processes therefore never hold locks on
// different files at the same path at the same time.
func withSessionLock(sessionID string, fn func() error) error {
	return withLockFile(sessionLockPath(sessionID), fn)
}

// withLockFile is withSessionLock for a caller that knows the session's file
// name but not its ID, as a directory scan does.
func withLockFile(path string, fn func() error) error {
	l, err := acquireLock(path, true, true, nil)
	if err != nil {
		return err
	}
	defer l.release(false)
	return fn()
}

// heldLock is an acquired, verified session lock.
type heldLock struct {
	path string
	f    *os.File
	info os.FileInfo // of the locked file, taken at acquisition
}

// acquireLock takes the lock file at path and verifies that the path still
// refers to it. With wait false it makes a single attempt and returns nil, nil
// instead of polling until lockTimeout whenever that attempt fails in a way
// that a waiting caller would retry: another holder has the lock, opening the
// file failed transiently (a Windows file pending deletion), or the path no
// longer names the locked file. With touch set it refreshes
// a stale modification time, which records the lock file as in use; the sweep
// passes false so that its own visits do not keep a file alive.
//
// step, when not nil, is called before each filesystem call of the
// acquisition (open, lock, stat, touch); when it returns false the
// acquisition gives up and returns nil, nil, closing and unlocking whatever it
// already holds (those releases always run and are not charged). A caller
// passing step (the sweep) also never creates the sessions directory.
func acquireLock(path string, wait, touch bool, step func() bool) (*heldLock, error) {
	if step == nil {
		if err := os.MkdirAll(GetSessionsDir(), 0700); err != nil {
			return nil, fmt.Errorf("failed to create sessions directory: %w", err)
		}
		step = func() bool { return true }
	}
	deadline := time.Now().Add(lockTimeout)
	for {
		if !step() {
			return nil, nil
		}
		f, err := openLockFile(path, os.O_CREATE|os.O_RDWR, 0600)
		if err == nil {
			if !step() {
				_ = f.Close()
				return nil, nil
			}
			locked, lockErr := tryLockFile(f)
			if locked {
				l, verifyErr := verifyLock(path, f, touch, step)
				if l != nil {
					return l, nil
				}
				_ = unlockFile(f)
				_ = f.Close()
				if verifyErr != nil {
					return nil, verifyErr
				}
				// The file was unlinked by the sweep: retry on the new file.
				if !wait {
					return nil, nil
				}
			} else {
				_ = f.Close()
				if lockErr != nil {
					return nil, fmt.Errorf("failed to acquire session lock %s: %w", path, lockErr)
				}
				if !wait {
					return nil, nil
				}
			}
		} else if !retryable(err) {
			return nil, fmt.Errorf("failed to open session lock %s: %w", path, err)
		} else if !wait {
			return nil, nil
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("%w after %s waiting for session lock %s", ErrLockTimeout, lockTimeout, path)
		}
		lockSleep(lockPoll)
	}
}

// verifyLock checks, while f is locked, that path still names f. It returns
// nil, nil when the path is missing or names another file, which happens when
// the sweep removed the lock file between this process's open and lock.
// step is charged before each filesystem call, as in acquireLock; when it
// refuses, verifyLock returns nil, nil like a failed verification.
func verifyLock(path string, f *os.File, touch bool, step func() bool) (*heldLock, error) {
	if afterLockHook != nil {
		afterLockHook(path)
	}
	if !step() {
		return nil, nil
	}
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to check session lock %s: %w", path, err)
	}
	if !step() {
		return nil, nil
	}
	pathInfo, err := statLockPath(path)
	if err != nil {
		// Windows reports a file that is pending deletion as access denied.
		if os.IsNotExist(err) || retryable(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to check session lock %s: %w", path, err)
	}
	if !os.SameFile(info, pathInfo) {
		return nil, nil
	}
	if age := time.Since(info.ModTime()); touch && (age > lockTouchInterval || age < -lockTouchInterval) && step() {
		_ = touchLockFile(f)
	}
	return &heldLock{path: path, f: f, info: info}, nil
}

// release unlocks and closes the lock. With remove set it also deletes the
// lock file, safely for concurrent acquirers (see removeLockedFile).
func (l *heldLock) release(remove bool) {
	if remove {
		removeLockedFile(l.path, l.f)
		return
	}
	_ = unlockFile(l.f)
	_ = l.f.Close()
}

// ErrLockTimeout is returned when another process held the session lock for
// longer than the acquisition timeout.
var ErrLockTimeout = errors.New("timed out")
